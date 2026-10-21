//! T8.2 (S8): a remote session end to end, offline. The real `ai-env-claude`
//! in remote mode (`AI_ENV_BRIDGE_MODE=remote`, the fake API, the agent
//! address knob) talks through the tests' fake endpoint, routed per port, to
//! an in-process shim with `fs_root` (`tests/common/remote.rs`'s `RemoteRig`):
//! the pre-spawn pipeline and its failures, the remote link, the close within
//! 1.5 s, the per-result code-out, the census and the registry. Declared in
//! S8 phase 0; S8 wave 1 (W2) writes the tests, the lead's integration adds
//! T8.2 itself (`t8_2_a_fake_extension_session_runs_on_the_vm`).
//!
//! First, T8.2 and wave 1 as one (`a_remote_session_runs_on_the_in_process_shim`).
//! Then phase 0's own checks: the rig without the remote session (the
//! routed endpoint, the shim, the green world, the VM side's fake claude
//! through `vm exec`), the new knobs of the fake claude, and `on_links!`'s
//! two halves. Wave 1's link and pipeline tests follow, then wave 2's
//! (W10): the design's remote_pump list (plans/s8-design-tests.md §2.5)
//! and the offline column of T8.2 to T8.6 (§2.1).
mod common;

use common::remote::{Reply, Req};
use common::{env_log_field, is_echo_of, is_init, is_response_to, is_result_for, Harness};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Upper bounds only (timing is `race.rs`'s): a loaded Mac can start a child seconds late.
const T: Duration = Duration::from_secs(30);
const EXIT: Duration = Duration::from_secs(30);

/// `git <args>` in `dir` by the real git (no user or system config): its
/// stdout, trimmed; a failure panics with its stderr.
fn git_in(dir: &Path, args: &[&str]) -> String {
    let o = Command::new(common::git_real())
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("run the real git");
    assert!(o.status.success(), "git {args:?} in {}: {}", dir.display(), String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// What a session must leave alone in the Mac's repository: HEAD, the
/// branches and tags, the index against HEAD and the worktree against the
/// index (untracked files included), read without optional locks.
fn mac_repo_view(work: &Path) -> Vec<String> {
    [
        &["rev-parse", "HEAD"][..],
        &["for-each-ref", "refs/heads", "refs/tags"],
        &["--no-optional-locks", "status", "--porcelain=v2", "--untracked-files=all"],
        &["--no-optional-locks", "diff", "--cached"],
        &["--no-optional-locks", "diff"],
    ]
    .iter()
    .map(|args| git_in(work, args))
    .collect()
}

/// Poll `done` every 25 ms until it holds; past `within` panic naming `what`.
fn wait_for(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let t = std::time::Instant::now();
    while !done() {
        assert!(t.elapsed() < within, "{what}: not within {within:?}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Until the session's per-result code-out has promoted the VM's refs and
/// recorded it (its `codeout_fetch` row, the fetch's last step: the trigger
/// keeps the report in the same turn of the wrapper's runtime). The box
/// refs move earlier, and the census end row counts only the fetches whose
/// report was in before it (plan section 11: the end row, then the
/// trigger's 300 ms).
fn wait_for_fetch(rig: &common::remote::RemoteRig) {
    wait_for("the turn's code-out recorded (codeout_fetch promoted)", T, || audit_rows(rig, "codeout_fetch").iter().any(|r| r["detail"]["outcome"] == "promoted"));
}

/// T8.2 offline (plan Part A, the lead's integration; S9 after the S3
/// cut-over): the extension reopens a chat in a dirty workspace and runs
/// one turn on the rig's VM. The real wrapper in remote mode
/// (`AI_ENV_BRIDGE_MODE=remote`, its cwd the workspace under the roots)
/// goes through the routed endpoint to the in-process shim. Before the
/// spawn the pipeline seeds the VM (its HEAD the Mac's, no origin, the
/// Mac's uncommitted work carried uncommitted) and restores the picker's
/// transcript (a chat begun on the Mac: it goes up to the tests' S3, the
/// Mac keeping its view, then is pulled into the VM), which the CLI resumes
/// from. `initialize` is answered with the wrapper's pid, not the VM's. One
/// turn (echo, assistant, result): no mirror frame reaches the host or the
/// Mac (S9: the VM's argv carries no `--session-mirror`, never `--add-dir`
/// or the debug flags), and the CLI's `oauth_token_refresh` is answered
/// `{"accessToken":null}` by the wrapper. The turn's result fetches the
/// agent's commit (`FAKE_COMMIT`) into `refs/remotes/box/main` and the edit
/// it left uncommitted (`FAKE_WIP_EDIT`) into a `box/wip/*` snapshot, the
/// Mac's branches and worktree untouched; the code port's tokens last the
/// seed's 15 minutes for the seed, the session's 5 for that code-out (plan
/// §10); the turn's transcript then goes to S3 and the view is rewritten.
/// The host's EOF ends the session as the CLI's own exit does (half a
/// second, a last mirror frame on the way, dropped and counted): exit 0
/// within 1.5 s, the Mac holding only the chat's view,
/// nothing left in the shim's spawn table. No other spawn lived, so the
/// closing suspend reaches the fake API (SUSPENDED), and the platform's
/// `/suspend` snapshots an edit made after the last fetch. The census end
/// row holds every remote part (C6), the registry row the remote fields,
/// stderr no `ai-env:` line, and the process cost one Touch ID (D1). Later
/// `box fetch --wip` reaches the suspended VM (the endpoint resumes it) and
/// brings that last snapshot to the Mac.
#[test]
fn t8_2_a_fake_extension_session_runs_on_the_vm() {
    use ai_env_cli::bridge::api::{Call, VmState};
    use ai_env_cli::bridge::authwatch::AUTH_TIMERS;
    use ai_env_cli::bridge::remote::{CLOSE_BUDGET_MS, LEG_NAMES};
    use ai_env_cli::wire::workspace::CODE_PORT;
    let mut p = Harness::prepare();
    let sid = common::uuid(0x8820);
    let earlier = format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, common::uuid(0x8821));
    let mac_transcript = p.plant_transcript(&sid, &[earlier.as_str()]);
    let (work, head, vm_cwd, touch) = {
        let rig = p.rig();
        let work = rig.work();
        // The Mac's uncommitted work: the seed carries it (D2).
        std::fs::write(work.join("README.md"), "fixture, edited on the Mac\n").expect("edit README.md");
        std::fs::write(work.join("staged.txt"), "staged on the Mac\n").expect("write staged.txt");
        git_in(&work, &["add", "staged.txt"]);
        std::fs::write(work.join("notes.txt"), "untracked on the Mac\n").expect("write notes.txt");
        (work, rig.head().to_string(), rig.vm_cwd(), rig.decrypts())
    };
    let mac_before = mac_repo_view(&work);
    let knobs = [
        ("FAKE_RESUME_NEEDS_FILE", "1"),
        ("FAKE_WRITE_TRANSCRIPT", "1"),
        ("FAKE_OAUTH_REFRESH", "1"),
        ("FAKE_EDIT", "agent.txt:from the VM"),
        ("FAKE_COMMIT", "the agent's commit"),
        ("FAKE_WIP_EDIT", "agent.txt:from the VM, not committed yet"),
        ("FAKE_FINAL_MIRROR_MS", "200"),
        ("FAKE_EXIT_DELAY_MS", "500"),
    ];
    let resume = format!("--resume={sid}");
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume, "--add-dir", "/Users/someone/elsewhere"], &knobs);
    let init = h.send_initialize();
    let answer = h.expect_out(|v| is_response_to(v, &init), T);
    let vm_pid = h.fake_pid(1).unwrap_or_else(|| panic!("the VM's CLI logged no pid: {:?}", h.env_log()));
    assert_eq!(answer["response"]["response"]["pid"].as_u64(), Some(u64::from(h.pid())), "initialize is answered with the wrapper's pid: {answer}");
    assert_ne!(vm_pid, h.pid(), "the VM's CLI is another process");
    // The seed went in before the spawn: the VM's copy at the identical path.
    let vm_dir = h.rig().vm_path(&work);
    assert_eq!(git_in(&vm_dir, &["rev-parse", "HEAD"]), head, "the VM's HEAD is the Mac's");
    assert_eq!(git_in(&vm_dir, &["remote"]), "", "no origin in the VM");
    assert_eq!(read(&vm_dir.join(".git").join("shallow")).trim(), head, "shallow at the seeded commit");
    let status = ["--no-optional-locks", "status", "--porcelain", "--untracked-files=all"];
    assert_eq!(git_in(&vm_dir, &status), git_in(&work, &status), "the carried WIP is uncommitted in the VM, as on the Mac");
    let kinds = (git_in(&vm_dir, &["diff", "--name-only"]), git_in(&vm_dir, &["diff", "--cached", "--name-only"]), git_in(&vm_dir, &["ls-files", "--others", "--exclude-standard"]));
    assert_eq!(kinds, ("README.md".to_string(), "staged.txt".to_string(), "notes.txt".to_string()), "an edit, a staged file, an untracked one");
    // The transcript was restored before the spawn too: the CLI resumed from it, at the workspace's VM path.
    let started = h.expect_out(is_init, T);
    assert_eq!((started["session_id"].as_str(), started["cwd"].as_str()), (Some(sid.as_str()), Some(vm_cwd.as_str())), "{started}");
    assert!(h.env_log().iter().any(|l| l == "gen 1 resumed lines=1"), "the CLI found the restored transcript: {:?}", h.env_log());
    let vm_transcript = h.rig().vm_projects().join(h.slug()).join(format!("{sid}.jsonl"));
    assert_eq!(read(&vm_transcript), format!("{earlier}\n"), "the chat begun on the Mac, restored in the VM");
    assert!(ai_env_cli::wire::view::is_view_head(read(&mac_transcript).as_bytes()), "the Mac keeps the view in its place: {}", read(&mac_transcript));
    // One turn.
    let u = h.send_user("hello");
    h.expect_out(|v| is_result_for(v, &u), T);
    let frames = h.out_json();
    let at = frames.iter().position(common::is_init).expect("the init frame");
    let turn: Vec<&str> = frames[at + 1..].iter().map(|v| v["type"].as_str().unwrap_or_default()).collect();
    assert_eq!(turn, ["user", "assistant", "result"], "one turn, its echo first: {frames:?}");
    assert!(is_echo_of(&frames[at + 1], &u), "{}", frames[at + 1]);
    let out = h.out_lines();
    assert!(!out.iter().any(|l| l.contains("transcript_mirror") || l.contains("oauth_token_refresh")), "a mirror frame or the refresh request reached the host: {out:?}");
    // The VM's argv: --add-dir and the debug flags gone, no --session-mirror (S9: the transcript is kept in S3).
    let argv = h.argv_log().into_iter().next().expect("the VM's CLI logged its argv");
    assert!(argv.contains(&resume), "{argv:?}");
    for gone in ["--add-dir", "/Users/someone/elsewhere", "--debug", "--debug-to-stderr", "--session-mirror"] {
        assert!(!argv.iter().any(|a| a == gone), "{gone}: {argv:?}");
    }
    // The turn's code-out: the agent's commit under box/main, the edit it left uncommitted in a box/wip/* snapshot on it.
    wait_for_fetch(h.rig());
    // Then the turn's transcript to S3 (S9): the Mac's line and the turn's, byte for byte, its view on the Mac (the
    // stage's view first, then the sync's).
    synced(&mut h, &sid, 2);
    let manifest = ai_env_cli::bridge::s3::manifest::read(&ai_env_cli::bridge::config::Paths::from_root_and_env(h.rig().bridge(), None), &sid).unwrap().expect("the chat's manifest");
    let synced: Vec<u8> = manifest.parts.iter().flat_map(|p| h.rig().s3().get(&p.key).expect("each part in S3")).collect();
    assert_eq!(synced, std::fs::read(&vm_transcript).unwrap(), "S3 holds the VM's transcript, the Mac's part first: {:?}", manifest.parts);
    let vm_head = git_in(&vm_dir, &["rev-parse", "HEAD"]);
    assert_eq!((git_in(&work, &["rev-parse", "refs/remotes/box/main"]), git_in(&work, &["rev-parse", "refs/remotes/box/main^"])), (vm_head.clone(), head.clone()), "the agent's commit on the seeded head");
    assert_eq!(git_in(&work, &["show", "refs/remotes/box/main:agent.txt"]), "from the VM");
    let fetched_wips: Vec<String> = git_in(&work, &["for-each-ref", "--format=%(refname)", "refs/remotes/box/wip/"]).lines().map(str::to_string).collect();
    assert_eq!(fetched_wips.len(), 1, "one snapshot: {fetched_wips:?}");
    let wip = &fetched_wips[0];
    assert_eq!((git_in(&work, &["rev-parse", &format!("{wip}^")]), git_in(&work, &["show", &format!("{wip}:agent.txt")])), (vm_head.clone(), "from the VM, not committed yet".to_string()));
    assert_eq!(mac_repo_view(&work), mac_before, "the Mac's branches and worktree untouched");
    // An edit after the last fetch: only the closing /suspend snapshot keeps it.
    std::fs::write(vm_dir.join("late.txt"), "after the last fetch\n").expect("write late.txt in the VM");
    h.close_stdin();
    let (status_of, took) = h.wait(EXIT);
    assert_eq!(status_of.code(), Some(0), "{}", h.transcript());
    assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "the host's EOF to the exit: {took:?} (budget {CLOSE_BUDGET_MS} ms)\n{}", h.transcript());
    let mac_file = read(&mac_transcript);
    assert!(mac_file.lines().all(|l| l.starts_with(ai_env_cli::wire::view::VIEW_MARK_PREFIX)), "the last mirror frame, after the EOF, never reached the Mac: {mac_file}");
    assert!(read(&vm_transcript).lines().all(|l| !mac_file.contains(l)), "no line of the VM's transcript on the Mac");
    // The shim keeps a dead leader unreaped a moment (its group id pinned for the group's ladder), then reaps it.
    let spawns = h.rig().shim.spawns.detail();
    assert!(spawns.iter().all(|s| !s.status.alive), "a spawn still lives in the shim's table at the wrapper's exit: {spawns:?}");
    wait_for("the shim's spawn table empty and the VM's CLI reaped", Duration::from_secs(10), || h.rig().shim.spawns.detail().is_empty() && !common::pid_alive(vm_pid));
    let answer = r#"{"type":"control_response","response":{"subtype":"success","request_id":"o1","response":{"accessToken":null}}}"#;
    assert!(h.stdin_of(1).iter().any(|l| l == answer), "the CLI got the wrapper's own answer to its refresh: {:?}", h.stdin_of(1));
    // L2: no other spawn lived, so the closing suspend reached the fake API; the platform's /suspend snapshotted the late edit.
    let starts = h.audit_events("session_remote_start");
    assert_eq!(starts.len(), 1, "{starts:?}");
    let vm = starts[0]["detail"]["id"].as_str().expect("the VM's id").to_string();
    let rig = h.rig();
    wait_for("the VM suspended in the fake", Duration::from_secs(10), || rig.fake().vms.get(&vm).is_some_and(|v| v.state == VmState::Suspended));
    assert_eq!(rig.fake_calls().iter().filter(|c| matches!(c, Call::Suspend(id) if *id == vm)).count(), 1, "one closing suspend");
    // Plan §10: the code port's tokens last a seed's 15 minutes for the seed, the session's 5 for the turn's code-out.
    let code_tokens: Vec<u16> = rig
        .fake_calls()
        .iter()
        .filter_map(|c| match c {
            Call::Token { id, minutes, port: CODE_PORT } if *id == vm => Some(*minutes),
            _ => None,
        })
        .collect();
    assert_eq!(code_tokens, [15, 5], "{:?}", rig.fake_calls());
    wait_for("the platform's /suspend answered", Duration::from_secs(20), || rig.endpoint.hooks().iter().any(|k| k.vm == vm && k.name == "suspend" && k.status != 0));
    assert!(rig.endpoint.hooks().iter().any(|k| k.vm == vm && k.name == "suspend" && k.status == 200), "{:?}", rig.endpoint.hooks());
    let snapshots: Vec<String> = git_in(&vm_dir, &["for-each-ref", "--format=%(refname)", "refs/wip/"]).lines().map(str::to_string).collect();
    let newest = snapshots.iter().max().expect("a refs/wip snapshot in the VM");
    assert_eq!(git_in(&vm_dir, &["show", &format!("{newest}:late.txt")]), "after the last fetch", "{snapshots:?}");
    assert!(!fetched_wips.iter().any(|w| w.strip_prefix("refs/remotes/box/").is_some_and(|n| format!("refs/{n}") == *newest)), "/suspend's snapshot is a new one: {snapshots:?}");
    // The census end row: every remote part (C6) with S2's and S7's.
    let note = h.end_note();
    let part = |name: &str| note.split("; ").find_map(|p| p.strip_prefix(name)?.strip_prefix(':')).map(str::to_string);
    for name in ["vm", "vm_how", "legs", "init_ms", "seed", "transcript", "fetch", "credential", "close_ms", "auth_timers", "pid_rewrite"] {
        assert!(part(name).is_some(), "{name}: {note}");
    }
    let legs: Vec<String> = part("legs").unwrap_or_default().split(',').map(|l| l.split('=').next().unwrap_or_default().to_string()).collect();
    assert_eq!(legs, LEG_NAMES, "{note}");
    let words = ["vm", "vm_how", "vm_pid", "claude", "seed", "transcript", "fetch", "credential", "auth_timers", "pid_rewrite", "oauth_refresh_answered", "mirror", "mirror_dropped"].map(|n| part(n).unwrap_or_default());
    let vm_pid = vm_pid.to_string();
    assert_eq!(words, [vm.as_str(), "started", vm_pid.as_str(), AUTH_TIMERS.claude, "seeded", "staged", "1/1", "combined", "match", "ok", "1", "0/0", "1"].map(str::to_string), "{note}");
    assert!(part("init_ms").and_then(|ms| ms.parse::<u64>().ok()).is_some(), "{note}");
    assert!(part("close_ms").and_then(|ms| ms.parse::<u64>().ok()).is_some_and(|ms| ms < CLOSE_BUDGET_MS), "{note}");
    // The registry row: the session's own, remote, its VM, spawn, acked seq, seeded head and the snapshot fetched.
    let rows = h.registry_rows();
    let row = rows.iter().find(|r| r.get("session_id").and_then(toml::Value::as_str) == Some(sid.as_str())).unwrap_or_else(|| panic!("no row of {sid}: {rows:?}"));
    let field = |k: &str| row.get(k).and_then(toml::Value::as_str);
    assert_eq!((field("mode"), field("status"), field("microvm_id"), field("seeded_head")), (Some("remote"), Some("closed"), Some(vm.as_str()), Some(head.as_str())), "{row:?}");
    assert_eq!((field("spawn_id"), field("last_wip_fetch")), (part("spawn").as_deref(), Some(wip.as_str())), "{row:?}");
    assert!(row.get("last_acked_seq").and_then(toml::Value::as_integer).is_some_and(|n| n > 0), "{row:?}");
    assert_eq!(row.get("exit").and_then(toml::Value::as_integer), Some(0), "{row:?}");
    assert_eq!(starts[0]["detail"]["spawn"].as_str(), part("spawn").as_deref(), "{starts:?}");
    assert_eq!((h.audit_events("session_remote_end").len(), h.audit_events("session_remote_failed").len(), h.audit_events("transcript_stage").len()), (1, 0, 1));
    assert!(h.audit_events("transcript_pull").iter().any(|r| r["detail"]["outcome"] == "written" && r["detail"]["vm"] == vm.as_str()), "the restore into the VM is audited");
    assert!(!h.err_text().lines().any(|l| l.starts_with("ai-env:")), "the wrapper speaks no ai-env: line: {}", h.err_text());
    assert_eq!(h.rig().decrypts() - touch, 1, "one Touch ID for the process (D1)");
    // Later, on the Mac: box fetch reaches the suspended VM (the endpoint resumes it) and brings /suspend's snapshot.
    let rig = h.rig();
    let o = rig.run(&["box", "fetch", &work.display().to_string(), "--wip", "--json"], None);
    assert!(o.status.success(), "box fetch after the close: {}", String::from_utf8_lossy(&o.stderr));
    let fetched: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("box fetch --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
    let late = format!("refs/remotes/box/{}", newest.trim_start_matches("refs/"));
    assert_eq!(fetched["report"]["promoted"][&late].as_str(), Some(git_in(&vm_dir, &["rev-parse", newest]).as_str()), "{fetched}");
    assert_eq!(git_in(&work, &["show", &format!("{late}:late.txt")]), "after the last fetch");
    assert_eq!(mac_repo_view(&work), mac_before, "the Mac's branches and worktree untouched");
}

/// Wave 1 as one (W1's link, W2's pipeline, W3's routes, W4's data plane):
/// the real wrapper in remote mode runs a turn on the rig's VM. The
/// pipeline seeded the workspace through the lab endpoint into the VM's
/// copy at the identical path (HEAD the Mac's, shallow at it, no origin),
/// the CLI ran there (its init reports the VM path) and committed an edit;
/// the turn's result fetched that commit into `refs/remotes/box/main`
/// before the close (the Mac's branch and worktree untouched), and the
/// census says so; nothing is left running on the VM.
#[test]
fn a_remote_session_runs_on_the_in_process_shim() {
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_EDIT", "agent.txt:from the VM"), ("FAKE_COMMIT", "the agent's commit")]);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    let started = h.expect_out(is_init, T);
    let u = h.send_user("hello");
    h.expect_out(|v| is_result_for(v, &u), T);
    let rig = h.rig();
    assert_eq!(started["cwd"].as_str(), Some(rig.vm_cwd().as_str()), "the CLI runs at the workspace's VM path: {started}");
    let vm_git = |args: &[&str]| String::from_utf8_lossy(&Command::new(common::git_real()).args(args).current_dir(rig.vm_path(&rig.work())).output().unwrap().stdout).trim().to_string();
    assert_eq!(vm_git(&["rev-parse", "HEAD^"]), rig.head(), "the VM checked out the Mac's HEAD, then committed on it");
    assert_eq!(vm_git(&["remote"]), "", "no origin in the VM");
    assert_eq!(read(&rig.vm_path(&rig.work()).join(".git").join("shallow")).trim(), rig.head(), "shallow at the seeded commit");
    // The per-result code-out runs beside the session: the VM's branch lands under box/ on the Mac.
    wait_for_fetch(rig);
    let mac_git = |args: &[&str]| Command::new(common::git_real()).args(args).current_dir(rig.work()).output().unwrap();
    let text = |args: &[&str]| String::from_utf8_lossy(&mac_git(args).stdout).trim().to_string();
    assert_eq!((text(&["rev-parse", "refs/remotes/box/main"]), text(&["rev-parse", "refs/remotes/box/main^"])), (vm_git(&["rev-parse", "HEAD"]), rig.head().to_string()));
    assert_eq!(text(&["show", "refs/remotes/box/main:agent.txt"]), "from the VM");
    assert_eq!((text(&["rev-parse", "HEAD"]), text(&["status", "--porcelain"])), (rig.head().to_string(), String::new()), "the Mac's branch and worktree untouched");
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    let note = h.end_note();
    for part in ["mode:remote", "vm_how:started", "seed:seeded", ",spawn=", "fetch:1/1", "link_drops:0"] {
        assert!(note.contains(part), "{part}: {note}");
    }
    assert!(h.rig().vm_spawns().iter().all(|s| !s.alive), "nothing left running on the VM");
    assert_eq!((h.audit_events("session_remote_start").len(), h.audit_events("session_remote_end").len(), h.audit_events("session_remote_failed").len()), (1, 1, 0));
}

// ---- phase 0: the rig without the remote session -----------------------------------------

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn sha256_hex(text: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}

/// The rig's routing, today: a vpc VM started for the workspace (`vm run
/// --egress vpc`, through the green world's gate) is run on the shim by the
/// endpoint at its first request. `/health` with a Port(8080) token reaches
/// the shim's app listener (its `/run` seen, the fake claude's version probed
/// through `vm-claude`); a Port(9418) token reaches the code listener, which
/// answers 401 without the bearer; a 9418 token against 8080 is the check's
/// 403; a port with no route is the proxy's 502; a script for one port is
/// taken by that port's next request alone; every attempt records its port.
/// The agent's home is the Mac's HOME under the fs_root, so the workspace's
/// VM copy is under it (plan section 6's "under `--home`").
#[test]
fn the_rig_routes_each_port_to_its_listener_behind_the_check() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    assert_eq!(rig.vm_home(), rig.vm_path(rig.root()));
    assert!(rig.vm_path(&rig.work()).starts_with(rig.vm_home()), "{}", rig.vm_path(&rig.work()).display());
    let vm = rig.start_vm();
    let (app, code, other) = (rig.mint(&vm, 8080), rig.mint(&vm, 9418), rig.mint(&vm, 2049));
    let health = rig.send(&vm, &Req::get("/health", 8080, &app));
    assert_eq!(health.status, 200, "{}", health.text());
    let h = health.json();
    assert_eq!((h["microvm_id"].as_str(), h["run_hook_seen"].as_bool(), h["claude_version"].as_str()), (Some(vm.as_str()), Some(true), Some("2.1.305")), "{h}");
    let hooks: Vec<(&str, u16)> = rig.endpoint.hooks().iter().map(|k| (k.name, k.status)).collect();
    assert_eq!(hooks, [("run", 200)], "the endpoint ran the VM on the shim at its first request");
    assert_eq!(rig.send(&vm, &Req::get("/health", 9418, &code)).status, 401, "the code listener: every path behind the bearer");
    assert_eq!(rig.send(&vm, &Req { port: 8080, ..Req::get("/health", 9418, &code) }).status, 403, "a 9418 token on 8080");
    let unrouted = rig.send(&vm, &Req::get("/health", 2049, &other));
    assert_eq!((unrouted.status, unrouted.header("x-aws-proxy-error")), (502, Some("BAD_GATEWAY")), "nothing listens on 2049");
    rig.endpoint.script_port(9418, [common::fake_endpoint::Action::status(503, &[])]);
    assert_eq!(rig.send(&vm, &Req::get("/health", 8080, &app)).status, 200, "another port's request leaves the script alone");
    assert_eq!(rig.send(&vm, &Req::get("/health", 9418, &code)).status, 503, "the port's next request takes it");
    assert_eq!(rig.send(&vm, &Req::get("/health", 9418, &code)).status, 401, "once");
    let seen: Vec<(u16, u16)> = rig.endpoint.attempts().iter().map(|a| (a.port, a.status)).collect();
    assert_eq!(seen, [(8080, 200), (9418, 401), (8080, 403), (2049, 502), (8080, 200), (9418, 503), (9418, 401)]);
}

/// A request's body goes up while its answer's head is awaited, and a cut
/// mid-body is a cut: a 48 KiB `PUT` on the app port reaches the shim whole
/// (its bearer layer reads the body, at most `peer::DRAIN_MAX`, before its
/// 401), while one cut after 16 KiB gets no answer at all (status 0,
/// recorded as such).
#[test]
fn request_bodies_stream_through_and_a_cut_mid_body_answers_nothing() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let vm = rig.start_vm();
    let app = rig.mint(&vm, 8080);
    let body = vec![b'x'; 48 * 1024];
    let put = |path| Req { method: "PUT", path, port: 8080, token: &app, headers: &[], body: &body };
    let whole: Reply = rig.send(&vm, &put("/transcript"));
    assert_eq!(whole.status, 401, "{}", whole.text());
    rig.endpoint.script_port(8080, [common::fake_endpoint::Action::CutRequestAfter { bytes: 16 * 1024 }]);
    let cut = rig.send(&vm, &put("/transcript"));
    assert_eq!((cut.status, cut.body.len()), (0, 0), "no answer after the cut");
    let seen: Vec<(u16, u16)> = rig.endpoint.attempts().iter().map(|a| (a.port, a.status)).collect();
    assert_eq!(seen, [(8080, 401), (8080, 0)]);
}

/// The VM side's fake claude through the rig, today: `vm exec
/// --with-credential` runs `claude` on the shim (its `--claude` is the
/// fake, linked as `vm-claude`) with the environment the shim builds, and
/// the knobs in `vm-claude.knobs` reach it all the same, a quote-laden value
/// intact. It answers `initialize`, reports the workspace's VM path as its
/// cwd, logs to the local link's files (its argv; its config dir the VM
/// home's, never the Mac's) and reads the green world's token on fd 3, with
/// nothing under its name in its environment: one Touch ID (combined.env).
#[test]
fn the_vm_claude_takes_its_knobs_and_the_token_through_the_shim() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let vm = rig.start_vm();
    let tricky = "it's \"quoted\" $HOME `id` \\ \u{e9}";
    let token_log = rig.root().join("token.log");
    rig.set_vm_knobs(&[("FAKE_STDERR", tricky), ("FAKE_TOKEN_LOG", token_log.to_str().unwrap())]);
    let before = rig.decrypts();
    let init = r#"{"request_id":"i1","type":"control_request","request":{"subtype":"initialize"}}"#;
    let o = rig.run(&["vm", "exec", &vm, "--with-credential", "--", "claude", "--verbose"], Some(format!("{init}\n").as_bytes()));
    let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert_eq!(o.status.code(), Some(0), "{err}");
    let frames: Vec<Value> = out.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    assert!(frames.iter().any(|f| is_response_to(f, "i1")), "{out}");
    let init_frame = frames.iter().find(|f| is_init(f)).unwrap_or_else(|| panic!("no init frame: {out}"));
    assert_eq!(init_frame["cwd"].as_str(), Some(rig.vm_cwd().as_str()), "FAKE_CWD");
    assert!(err.lines().any(|l| l == tricky), "the knob's value intact: {err}");
    assert_eq!(rig.decrypts() - before, 1, "one Touch ID with combined.env");
    assert_eq!(read(&rig.root().join("argv.log")).lines().collect::<Vec<_>>(), ["--- gen 1", "--verbose"], "the shim's probe of --version is not a generation");
    let env = read(&rig.root().join("env.log"));
    let vm_config = rig.vm_home().join(".claude");
    assert_eq!(env.lines().next().and_then(|l| env_log_field(l, "CLAUDE_CONFIG_DIR")), vm_config.to_str(), "{env}");
    let sha8 = &sha256_hex(rig.token())[..8];
    assert_eq!(read(&token_log).trim(), format!("gen 1 source=fd len={} sha8={sha8} fdvar=3 envvar=absent", rig.token().len()));
    assert!(!out.contains(&rig.token()[13..]) && !err.contains(&rig.token()[13..]), "the token is in no output");
}

// ---- phase 0: the fake claude's S8 knobs -------------------------------------------------

/// A tempdir with the fake claude hard-linked as `claude` and a git
/// repository `ws/`: the fake run directly, as the shim runs it.
struct Fake {
    _p: common::Prepared,
    root: PathBuf,
}

impl Fake {
    fn new() -> Fake {
        let p = Harness::prepare();
        let root = p.root.clone();
        let ws = root.join("work");
        let o = Command::new(common::git_real()).args(["-c", "init.defaultBranch=main", "init", "-q"]).current_dir(&ws).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
        assert!(o.status.success(), "git init: {}", String::from_utf8_lossy(&o.stderr));
        Fake { _p: p, root }
    }

    /// The fake in `work/` with `args` and `knobs` (on top of a config dir
    /// under `home/.claude`), `stdin` then EOF, within [`T`] (killed and
    /// failed past it): (exit code, stdout lines, stderr).
    fn run(&self, args: &[&str], knobs: &[(&str, &str)], stdin: &str) -> (Option<i32>, Vec<String>, String) {
        let mut cmd = Command::new(self.root.join("claude"));
        cmd.args(args).current_dir(self.root.join("work")).env_clear().env("HOME", self.root.join("home")).env("PATH", "/usr/bin:/bin").env("CLAUDE_CONFIG_DIR", self.config());
        cmd.env("FAKE_ENV_LOG", self.root.join("env.log"));
        for (k, v) in knobs {
            cmd.env(k, v);
        }
        let o = common::bounded::run_within(cmd, Some(stdin.as_bytes()), T, "the fake claude");
        (o.status.code(), String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect(), String::from_utf8_lossy(&o.stderr).into_owned())
    }

    fn config(&self) -> PathBuf {
        self.root.join("home").join(".claude")
    }

    fn slug(&self) -> String {
        ai_env_cli::wire::slug::project_dir_name(&self.root.join("work")).unwrap()
    }
}

fn json_lines(lines: &[String]) -> Vec<Value> {
    lines.iter().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}"))).collect()
}

const INIT: &str = r#"{"request_id":"i1","type":"control_request","request":{"subtype":"initialize"}}"#;

fn user(uuid: &str) -> String {
    Harness::user_line(uuid, "hi")
}

/// The entries of the `transcript_mirror` frames among `out`, as the frames
/// carry them (no re-serialising), one line each.
fn frame_entries(out: &[String]) -> String {
    let mut mirrored = String::new();
    for line in out.iter().filter(|l| l.contains(r#""type":"transcript_mirror""#)) {
        let members: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> = serde_json::from_str(line).unwrap();
        let entries: Vec<Box<serde_json::value::RawValue>> = serde_json::from_str(members["entries"].get()).unwrap();
        mirrored.extend(entries.iter().map(|e| format!("{}\n", e.get())));
    }
    mirrored
}

/// FAKE_WRITE_TRANSCRIPT with --session-mirror: each turn appends its two
/// entries to the fake's own transcript and sends one mirror frame holding
/// the same two (its filePath under FAKE_CONFIG_DIR), before the turn's
/// rate_limit_event line (the 2.1.296 fixture's) and its result; a second
/// turn chains to the first. FAKE_FINAL_MIRROR_MS sends one more frame after
/// EOF, appended to the file too: the frames' entries joined are the file,
/// byte for byte, but the api-request lines 2.1.302 writes after each user
/// entry, which no frame carries (S9, `FAKE_API_REQUEST`; with it 0 the file
/// is the entries alone). FAKE_EXIT_DELAY_MS holds the exit that long after
/// EOF.
#[test]
fn the_fake_writes_its_transcript_and_mirrors_it_frame_for_frame() {
    let f = Fake::new();
    let (u1, u2) = (common::uuid(0x8801), common::uuid(0x8802));
    let shown = f.root.join("mac").join(".claude");
    let knobs = [
        ("FAKE_WRITE_TRANSCRIPT", "1"),
        ("FAKE_RATE_LIMIT_EVENT", "1"),
        ("FAKE_FINAL_MIRROR_MS", "100"),
        ("FAKE_EXIT_DELAY_MS", "400"),
        ("FAKE_CONFIG_DIR", shown.to_str().unwrap()),
    ];
    let started = std::time::Instant::now();
    let (code, out, err) = f.run(&["--session-mirror"], &knobs, &format!("{INIT}\n{}\n{}\n", user(&u1), user(&u2)));
    assert!(started.elapsed() >= Duration::from_millis(400), "the exit waited");
    assert_eq!(code, Some(0), "{err}");
    let frames = json_lines(&out);
    let kinds: Vec<&str> = frames.iter().map(|v| v["type"].as_str().unwrap_or_default()).collect();
    let turn = ["user", "assistant", "transcript_mirror", "rate_limit_event", "result"];
    let want: Vec<&str> = ["control_response", "system"].into_iter().chain(turn).chain(turn).chain(["transcript_mirror"]).collect();
    assert_eq!(kinds, want);
    let rate = out.iter().find(|l| l.contains("rate_limit_event")).unwrap();
    let fixture = include_str!("fixtures/claude/valid-stream-json-2.1.296.jsonl");
    assert!(fixture.lines().any(|l| l == rate), "the fixture's line: {rate}");
    let sid = common::fake_fixed_sid();
    let file = f.config().join("projects").join(f.slug()).join(format!("{sid}.jsonl"));
    let mirrors: Vec<&Value> = frames.iter().filter(|v| v["type"] == "transcript_mirror").collect();
    let path = shown.join("projects").join(f.slug()).join(format!("{sid}.jsonl"));
    assert!(mirrors.iter().all(|m| m["filePath"].as_str() == path.to_str()), "{mirrors:?}");
    // The entries as their frames carry them, byte for byte (no re-serialising): the file but its api-request lines.
    let mirrored = frame_entries(&out);
    let text = read(&file);
    assert_eq!(String::from_utf8(common::mirrored(text.as_bytes())).unwrap(), mirrored, "the frames' entries are the file but its api-request lines");
    let all: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let kinds: Vec<&str> = all.iter().map(|v| v["type"].as_str().unwrap_or_default()).collect();
    let turn = ["user", "api-request", "api-request-blob", "assistant"];
    assert_eq!(kinds, turn.into_iter().chain(turn).chain(["summary"]).collect::<Vec<_>>());
    for (at, n) in [(1, 1), (5, 2)] {
        let id = format!("req_fake_{n}_1");
        assert_eq!((all[at]["requestId"].as_str(), all[at]["sessionId"].as_str(), all[at + 1]["requestId"].as_str()), (Some(id.as_str()), Some(sid.as_str()), Some(id.as_str())), "{text}");
    }
    let entries: Vec<Value> = mirrored.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(entries.len(), 5);
    assert_eq!((entries[0]["uuid"].as_str(), entries[2]["uuid"].as_str()), (Some(u1.as_str()), Some(u2.as_str())));
    assert_eq!(entries[2]["parentUuid"], entries[1]["uuid"], "the second turn chains to the first");
    assert_eq!((entries[4]["type"].as_str(), &entries[4]["leafUuid"]), (Some("summary"), &entries[3]["uuid"]));
    // FAKE_API_REQUEST=0 (2.1.296 and earlier): the file is the frames' entries, byte for byte.
    let old = Fake::new();
    let shown = old.root.join("mac").join(".claude");
    let knobs = [("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_API_REQUEST", "0"), ("FAKE_FINAL_MIRROR_MS", "100"), ("FAKE_CONFIG_DIR", shown.to_str().unwrap())];
    let (code, out, err) = old.run(&["--session-mirror"], &knobs, &format!("{INIT}\n{}\n{}\n", user(&u1), user(&u2)));
    assert_eq!(code, Some(0), "{err}");
    let file = old.config().join("projects").join(old.slug()).join(format!("{sid}.jsonl"));
    assert_eq!(read(&file), frame_entries(&out), "FAKE_API_REQUEST=0: the frames' entries are the file");
    assert_eq!(read(&file).lines().count(), 5);
}

/// A1: FAKE_USAGE_LIMIT refuses a turn as claude 2.1.305 does (S10 part
/// B's B2): after the echo, FAKE_USAGE_LIMIT_EVENT's event, then one result
/// line that is the fixture but for its ids (this session's, the user
/// line's uuid as user_message_uuid(s), a uuid of its own), its keys in the
/// fixture's order; no reply, no turn effects. `turn:<n>` refuses that turn
/// alone; FAKE_USAGE_LIMIT_TEXT and FAKE_USAGE_LIMIT_PARAMS set the text and
/// add the params. FAKE_RATE_LIMIT_INFO's info goes out verbatim in an
/// answered turn's event, in place of FAKE_RATE_LIMIT_EVENT's line.
#[test]
fn the_fake_refuses_a_usage_limited_turn_as_claude_2_1_305_does() {
    let f = Fake::new();
    let (u1, u2) = (common::uuid(0x8811), common::uuid(0x8812));
    let info = r#"{"status":"allowed_warning","rateLimitType":"seven_day","utilization":0.81,"unifiedWindows":{"seven_day":{"utilization":0.81,"resetsAt":1792663200}}}"#;
    let knobs = [("FAKE_USAGE_LIMIT", "turn:2"), ("FAKE_USAGE_LIMIT_EVENT", r#"{"status":"rejected","rateLimitType":"seven_day"}"#), ("FAKE_RATE_LIMIT_INFO", info), ("FAKE_RATE_LIMIT_EVENT", "1"), ("FAKE_WRITE_TRANSCRIPT", "1")];
    let (code, out, err) = f.run(&[], &knobs, &format!("{INIT}\n{}\n{}\n", user(&u1), user(&u2)));
    assert_eq!(code, Some(0), "{err}");
    let frames = json_lines(&out);
    let kinds: Vec<&str> = frames.iter().map(|v| v["type"].as_str().unwrap_or_default()).collect();
    assert_eq!(kinds, ["control_response", "system", "user", "assistant", "rate_limit_event", "result", "user", "rate_limit_event", "result"], "turn 1 answered, turn 2 refused");
    let answered = out.iter().find(|l| l.contains("rate_limit_event")).unwrap();
    assert!(answered.starts_with(&format!(r#"{{"type":"rate_limit_event","rate_limit_info":{info},"uuid":""#)), "the info verbatim: {answered}");
    assert_eq!(frames[7]["rate_limit_info"]["status"], "rejected");
    let sid = common::fake_fixed_sid();
    let fixture = include_str!("fixtures/claude/usage-limit-result-2.1.305.json").trim_end();
    let (theirs, ours): (Value, Value) = (serde_json::from_str(fixture).unwrap(), serde_json::from_str(&out[8]).unwrap());
    assert_eq!((ours["session_id"].as_str(), ours["user_message_uuid"].as_str(), ours["user_message_uuids"][0].as_str()), (Some(sid.as_str()), Some(u2.as_str()), Some(u2.as_str())));
    let ids = |v: &Value, k: &str| v[k].as_str().unwrap().to_string();
    let same = out[8].replace(&sid, &ids(&theirs, "session_id")).replace(&u2, &ids(&theirs, "user_message_uuid")).replace(&ids(&ours, "uuid"), &ids(&theirs, "uuid"));
    assert_eq!(same, fixture, "the fixture, byte for byte, but for its ids");
    let transcript = read(&f.config().join("projects").join(f.slug()).join(format!("{sid}.jsonl")));
    assert_eq!(transcript.lines().filter(|l| l.contains("\"type\":\"user\"")).count(), 1, "the refused turn wrote nothing");
    // Every turn, its own text and the params.
    let g = Fake::new();
    let knobs = [("FAKE_USAGE_LIMIT", "1"), ("FAKE_USAGE_LIMIT_TEXT", "You've hit your session limit · resets 3pm (UTC)"), ("FAKE_USAGE_LIMIT_PARAMS", r#"{"rateLimitType":"five_hour","resetsAt":1792591200}"#)];
    let (code, out, err) = g.run(&[], &knobs, &format!("{INIT}\n{}\n", user(&u1)));
    assert_eq!(code, Some(0), "{err}");
    let result: Value = serde_json::from_str(out.last().unwrap()).unwrap();
    assert_eq!((result["result"].as_str(), result["api_error_params"]["rate_limit_info"]["rateLimitType"].as_str()), (Some("You've hit your session limit · resets 3pm (UTC)"), Some("five_hour")));
    assert!(out.last().unwrap().starts_with(r#"{"api_error":"usage_limit_reached","api_error_origin":"first_party","api_error_params":{"rate_limit_info":"#), "{}", out.last().unwrap());
    assert!(!out.iter().any(|l| l.contains("\"type\":\"assistant\"")), "no reply");
}

/// FAKE_RESUME_NEEDS_FILE: a --resume whose transcript is missing from the
/// config dir is the CLI's miss (logged `resumed lines=missing`, exit 1
/// before reading stdin); once the file is there the session resumes (logged
/// with its line count) under that id. FAKE_CWD is the cwd its init frame
/// reports and the slug it looks under.
#[test]
fn the_fake_resumes_only_from_a_transcript_on_its_disk() {
    let f = Fake::new();
    let sid = common::uuid(0x8803);
    let shown_cwd = "/Users/mike/\u{41f}\u{440}\u{43e}\u{435}\u{43a}\u{442}/ws";
    let knobs = [("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_CWD", shown_cwd)];
    let (code, out, err) = f.run(&["--resume", &sid], &knobs, &format!("{INIT}\n"));
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains(&format!("No conversation found with session ID: {sid}")), "{err}");
    assert!(out.iter().all(|l| !l.contains("control_response")), "a miss before stdin: {out:?}");
    let slug = ai_env_cli::wire::slug::slug_of(shown_cwd);
    let dir = f.config().join("projects").join(&slug);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{sid}.jsonl")), "{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n").unwrap();
    let (code, out, err) = f.run(&["--resume", &sid], &knobs, &format!("{INIT}\n"));
    assert_eq!(code, Some(0), "{err}");
    let init = json_lines(&out).into_iter().find(is_init).unwrap_or_else(|| panic!("{out:?}"));
    assert_eq!((init["session_id"].as_str(), init["cwd"].as_str()), (Some(sid.as_str()), Some(shown_cwd)));
    let logged: Vec<String> = read(&f.root.join("env.log")).lines().filter(|l| l.contains("resumed")).map(str::to_string).collect();
    assert_eq!(logged, ["gen 1 resumed lines=missing", "gen 1 resumed lines=3"]);
}

/// FAKE_EDIT, FAKE_COMMIT and FAKE_WRITE_SETTINGS act before the turn's
/// result: the edit is in the commit (`git add -A` first), the commit is
/// claude-agent's on the branch, the settings land in the cwd's
/// `.claude/settings.local.json` and (`both:`) the config dir's
/// `settings.json`; nothing of git's reaches stdout.
#[test]
fn the_fake_edits_commits_and_writes_settings_during_a_turn() {
    let f = Fake::new();
    let settings = r#"{"permissions":{"allow":["Bash(ls:*)"]}}"#;
    let both = format!("both:{settings}");
    let knobs = [("FAKE_EDIT", "src/note.txt:one: two"), ("FAKE_COMMIT", "vm work"), ("FAKE_WRITE_SETTINGS", both.as_str())];
    let u = common::uuid(0x8804);
    let (code, out, err) = f.run(&[], &knobs, &format!("{INIT}\n{}\n", user(&u)));
    assert_eq!(code, Some(0), "{err}");
    assert!(json_lines(&out).iter().any(|v| is_result_for(v, &u)), "{out:?}");
    let work = f.root.join("work");
    assert_eq!(read(&work.join("src").join("note.txt")), "one: two\n");
    assert_eq!(read(&work.join(".claude").join("settings.local.json")), format!("{settings}\n"));
    assert_eq!(read(&f.config().join("settings.json")), format!("{settings}\n"));
    let git = |args: &[&str]| String::from_utf8_lossy(&Command::new(common::git_real()).args(args).current_dir(&work).output().unwrap().stdout).trim().to_string();
    assert_eq!(git(&["log", "-1", "--format=%an|%s"]), "claude-agent|vm work");
    assert_eq!(git(&["show", "--name-only", "--format=", "HEAD"]).lines().collect::<Vec<_>>(), [".claude/settings.local.json", "src/note.txt"]);
    assert_eq!(git(&["status", "--porcelain"]), "", "the edit and the settings are in the commit");
}

/// FAKE_WIP_EDIT acts after FAKE_COMMIT: one turn leaves a commit (with
/// FAKE_EDIT's edit) and, over it, an edit that is not committed: what
/// T8.2's per-result code-out brings back as `box/main` and `box/wip/*`.
#[test]
fn the_fake_leaves_its_wip_edit_uncommitted_beside_the_turns_commit() {
    let f = Fake::new();
    let knobs = [("FAKE_EDIT", "src/note.txt:committed"), ("FAKE_COMMIT", "vm work"), ("FAKE_WIP_EDIT", "src/note.txt:not committed")];
    let u = common::uuid(0x8808);
    let (code, out, err) = f.run(&[], &knobs, &format!("{INIT}\n{}\n", user(&u)));
    assert_eq!(code, Some(0), "{err}");
    assert!(json_lines(&out).iter().any(|v| is_result_for(v, &u)), "{out:?}");
    let work = f.root.join("work");
    assert_eq!((git_in(&work, &["show", "HEAD:src/note.txt"]), read(&work.join("src").join("note.txt"))), ("committed".to_string(), "not committed\n".to_string()));
    assert_eq!((git_in(&work, &["diff", "--name-only"]), git_in(&work, &["diff", "--cached", "--name-only"])), ("src/note.txt".to_string(), String::new()), "the WIP edit alone is uncommitted");
}

/// FAKE_ONBOARDING: one stderr line, then nothing is answered, not even
/// `initialize`, until EOF (exit 1); every line is still logged.
#[test]
fn the_fake_stalls_like_an_onboarding() {
    let f = Fake::new();
    let log = f.root.join("stdin.log");
    let (code, out, err) = f.run(&[], &[("FAKE_ONBOARDING", "1"), ("FAKE_STDIN_LOG", log.to_str().unwrap())], &format!("{INIT}\n{}\n", user(&common::uuid(0x8805))));
    assert_eq!((code, out.len()), (Some(1), 0), "{out:?}");
    assert!(err.contains("FAKE_ONBOARDING"), "{err}");
    assert_eq!(read(&log).lines().count(), 2);
}

// ---- phase 0: one body, two links --------------------------------------------------------

on_links!(
    /// One turn, then EOF, on either link: the `initialize` answer, the init,
    /// the turn's result, one child generation that read both lines, exit 0.
    a_turn_round_trips_on_either_link,
    |link| {
        let mut h = Harness::prepare().spawn_on(link, "local-child", &[], &[]);
        let init = h.send_initialize();
        h.expect_out(|v| is_response_to(v, &init), T);
        h.expect_out(is_init, T);
        let u = h.send_user("hello");
        h.expect_out(|v| is_result_for(v, &u), T);
        h.close_stdin();
        let (status, _) = h.wait(EXIT);
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
        assert_eq!((h.spawn_count(), h.stdin_of(1).len()), (1, 2), "{}", h.transcript());
        if link.is_remote() {
            assert!(h.rig().vm_spawns().iter().all(|s| !s.alive), "nothing left running on the VM");
        }
    }
);

// ---- S8 wave 1 (W1): the remote link over the real session -------------------------------
//
// `RemoteLinks` with W2's pre-spawn steps put aside (`RemoteLinks::with_pipeline`):
// each generation's session is `agent::run_spawn_with` of the VM's fake claude on
// the rig's VM, through the routed endpoint to the in-process shim, handed to the
// link as the pipeline hands it over. What the link makes of it is what the pump
// takes: `Started` first, the lines, the exit as both EOFs and a status, the
// wrapper's own detach as `Detached`.

mod remote_link {
    use super::common::remote::{RemoteRig, BACKOFF_MS};
    use super::common::{is_init, is_response_to, is_result_for, Harness};
    use ai_env_cli::bridge::agent::{run_spawn_with, AgentEnv, AgentTarget, RunPolicy, SpawnSpec, Start};
    use ai_env_cli::bridge::api::AuthToken;
    use ai_env_cli::bridge::authwatch::AUTH_TIMERS;
    use ai_env_cli::bridge::codeout::{CodeoutCtx, CodeoutTrigger};
    use ai_env_cli::bridge::config::{BridgeConfig, Paths, TransportCfg};
    use ai_env_cli::bridge::dataplane::{CodeoutBody, DataPlane, DpReply, TokenSource};
    use ai_env_cli::bridge::errors::BridgeError;
    use ai_env_cli::bridge::pump::{ChildEvent, ChildInput, ChildLink, Sig};
    use ai_env_cli::bridge::remote::link::{LinkFactory, RemoteLinks, StartReq, StartWhy};
    use ai_env_cli::bridge::remote::pipeline::PipelineEnd;
    use ai_env_cli::bridge::transport::AgentDial;
    use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
    use ai_env_cli::bridge::vm::registry::read_row;
    use ai_env_cli::bridge::workspace::{Head, WorkspaceRef, WsKind};
    use ai_env_cli::wire::frame::SpawnId;
    use ai_env_cli::wire::workspace::{CodeoutRequest, ObjectFormat, SeedQuery, SeedReply, SeedState, SettingsCapture, TranscriptStat};
    use bytes::Bytes;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Every wait's bound.
    const T: Duration = Duration::from_secs(60);
    const INIT: &str = r#"{"request_id":"i1","type":"control_request","request":{"subtype":"initialize"}}"#;

    /// The data plane the code-out trigger is built with; no test here asks for a code-out.
    struct NoDataPlane;

    fn unreached() -> BridgeError {
        BridgeError::Endpoint("no data plane in the link's tests".into())
    }

    impl TokenSource for NoDataPlane {
        async fn token(&self, _: u16) -> Result<AuthToken, BridgeError> {
            Err(unreached())
        }
    }

    impl DataPlane for NoDataPlane {
        async fn seed_state(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SeedState>, BridgeError> {
            Err(unreached())
        }

        async fn put_seed(&self, _: &AgentTarget, _: &AuthToken, _: &SeedQuery, _: &Path, _: u64) -> Result<DpReply<SeedReply>, BridgeError> {
            Err(unreached())
        }

        async fn post_codeout(&self, _: &AgentTarget, _: &AuthToken, _: &CodeoutRequest, _: &Path, _: u64) -> Result<DpReply<CodeoutBody>, BridgeError> {
            Err(unreached())
        }

        async fn transcript_stat(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<TranscriptStat>, BridgeError> {
            Err(unreached())
        }

        async fn get_settings(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SettingsCapture>, BridgeError> {
            Err(unreached())
        }
    }

    fn on_local<F: std::future::Future>(f: F) -> F::Output {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime");
        tokio::task::LocalSet::new().block_on(&rt, f)
    }

    /// The remote factory on `vm`, the rig's: each start runs the session of
    /// `claude <stream-json argv>` there, as the pipeline's P4 would (no
    /// Touch ID, no SELECT_VM, no seed, no credential).
    fn links_on(rig: &RemoteRig, vm: &str) -> RemoteLinks {
        let (bridge, fake, addr, work, vm) = (rig.bridge(), rig.fake_path(), rig.endpoint.addr, rig.work(), vm.to_string());
        RemoteLinks::with_pipeline(
            Paths::from_root_and_env(bridge.clone(), None),
            Box::new(move |_gen, _why, io| {
                let (bridge, fake, work, vm) = (bridge.clone(), fake.clone(), work.clone(), vm.clone());
                Box::pin(async move {
                    let paths = Paths::from_root_and_env(bridge, None);
                    let row = read_row(&paths, &vm).ok().flatten().expect("the VM's row");
                    let spawn_id = SpawnId::new_v7();
                    let argv = ["claude", "--output-format", "stream-json", "--verbose", "--input-format", "stream-json"].map(String::from).to_vec();
                    let spec = SpawnSpec { argv, cwd: None, env: BTreeMap::new(), detach_grace_s: Some(60), id: Some(spawn_id.clone()) };
                    let (session_paths, session_row, session_fake) = (paths.clone(), row.clone(), fake.clone());
                    let session = tokio::task::spawn_local(async move {
                        let api = FileFakeMicrovmApi::open(&session_fake)?;
                        let target = AgentTarget::from_row(&session_row)?;
                        let env = AgentEnv { api: &api, ep: &api, paths: &session_paths, target, policy: RunPolicy::from_cfg(&TransportCfg::default(), &session_row, Some(BACKOFF_MS)), dial: AgentDial { local: Some(addr) } };
                        run_spawn_with(&env, Start::New(spec), io, None).await
                    });
                    let ws = WorkspaceRef {
                        cwd: work.clone(),
                        root: work.clone(),
                        vm_cwd: work.display().to_string(),
                        vm_root: work.display().to_string(),
                        slug: "work".into(),
                        kind: WsKind::Git { git_dir: work.join(".git"), common_dir: work.join(".git"), object_format: ObjectFormat::Sha1 },
                        head: Head::Detached { sha: "a".repeat(40) },
                        seed_branch: None,
                    };
                    let api = FileFakeMicrovmApi::open(&fake).expect("the fake API");
                    let target = AgentTarget::from_row(&row).expect("the VM's target");
                    let trigger = CodeoutTrigger::spawn(CodeoutCtx { api: Arc::new(api), dp: Arc::new(NoDataPlane), tokens: Arc::new(NoDataPlane), paths, cfg: Arc::new(BridgeConfig::default()), target, ws, capture_settings: false, transcript: None });
                    Ok(PipelineEnd { vm, vm_how: "reused", legs: Vec::new(), seed: "up_to_date", transcript: None, seeded_head: None, credential: None, delivery: None, spawn_id, started_by: None, trigger, session, carried: None, moved: None, after_started: None, seal: None })
                })
            }),
        )
    }

    fn line(text: &str) -> ChildInput {
        ChildInput::Line(Bytes::from(format!("{text}\n")))
    }

    async fn next(link: &mut ChildLink) -> Option<ChildEvent> {
        tokio::time::timeout(T, link.events.recv()).await.expect("an event within the bound")
    }

    /// The link's next line, as JSON (a non-line event before it fails).
    async fn next_json(link: &mut ChildLink) -> Value {
        match next(link).await {
            Some(ChildEvent::Line(b)) => serde_json::from_slice(&b).unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&b[..b.len().min(200)]))),
            other => panic!("not a line: {:?}", other.map(|e| e.kind())),
        }
    }

    /// No spawn left alive on the VM, within the bound.
    fn vm_spawns_end(rig: &RemoteRig) {
        let until = Instant::now() + Duration::from_secs(10);
        while rig.vm_spawns().iter().any(|s| s.alive) {
            assert!(Instant::now() < until, "a spawn still runs on the VM: {:?}", rig.vm_spawns());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A turn over the link: `Started` first (the VM's pid, and its claude as
    /// the shim's `hello_ok` named it, the version `AUTH_TIMERS` measured),
    /// the `initialize` answer and the init, the turn's echo, reply and
    /// result; the host's EOF is the CLI's stdin's, and its own exit 0 comes
    /// back as both EOFs and the status; nothing is left on the VM.
    #[test]
    fn a_turn_crosses_the_remote_link_and_the_clis_exit_ends_it() {
        let mut p = Harness::prepare();
        let rig = p.rig();
        let vm = rig.start_vm();
        on_local(async {
            let mut links = links_on(rig, &vm);
            let mut link = links.start(1, StartReq { why: StartWhy::First, credential: None }).expect("a start");
            assert_eq!(link.pid, None);
            link.input.send(line(INIT)).await.unwrap();
            match next(&mut link).await {
                Some(ChildEvent::Started(s)) => {
                    assert!(s.vm_pid > 0);
                    assert_eq!(s.claude_version.as_deref(), Some(AUTH_TIMERS.claude), "the hello_ok's claude");
                }
                other => panic!("{:?}", other.map(|e| e.kind())),
            }
            assert!(is_response_to(&next_json(&mut link).await, "i1"));
            assert!(is_init(&next_json(&mut link).await));
            let u = super::common::uuid(0x8811);
            link.input.send(line(&Harness::user_line(&u, "hello"))).await.unwrap();
            let mut turn = Vec::new();
            while !turn.last().is_some_and(|v| is_result_for(v, &u)) {
                turn.push(next_json(&mut link).await);
            }
            assert_eq!(turn.iter().map(|v| v["type"].as_str().unwrap_or_default()).collect::<Vec<_>>(), ["user", "assistant", "result"]);
            let snap = links.snapshot().expect("a remote snapshot");
            assert_eq!((snap.vm.as_deref(), snap.auth_timers.as_deref(), snap.link_up), (Some(vm.as_str()), Some("match"), true));
            assert!(snap.last_acked_seq >= 1, "{snap:?}");
            let closed = Instant::now();
            link.input.send(ChildInput::Eof).await.unwrap();
            let mut ends = Vec::new();
            while let Some(ev) = next(&mut link).await {
                ends.push(ev);
            }
            let kinds: Vec<&str> = ends.iter().map(ChildEvent::kind).collect();
            assert_eq!(kinds, ["stdout_eof", "stderr_eof", "exit"], "the link ends with the exit");
            assert!(matches!(ends[2], ChildEvent::Exit(Some(s)) if s.code() == Some(0)));
            assert!(closed.elapsed() < Duration::from_secs(5), "{:?}", closed.elapsed());
            links.close(Duration::from_secs(5)).await;
        });
        vm_spawns_end(rig);
    }

    /// M09 through the shim: a 20 MiB stdout line passes whole while the
    /// shim keeps at most its 8 MiB window unacked: the link marks each chunk
    /// once its lines are handed over (a chunk that ends no line at once).
    #[test]
    fn a_20_mib_stdout_line_crosses_the_shims_window_whole() {
        const PAD: usize = 20 * 1024 * 1024;
        let mut p = Harness::prepare();
        let rig = p.rig();
        rig.set_vm_knobs(&[("FAKE_STREAM_LINES", "1"), ("FAKE_STREAM_PAD", &PAD.to_string())]);
        let vm = rig.start_vm();
        on_local(async {
            let mut links = links_on(rig, &vm);
            let mut link = links.start(1, StartReq { why: StartWhy::First, credential: None }).expect("a start");
            link.input.send(line(INIT)).await.unwrap();
            assert!(matches!(next(&mut link).await, Some(ChildEvent::Started(_))));
            assert!(is_response_to(&next_json(&mut link).await, "i1"));
            assert!(is_init(&next_json(&mut link).await));
            match next(&mut link).await {
                Some(ChildEvent::Line(b)) => {
                    let head = br#"{"type":"stream_event","n":1,"pad":""#;
                    assert_eq!(b.len(), head.len() + PAD + 2, "the long line whole");
                    assert!(b.starts_with(head) && b.ends_with(b"\"}"));
                }
                other => panic!("{:?}", other.map(|e| e.kind())),
            }
            link.input.send(ChildInput::Eof).await.unwrap();
            let mut last = None;
            while let Some(ev) = next(&mut link).await {
                last = Some(ev);
            }
            assert!(matches!(last, Some(ChildEvent::Exit(Some(s))) if s.code() == Some(0)), "{:?}", last.map(|e| e.kind()));
            links.close(Duration::from_secs(5)).await;
        });
        vm_spawns_end(rig);
    }

    /// L2 through the shim: a stop after `Started` is `Signal(Term)` plus
    /// `detach{final}`; the session ends on its own detach (`Detached`, never
    /// an exit or a loss), and the shim ends the CLI.
    #[test]
    fn a_stop_after_started_detaches_and_the_shim_ends_the_cli() {
        let mut p = Harness::prepare();
        let rig = p.rig();
        let vm = rig.start_vm();
        on_local(async {
            let mut links = links_on(rig, &vm);
            let mut link = links.start(1, StartReq { why: StartWhy::First, credential: None }).expect("a start");
            link.input.send(line(INIT)).await.unwrap();
            assert!(matches!(next(&mut link).await, Some(ChildEvent::Started(_))));
            assert!(is_response_to(&next_json(&mut link).await, "i1"));
            assert!(is_init(&next_json(&mut link).await));
            let stopped = Instant::now();
            link.signal.send(Sig::Term).unwrap();
            let mut ends = Vec::new();
            while let Some(ev) = next(&mut link).await {
                ends.push(ev);
            }
            assert!(matches!(ends.last(), Some(ChildEvent::Detached)), "{:?}", ends.iter().map(ChildEvent::kind).collect::<Vec<_>>());
            assert!(stopped.elapsed() < Duration::from_secs(5), "{:?}", stopped.elapsed());
            links.close(Duration::from_secs(5)).await;
        });
        vm_spawns_end(rig);
    }

    /// T8.6 offline: `drop_transport` (what `session drop-transport`'s
    /// signal asks) closes the running spawn's socket from the wrapper's
    /// side mid-stream, past the shim's 8 MiB window; the session reattaches
    /// (`Link(false)`, then `Link(true)`, never a loss) and every stdout line
    /// arrives once, in order, across the drop; the CLI's own exit ends it.
    #[test]
    fn a_dropped_transport_reattaches_and_every_line_arrives_once() {
        const LINES: u64 = 400;
        const PAD: usize = 64 * 1024;
        let mut p = Harness::prepare();
        let rig = p.rig();
        rig.set_vm_knobs(&[("FAKE_STREAM_LINES", &LINES.to_string()), ("FAKE_STREAM_PAD", &PAD.to_string())]);
        let vm = rig.start_vm();
        on_local(async {
            let mut links = links_on(rig, &vm);
            let mut link = links.start(1, StartReq { why: StartWhy::First, credential: None }).expect("a start");
            link.input.send(line(INIT)).await.unwrap();
            assert!(matches!(next(&mut link).await, Some(ChildEvent::Started(_))));
            assert!(is_response_to(&next_json(&mut link).await, "i1"));
            assert!(is_init(&next_json(&mut link).await));
            let (mut ns, mut ups) = (Vec::new(), Vec::new());
            while ns.len() < LINES as usize {
                match next(&mut link).await {
                    Some(ChildEvent::Line(b)) => {
                        let v: Value = serde_json::from_slice(&b).expect("a JSON line");
                        assert_eq!(v["type"], "stream_event", "{}", String::from_utf8_lossy(&b[..b.len().min(200)]));
                        ns.push(v["n"].as_u64().expect("its n"));
                        if ns.len() == 10 {
                            links.drop_transport();
                        }
                    }
                    Some(ChildEvent::Link(up)) => ups.push(up),
                    Some(ChildEvent::Note(_)) => {}
                    other => panic!("{:?}", other.map(|e| e.kind())),
                }
            }
            assert!(ns == (1..=LINES).collect::<Vec<_>>(), "every line once, in order: {} lines", ns.len());
            link.input.send(ChildInput::Eof).await.unwrap();
            let mut ends = Vec::new();
            while let Some(ev) = next(&mut link).await {
                match ev {
                    ChildEvent::Link(up) => ups.push(up),
                    ChildEvent::Note(_) => {}
                    ev => ends.push(ev),
                }
            }
            assert_eq!(ups, [false, true], "the socket dropped and came back");
            let kinds: Vec<&str> = ends.iter().map(ChildEvent::kind).collect();
            assert_eq!(kinds, ["stdout_eof", "stderr_eof", "exit"], "the CLI's own exit ends the link, never a loss");
            assert!(matches!(ends[2], ChildEvent::Exit(Some(s)) if s.code() == Some(0)));
            assert_eq!(links.snapshot().expect("a remote snapshot").link_drops, 1);
            links.close(Duration::from_secs(5)).await;
        });
        vm_spawns_end(rig);
    }
}

// ---- S8 wave 1, W2: the remote session's pipeline (P0 to P4, the close's suspend) -----------
//
// The real `ai-env-claude` in remote mode against the rig. Each needs the
// whole remote session: W1's link (the pump's remote start, its first line,
// the pending start's close), W3's routes (the seed, the transcript) and
// W4's data plane (`workspace::resolve` and the seed), merged by the lead's
// integration. The pipeline's own units (the prechecks' failures and their
// lines, the `Choice`, the session's environment, the unseal lock, the
// closing suspend's conditions) are in `src/bridge/remote/`,
// `src/bridge/vm/run.rs` and `src/bridge/agent/credential.rs`.

/// The wrapper of the rig in remote mode, run to its end with stdin closed
/// at once, in `cwd` (the rig's workspace unless given), within the rig's
/// `LIMIT` (killed and failed past it): exit code, stderr.
fn remote_run(rig: &common::remote::RemoteRig, cwd: Option<&Path>, envs: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut cmd = rig.wrapper(&[], envs);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = common::bounded::run_within(cmd, None, common::remote::LIMIT, "the wrapper");
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The last line of a stderr text.
fn last_line(err: &str) -> &str {
    err.lines().last().unwrap_or_default()
}

/// D1, P0's argv and P4: one Touch ID for the whole session (a current
/// `combined.env` opens the runtime key and the token together); the VM's
/// argv carries neither `--add-dir` nor the debug flags, nor (S9: the
/// transcript is kept in S3) `--session-mirror`; the census end row names
/// the VM, how it was chosen, the legs and the delivery; nothing on stderr
/// says `ai-env:`.
#[test]
fn the_vm_argv_has_no_session_mirror_add_dir_or_debug_and_one_touch_id() {
    let mut p = Harness::prepare();
    let before = p.rig().decrypts();
    let mut h = p.spawn_on(common::Link::Remote, "", &["--add-dir", "/Users/someone/elsewhere"], &[]);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    h.expect_out(is_init, T);
    let u = h.send_user("hello");
    h.expect_out(|v| is_result_for(v, &u), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert_eq!(h.rig().decrypts() - before, 1, "one Touch ID per wrapper process (D1)");
    let argv = read(&h.root().join("argv.log"));
    let args: Vec<&str> = argv.lines().filter(|l| !l.starts_with("--- gen")).collect();
    for gone in ["--add-dir", "/Users/someone/elsewhere", "--debug", "--debug-to-stderr", "--session-mirror"] {
        assert!(!args.contains(&gone), "{gone}: {argv}");
    }
    let note = h.end_note();
    for part in ["vm:", "vm_how:started", "legs:touchid=", ",select=", ",workspace=", ",gate=", ",spawn=", "credential:combined", "seed:seeded"] {
        assert!(note.contains(part), "{part}: {note}");
    }
    assert!(!h.err_text().lines().any(|l| l.starts_with("ai-env:")), "no ai-env: line: {}", h.err_text());
    assert_eq!(h.audit_events("session_remote_start").len(), 1);
    let select = h.audit_events("vm_select");
    assert_eq!(select.len(), 1, "{select:?}");
    assert_eq!((select[0]["detail"]["how"].as_str(), select[0]["detail"]["choice"].as_str()), (Some("started"), Some("workspace")), "{select:?}");
    assert!(h.audit_events("vm_run").iter().all(|r| r["detail"]["purpose"] == "session"), "the S4 rows carry the session's purpose");
}

/// Plan §2, D1 and L8: a `--resume` whose transcript the VM lacks
/// (`AI_ENV_BRIDGE_LAB_TRANSCRIPT=skip` keeps generation 1 from restoring
/// it) misses; the retry restores it (S9: a chat begun on the Mac goes up
/// to S3, then into the VM: `transcript:staged`) and respawns on the same
/// VM with no second Touch ID, the token from the VM's cache, and the
/// conversation goes on under that id.
#[test]
fn a_resume_miss_retries_on_the_same_vm_with_its_transcript_and_no_second_touch_id() {
    let mut p = Harness::prepare();
    let sid = common::uuid(0x8806);
    let earlier = format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, common::uuid(0x8807));
    p.plant_transcript(&sid, &[earlier.as_str()]);
    let before = p.rig().decrypts();
    let resume = format!("--resume={sid}");
    let knobs = [("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_RESUME_FAIL_AFTER_ACK", "1"), ("AI_ENV_BRIDGE_LAB_TRANSCRIPT", "skip")];
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &knobs);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    let u = h.send_user("after the miss");
    h.expect_out(|v| is_result_for(v, &u), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert_eq!(h.rig().decrypts() - before, 1, "no second Touch ID (D1)");
    let starts = h.audit_events("session_remote_start");
    assert_eq!(starts.iter().map(|r| r["detail"]["gen"].as_str().unwrap_or_default().to_string()).collect::<Vec<_>>(), ["1", "2"], "{starts:?}");
    assert_eq!(starts[0]["detail"]["id"], starts[1]["detail"]["id"], "the retry respawns on the same VM");
    assert!(h.rig().vm_projects().join(h.slug()).join(format!("{sid}.jsonl")).exists(), "the transcript is on the VM");
    let resumed: Vec<String> = read(&h.root().join("env.log")).lines().filter(|l| l.contains("resumed")).map(str::to_string).collect();
    assert_eq!(resumed, ["gen 1 resumed lines=missing", "gen 2 resumed lines=1"]);
    let note = h.end_note();
    for part in ["transcript:staged", "credential:cached"] {
        assert!(note.split("; ").any(|p| p == part), "{part}: {note}");
    }
}

/// A1: a resume miss's retry keeps the first start's account, as it asks
/// no Touch ID: `work` made the active account while the first CLI is up
/// (between its answer to `initialize` and its miss) changes nothing for
/// the retry, which takes the VM's copy of `default`'s token (both CLIs
/// read it on fd 3); no `session_account`, both starts `default`.
#[test]
fn a1_a_resume_miss_retry_keeps_the_first_starts_account() {
    let mut p = Harness::prepare();
    let default = p.rig().token().to_string();
    p.rig().seal_account("work", "Wk");
    let sid = common::uuid(0x8836);
    let earlier = format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, common::uuid(0x8837));
    p.plant_transcript(&sid, &[earlier.as_str()]);
    let before = p.rig().decrypts();
    let log = p.root.join("token.log").display().to_string();
    let resume = format!("--resume={sid}");
    let knobs = [("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_RESUME_FAIL_AFTER_ACK", "1"), ("FAKE_MISS_DELAY_MS", "1500"), ("AI_ENV_BRIDGE_LAB_TRANSCRIPT", "skip"), ("FAKE_TOKEN_LOG", log.as_str())];
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &knobs);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    let installed = ai_env_cli::bridge::accounts::install(&h.rig().paths(), "work").expect("work installed");
    assert_eq!(installed.from.as_deref(), Some("default"));
    let u = h.send_user("after the miss");
    h.expect_out(|v| is_result_for(v, &u), T);
    closed(&mut h);
    assert_eq!(h.rig().decrypts() - before, 1, "no second Touch ID (D1)");
    let sha8 = &sha256_hex(&default)[..8];
    let want: Vec<String> = (1..=2).map(|gen| format!("gen {gen} source=fd len={} sha8={sha8} fdvar=3 envvar=absent", default.len())).collect();
    assert_eq!(read(&h.root().join("token.log")).lines().map(str::to_string).collect::<Vec<_>>(), want, "both CLIs read default's token");
    let starts: Vec<(String, String)> = h.audit_events("session_remote_start").iter().map(|r| (r["detail"]["gen"].as_str().unwrap_or_default().to_string(), r["detail"]["account"].as_str().unwrap_or_default().to_string())).collect();
    assert_eq!(starts, [("1".to_string(), "default".to_string()), ("2".to_string(), "default".to_string())]);
    assert!(h.audit_events("session_account").is_empty(), "the retry keeps the first start's account");
}

/// D6: a workspace under the roots that is no git repository is refused at
/// P0 (exit 9, the plan's line last on stderr), before any Touch ID and any
/// AWS call: nothing leaves the Mac.
#[test]
fn a_workspace_that_is_no_git_repository_exits_9_before_any_touch_id() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let plain = rig.root().join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    let toml = rig.bridge().join("bridge.toml");
    let mut text = read(&toml);
    text.push_str(&format!("\n[[workspace]]\npath = {plain:?}\n"));
    std::fs::write(&toml, text).unwrap();
    let (before, calls) = (rig.decrypts(), rig.fake_calls().len());
    let (code, err) = remote_run(rig, Some(&plain), &[]);
    assert_eq!(code, Some(9), "{err}");
    assert_eq!(last_line(&err), "ai-env-claude: not a git repository: ai-env seeds git workspaces only; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally");
    assert_eq!((rig.decrypts(), rig.fake_calls().len()), (before, calls), "no Touch ID, no AWS call");
    let failed = audit_rows(rig, "session_remote_failed");
    assert_eq!(failed.len(), 1, "one row, the pump's: {failed:?}");
    assert_eq!((failed[0]["detail"]["step"].as_str(), failed[0]["detail"]["code"].as_str(), failed[0]["detail"]["why"].as_str()), (Some("precheck"), Some("9"), Some("not_git_repo")));
}

/// `AI_ENV_BRIDGE_VM` that is no MicroVM id: exit 2 before any Touch ID,
/// naming the variable.
#[test]
fn a_pin_that_is_not_a_vm_id_exits_2_before_any_touch_id() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let before = rig.decrypts();
    let (code, err) = remote_run(rig, None, &[("AI_ENV_BRIDGE_VM", "not a vm")]);
    assert_eq!(code, Some(2), "{err}");
    assert!(last_line(&err).starts_with("ai-env-claude: AI_ENV_BRIDGE_VM is not a MicroVM id"), "{err}");
    assert_eq!(rig.decrypts(), before);
}

/// `AI_ENV_BRIDGE_VM=<id>`: the session runs on that VM (`vm_how:pinned`),
/// and no other VM is started.
#[test]
fn the_vm_pin_selects_that_vm() {
    let mut p = Harness::prepare();
    let vm = p.rig().start_vm();
    let runs = |calls: &[ai_env_cli::bridge::api::Call]| calls.iter().filter(|c| matches!(c, ai_env_cli::bridge::api::Call::Run { .. })).count();
    let before = runs(&p.rig().fake_calls());
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("AI_ENV_BRIDGE_VM", vm.as_str())]);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    let note = h.end_note();
    assert!(note.contains(&format!("vm:{vm}")) && note.contains("vm_how:pinned"), "{note}");
    assert_eq!(runs(&h.rig().fake_calls()), before, "no other VM");
}

/// The Touch ID unanswered: the wrapper gives up before Cursor's window
/// closes, exit 5; its stderr is the countdown (`ai-env-claude:`) and one
/// final line naming `ai-env vm warm`, never an `ai-env:` line; the failure
/// is audited once, by the pipeline. Cursor keeps the wrapper's stdin open
/// meanwhile (a host EOF would cancel the pending start: exit 0).
#[test]
fn an_unanswered_touch_id_fails_fast_with_the_countdown_and_one_line() {
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_AGE_HANG", "1"), ("AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS", "2000")]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(5), "{}", h.transcript());
    let err = h.err_text();
    let lines: Vec<&str> = err.lines().collect();
    let (last, countdown) = lines.split_last().expect("a line");
    assert!(last.starts_with("ai-env-claude: no Touch ID within ") && last.ends_with("ai-env vm warm prepares the VM ahead"), "{err}");
    assert!(!countdown.is_empty() && countdown.iter().all(|l| l.starts_with("ai-env-claude: waiting for Touch ID")), "{err}");
    let failed = h.audit_events("session_remote_failed");
    assert_eq!(failed.len(), 1, "one row, the pipeline's: {failed:?}");
    assert_eq!((failed[0]["detail"]["step"].as_str(), failed[0]["detail"]["code"].as_str(), failed[0]["detail"]["why"].as_str()), (Some("touchid"), Some("5"), Some("touchid_timeout")));
}

/// L2: a closing session alone on its workspace suspends the VM (fired, not
/// waited for); while another holder of the workspace's `.active` lock lives
/// (another wrapper, a `vm warm`), the VM keeps running.
#[test]
fn close_suspends_the_vm_only_when_no_other_session_holds_the_workspace() {
    let suspends = |calls: &[ai_env_cli::bridge::api::Call]| calls.iter().filter(|c| matches!(c, ai_env_cli::bridge::api::Call::Suspend { .. })).count();
    let session = |p: common::Prepared| {
        let mut h = p.spawn_on(common::Link::Remote, "", &[], &[]);
        let init = h.send_initialize();
        h.expect_out(|v| is_response_to(v, &init), T);
        h.close_stdin();
        let (status, _) = h.wait(EXIT);
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
        h
    };
    // Another holder: the test holds the workspace's .active shared, as another wrapper does.
    let mut p = Harness::prepare();
    let slug = ai_env_cli::wire::slug::project_dir_name(&p.rig().work()).unwrap();
    let active = p.rig().bridge().join("state").join("workspaces").join(format!("{slug}.active"));
    std::fs::create_dir_all(active.parent().unwrap()).unwrap();
    let held = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&active).unwrap();
    use std::os::fd::AsRawFd as _;
    // SAFETY: flock(2) on a descriptor this test owns.
    assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_SH) }, 0);
    let h = session(p);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(suspends(&h.rig().fake_calls()), 0, "another session keeps the VM running");
    drop(held);
    // Alone: suspended.
    let h = session(Harness::prepare());
    let t = std::time::Instant::now();
    while suspends(&h.rig().fake_calls()) == 0 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(suspends(&h.rig().fake_calls()), 1, "the closing session suspended its VM");
}

// ---- S8 wave 2 (W10): the remote session's offline tests ----------------------------------
//
// plans/s8-design-tests.md §2.1 (T8.2 to T8.6, the offline column) and §2.5
// (the remote_pump list), adapted to D7 (packs and manifests) and L6
// (snapshots at a code-out and at `/suspend`, none at `/terminate`). Each runs
// the real wrapper in remote mode against the rig: what the VM's CLI sees (its
// environment, its config dir), the remote close, two wrappers on one VM (a
// probe beside a chat), SELECT_VM's filters, D1's Touch IDs and a token the VM
// holds, the gate before any unseal, the 401 watch, the records' secrets, the
// per-result fetch, the session's grace, a resume on the same VM and on a new
// one, the transcript's 409, a terminated VM, a cut endpoint, a symlinked
// component and an NFD workspace path. The S2 suites on this link are W5's
// (§2.2), `session drop-transport` W8's, Docker W6's.
//
// The rig answers `/health` from the fake API's state (the `EndpointClient`
// a fake-API backend gets) and `/health/detail` from the shim behind the
// endpoint (phase 4: `FakeState::health_detail_at`): a closing suspend's
// read of the VM's spawns and S7's `cached_on_vm` see the shim's, as the
// data plane and `/agent` do.

// ---- phase 4 F7: timing and resume ----
//
// S8 phase 4's review, packet F7: an unanswered Touch ID with the default
// budget (TIMING-2), a stalled retry the host waits on (TIMING-3, RESUME-4),
// a stop or an EOF while a closing session holds the workspace alone, or
// during P0 (TIMING-5), and a retried resume's legs and row (RESUME-2,
// RESUME-3). The two deadline tests take about 50 s each: the default
// budget and T0 + 50 s are what they prove.

/// The workspace's `.active` lock of `rig`, held alone by the test as a
/// closing session holds it around its suspend verdict (LOCK_EX).
fn hold_active_alone(rig: &common::remote::RemoteRig) -> std::fs::File {
    use std::os::fd::AsRawFd as _;
    let slug = ai_env_cli::wire::slug::project_dir_name(&rig.work()).expect("the workspace's slug");
    let active = rig.bridge().join("state").join("workspaces").join(format!("{slug}.active"));
    std::fs::create_dir_all(active.parent().expect("the workspaces dir")).expect("mkdir the workspaces dir");
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&active).expect("open .active");
    // SAFETY: flock(2) on a descriptor this test owns.
    assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0, "the test holds .active alone");
    file
}

/// Until the census holds the start row of wrapper `h`.
fn wait_for_start_row(h: &mut Harness) {
    let pid = u64::from(h.pid());
    h.wait_until("the census start row", T, |h| h.census().iter().any(|r| r["pid"].as_u64() == Some(pid)));
}

/// The fake age's calls on `rig` so far (its `age.log`: each call's name and
/// argv; P1's `age --version` probe first).
fn age_calls(rig: &common::remote::RemoteRig) -> Vec<String> {
    std::fs::read_to_string(rig.root().join("age.log")).unwrap_or_default().lines().map(str::to_string).collect()
}

/// TIMING-2: an unanswered Touch ID with the default budget
/// (`[creds].unseal_timeout_s` 60 s, so Cursor's window sets it) ends as
/// the dialog's own deadline before the pipeline's T0 + 50 s: exit 5 with
/// the README's line `no Touch ID within N s (Cursor's 60 s window)`,
/// audited `touchid_timeout` at the Touch ID, the unseal's row `exit 5`
/// (it ran out, it was not dropped), all within T0 + 50 s.
#[test]
fn an_unanswered_touch_id_with_the_default_budget_is_its_own_timeout_within_the_window() {
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_AGE_HANG", "1")]);
    h.send_initialize();
    let (status, _) = h.wait(Duration::from_secs(120));
    assert_eq!(status.code(), Some(5), "{}", h.transcript());
    let err = h.err_text();
    let secs: u64 = last_line(&err)
        .strip_prefix("ai-env-claude: no Touch ID within ")
        .and_then(|rest| rest.strip_suffix(" s (Cursor's 60 s window): nothing was started; ai-env vm warm prepares the VM ahead"))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("the README's line last: {err}"));
    assert!((40..=49).contains(&secs), "the dialog's room in Cursor's window: {secs} s");
    let failed = h.audit_events("session_remote_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!((failed[0]["detail"]["step"].as_str(), failed[0]["detail"]["code"].as_str(), failed[0]["detail"]["why"].as_str()), (Some("touchid"), Some("5"), Some("touchid_timeout")));
    let unseals = h.audit_events("credential_unseal");
    assert!(!unseals.is_empty() && unseals.iter().all(|r| r["detail"]["outcome"] == "exit 5"), "{unseals:?}");
    let end = h.end_row();
    let took = end["end"].as_u64().unwrap_or(u64::MAX).saturating_sub(end["start"].as_u64().unwrap_or(0));
    assert!(took < 50_000, "the wrapper's own line within T0 + 50 s: {took} ms");
}

/// TIMING-3, RESUME-4 (plan §3 item 6): a resume miss's retry the host still
/// waits on (the miss before the CLI answered `initialize`, the bundled
/// CLI's way: L8's knob kept the transcript off the VM) keeps Cursor's
/// window from T0. Stalled (the endpoint holds the retry's app-port
/// requests: its transcript's stat), it gives up at T0 + 50 s with the
/// deadline's line naming the step, exit 7, never past Cursor's 60 s.
#[test]
fn a_stalled_retry_the_host_waits_on_gives_up_at_the_init_deadline() {
    use ai_env_cli::wire::workspace::APP_PORT;
    use common::fake_endpoint::Action;
    let p = Harness::prepare();
    let sid = common::uuid(0x8850);
    let earlier = format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, common::uuid(0x8851));
    p.plant_transcript(&sid, &[earlier.as_str()]);
    let resume = format!("--resume={sid}");
    let knobs = [("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_MISS_EXIT_DELAY_MS", "2000"), ("AI_ENV_BRIDGE_LAB_TRANSCRIPT", "skip")];
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &knobs);
    h.send_initialize();
    // Generation 1 missed; its exit is 2 s away, and with it the retry: every new app-port connection is held from now.
    h.wait_until("generation 1's miss", T, |h| h.env_log().iter().any(|l| l == "gen 1 resumed lines=missing"));
    h.rig().endpoint.script_port(APP_PORT, vec![Action::Held; 4]);
    let (status, _) = h.wait(Duration::from_secs(120));
    h.rig().endpoint.release();
    assert_eq!(status.code(), Some(7), "{}", h.transcript());
    let err = h.err_text();
    assert_eq!(last_line(&err), "ai-env-claude: did not start within Cursor's 60 s window (stuck at workspace): ai-env vm warm prepares the VM ahead", "{err}");
    assert!(!h.out_lines().iter().any(|l| l.contains("control_response")), "the host's initialize was never answered");
    let failed = h.audit_events("session_remote_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(["gen", "step", "code"].map(|k| failed[0]["detail"][k].as_str().unwrap_or_default().to_string()), ["2", "deadline", "7"], "{failed:?}");
    let end = h.end_row();
    let took = end["end"].as_u64().unwrap_or(u64::MAX).saturating_sub(end["start"].as_u64().unwrap_or(0));
    assert!(took < 51_000, "the retry gave up at T0 + 50 s, inside Cursor's window: {took} ms");
    assert!(common::note_has(end["note"].as_str().unwrap_or_default(), "step:deadline"), "{end}");
}

/// TIMING-5: P0 never waits for the workspace's `.active` lock (it runs
/// before the pump reads the host or listens for a stop). While a closing
/// session holds it alone, generation 1's pending start waits for it, where
/// a stop reaches the wait: a SIGTERM or a SIGHUP is a cancelled start (exit
/// 143, the stopped line last, one census end row), never the default
/// action's death with no record. A second after the census start row is
/// inside P0's old wait (2 s from its try), and before any Touch ID.
#[test]
fn a_stop_while_a_closing_session_holds_the_workspace_is_a_cancelled_start() {
    for sig in [libc::SIGTERM, libc::SIGHUP] {
        let mut p = Harness::prepare();
        let closing = hold_active_alone(p.rig());
        let before = p.rig().decrypts();
        let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_AGE_HANG", "1")]);
        h.send_initialize();
        wait_for_start_row(&mut h);
        std::thread::sleep(Duration::from_secs(1));
        // SAFETY: kill(2) on the pid of our own not-yet-reaped child.
        assert_eq!(unsafe { libc::kill(i32::try_from(h.pid()).expect("a pid"), sig) }, 0);
        let (status, _) = h.wait(EXIT);
        drop(closing);
        assert_eq!(status.code(), Some(143), "signal {sig}: {}", h.transcript());
        let err = h.err_text();
        assert_eq!(last_line(&err), "ai-env-claude: stopped before the session started: nothing was started; reopen the chat to start it", "{err}");
        assert!(!err.contains("waiting for Touch ID") && h.rig().decrypts() == before, "no dialog before the workspace's .active: {err}");
        assert!(common::note_has(&h.end_note(), "end:sigterm"), "{}", h.end_note());
    }
}

/// TIMING-5: the host's EOF while a closing session holds the workspace
/// alone cancels the pending start at once: exit 0 within the close's
/// budget from the EOF, before any Touch ID (no countdown, no decrypt).
#[test]
fn an_eof_while_a_closing_session_holds_the_workspace_closes_within_budget() {
    use ai_env_cli::bridge::remote::CLOSE_BUDGET_MS;
    let _alone = common::remote::alone();
    let mut p = Harness::prepare();
    let closing = hold_active_alone(p.rig());
    let before = p.rig().decrypts();
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_AGE_HANG", "1")]);
    h.send_initialize();
    wait_for_start_row(&mut h);
    std::thread::sleep(Duration::from_millis(200));
    h.close_stdin();
    let (status, took) = h.wait(EXIT);
    drop(closing);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "the host's EOF to the exit: {took:?}\n{}", h.transcript());
    let err = h.err_text();
    assert!(!err.contains("waiting for Touch ID") && h.rig().decrypts() == before, "no dialog after the host closed: {err}");
    assert!(common::note_has(&h.end_note(), "end:eof"), "{}", h.end_note());
}

/// TIMING-5: the stop handlers come before P0, so a SIGTERM during P0's own
/// work (here every Mac git of `workspace::resolve` slowed down, the signal
/// sent once the first was logged) is a cancelled start once P0 is done:
/// exit 143, the stopped line, the census end row. P0 itself is not cut
/// short (no AWS call, no Touch ID: about 0.2 s as built), and the signal is
/// the supervisor's first wake: generation 1's start never runs (no
/// countdown, not even P1's `age --version`).
#[test]
fn a_sigterm_during_p0_is_a_cancelled_start() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let knobs = rig.root().join("bin").join("git.knobs");
    let mut text = read(&knobs);
    text.push_str("sleep 0.3\n");
    std::fs::write(&knobs, text).expect("slow the Mac's fake git");
    let calls = rig.mac_git_calls().len();
    let ages = age_calls(rig);
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_AGE_HANG", "1")]);
    h.send_initialize();
    h.wait_until("P0's first git", T, |h| h.rig().mac_git_calls().len() > calls);
    h.sigterm();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(143), "{}", h.transcript());
    let err = h.err_text();
    assert_eq!(last_line(&err), "ai-env-claude: stopped before the session started: nothing was started; reopen the chat to start it");
    assert!(common::note_has(&h.end_note(), "end:sigterm"), "{}", h.end_note());
    assert!(!err.contains("waiting for Touch ID"), "no countdown: {err}");
    assert_eq!(age_calls(h.rig()), ages, "no age call: generation 1's start never ran");
}

/// TIMING-5: a SIGTERM as soon as the census start row is there is a
/// cancelled start as well, never the default action's death with a start
/// row and no end row (the pump writes a remote session's row once its stop
/// handlers listen): exit 143, the stopped line last, `end:sigterm`, and no
/// countdown or age call. In rounds: the signal lands anywhere from the
/// pump's child plan through P0.
#[test]
fn a_sigterm_at_the_census_start_row_is_a_cancelled_start() {
    for round in 0..8 {
        let mut p = Harness::prepare();
        let ages = age_calls(p.rig());
        let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_AGE_HANG", "1")]);
        wait_for_start_row(&mut h);
        h.sigterm();
        let (status, _) = h.wait(EXIT);
        assert_eq!(status.code(), Some(143), "round {round}: {status:?}\n{}", h.transcript());
        let err = h.err_text();
        assert_eq!(last_line(&err), "ai-env-claude: stopped before the session started: nothing was started; reopen the chat to start it", "round {round}");
        assert!(common::note_has(&h.end_note(), "end:sigterm"), "round {round}: {}", h.end_note());
        assert!(!err.contains("waiting for Touch ID"), "round {round}: no countdown: {err}");
        assert_eq!(age_calls(h.rig()), ages, "round {round}: no age call");
    }
}

/// RESUME-2, RESUME-3: a resume miss before the CLI answered `initialize`
/// (L8's knob kept the transcript off the VM) and its retry, end to end.
/// The census's legs lead to `init_ms`, the retry's answer: the one Touch
/// ID first, then both generations' steps added up, in order. The row's
/// history ends each generation.
#[test]
fn a_retried_resume_records_both_generations_legs_and_ends() {
    use ai_env_cli::bridge::remote::LEG_NAMES;
    let mut p = Harness::prepare();
    let sid = common::uuid(0x8852);
    let earlier = format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, common::uuid(0x8853));
    p.plant_transcript(&sid, &[earlier.as_str()]);
    let before = p.rig().decrypts();
    let resume = format!("--resume={sid}");
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1"), ("AI_ENV_BRIDGE_LAB_TRANSCRIPT", "skip")]);
    started(&mut h);
    turn(&mut h, "after the miss");
    closed(&mut h);
    assert_eq!(h.rig().decrypts() - before, 1, "one Touch ID (D1)");
    let resumed: Vec<String> = h.env_log().into_iter().filter(|l| l.contains("resumed")).collect();
    assert_eq!(resumed, ["gen 1 resumed lines=missing", "gen 2 resumed lines=1"]);
    let note = h.end_note();
    assert_eq!(part_of(&note, "respawns").as_deref(), Some("1"), "{note}");
    let legs: Vec<String> = part_of(&note, "legs").unwrap_or_default().split(',').map(|l| l.split('=').next().unwrap_or_default().to_string()).collect();
    assert_eq!(legs, LEG_NAMES, "the Touch ID and both generations' steps: {note}");
    let rows = h.registry_rows();
    let row = rows.iter().find(|r| r.get("session_id").and_then(toml::Value::as_str) == Some(sid.as_str())).unwrap_or_else(|| panic!("no row of {sid}: {rows:?}"));
    let vms = row.get("vms").and_then(toml::Value::as_array).cloned().unwrap_or_default();
    let ended: Vec<(Option<i64>, bool)> = vms.iter().map(|v| (v.get("gen").and_then(toml::Value::as_integer), v.get("to").is_some())).collect();
    assert_eq!(ended, [(Some(1), true), (Some(2), true)], "{vms:?}");
}

// ---- S8 wave 2 (W10), continued ----

/// The census end row of the wrapper `pid` (every wrapper on a rig writes
/// the rig's census): its note.
fn end_note_of(h: &Harness, pid: u32) -> String {
    let rows = h.census();
    let ends: Vec<&Value> = rows.iter().filter(|r| r.get("end").is_some() && r["pid"].as_u64() == Some(u64::from(pid))).collect();
    assert_eq!(ends.len(), 1, "one end row of wrapper {pid}: {rows:#?}");
    ends[0]["note"].as_str().unwrap_or_default().to_string()
}

/// The value of `name` in a census note (`name:value`).
fn part_of(note: &str, name: &str) -> Option<String> {
    note.split("; ").find_map(|p| p.strip_prefix(name)?.strip_prefix(':')).map(str::to_string)
}

/// How many RunMicrovm the fake API took.
fn runs(rig: &common::remote::RemoteRig) -> usize {
    rig.fake_calls().iter().filter(|c| matches!(c, ai_env_cli::bridge::api::Call::Run { .. })).count()
}

/// How many SuspendMicrovm the fake API took.
fn suspends(rig: &common::remote::RemoteRig) -> usize {
    rig.fake_calls().iter().filter(|c| matches!(c, ai_env_cli::bridge::api::Call::Suspend(_))).count()
}

/// `text` appended to the rig's bridge.toml.
fn add_config(rig: &common::remote::RemoteRig, text: &str) {
    let path = rig.bridge().join("bridge.toml");
    let mut toml = read(&path);
    toml.push_str(&format!("\n{text}"));
    std::fs::write(&path, toml).expect("write bridge.toml");
}

/// The session's start: `initialize` answered, then the init frame, which it gives.
fn started(h: &mut Harness) -> Value {
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    h.expect_out(is_init, T)
}

/// One turn, to its result.
fn turn(h: &mut Harness, text: &str) {
    let u = h.send_user(text);
    h.expect_out(|v| is_result_for(v, &u), T);
}

/// The host's EOF, then the exit, which must be 0: the time from the EOF.
fn closed(h: &mut Harness) -> Duration {
    h.close_stdin();
    let (status, took) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    took
}

/// S9: until `views` of session `sid`'s transcript steps wrote its view
/// (`transcript_view`, `written`): after each turn's code-out the trigger
/// syncs the transcript to S3, then rewrites the view on the Mac.
fn synced(h: &mut Harness, sid: &str, views: usize) {
    h.wait_until("the turn's transcript synced to S3 and its view written", T, |h| {
        h.audit_events("transcript_view").iter().filter(|r| r["detail"]["session"] == sid && r["detail"]["outcome"] == "written").count() >= views
    });
}

/// S9: what the tests' S3 holds of session `sid`, its manifest's parts in
/// order (the rig's bridge): the transcript the Mac committed.
fn held_in_s3(rig: &common::remote::RemoteRig, sid: &str) -> Vec<u8> {
    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None);
    let m = ai_env_cli::bridge::s3::manifest::read(&paths, sid).unwrap().unwrap_or_else(|| panic!("no manifest of {sid}"));
    m.parts.iter().flat_map(|p| rig.s3().get(&p.key).unwrap_or_else(|| panic!("{} not in S3", p.key))).collect()
}

/// S9: whether `path` is a chat's view (its first bytes the view's mark).
fn is_view(path: &Path) -> bool {
    ai_env_cli::wire::view::is_view_head(&std::fs::read(path).unwrap_or_default())
}

/// Every file under `dir` (recursively, links not followed), relative to it, sorted.
fn files_under(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.filter_map(Result::ok) {
            let path = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => walk(base, &path, out),
                Ok(_) => out.push(path.strip_prefix(base).unwrap_or(&path).display().to_string()),
                Err(_) => {}
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// The entry names of `dir`, sorted.
fn names_in(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    out.sort();
    out
}

/// The files under `dirs` whose bytes hold one of `needles`, each named with the needle's index.
fn holding(dirs: &[&Path], needles: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for dir in dirs {
        for rel in files_under(dir) {
            let bytes = std::fs::read(dir.join(&rel)).unwrap_or_default();
            for (i, needle) in needles.iter().enumerate() {
                if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                    out.push(format!("{} (needle {i})", dir.join(&rel).display()));
                }
            }
        }
    }
    out
}

/// L4 in the VM: what the VM's CLI was started with, as its fake dumps it
/// (`FAKE_ENV_DUMP`). The shim's own (`HOME`, `PATH`, `CLAUDE_CONFIG_DIR`,
/// `DISABLE_AUTOUPDATER`, which the wrapper names too: its half is the lib's
/// `remote::env` test), a vpc row's six proxy variables at the proxy's
/// address (Cursor's own proxy setting never in their place), the wrapper's
/// names over Cursor's values (telemetry and error reports off: Cursor's
/// `DISABLE_TELEMETRY=0`, forwarded by `env_extra`, arrives as 1), the
/// `[wrapper].env_forward` names Cursor set and an `env_extra` one, and the
/// descriptor the token rides on (`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`):
/// nothing else. No `AWS_*` name, no other TOKEN, KEY, SECRET or PASSWORD
/// name and no secret value of Cursor's environment reaches the VM.
#[test]
fn the_vm_env_is_the_allowlist_plus_the_wrapper_names() {
    use ai_env_cli::bridge::egress::{proxy_url, PROXY_IP, PROXY_PORT};
    use std::collections::BTreeMap;
    let mut p = Harness::prepare();
    add_config(p.rig(), "[wrapper]\nenv_extra = [\"MY_FLAG\", \"DISABLE_TELEMETRY\"]\n");
    let dump = p.rig().vm_env_log().display().to_string();
    // Cursor's secrets, built at run time.
    let shaped = |tag: &str| format!("{}-{}-{tag}{}", "sk", "ant", "Zq9".repeat(12));
    let secrets = [format!("{}{}", "AKIA", "W".repeat(16)), shaped("oauth"), shaped("gh"), shaped("api"), shaped("pw"), shaped("app")];
    let cursor = [
        ("CLAUDE_CODE_ENTRYPOINT", "claude-vscode"),
        ("CLAUDE_AGENT_SDK_VERSION", "0.2.0"),
        ("CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING", "true"),
        ("MCP_CONNECTION_NONBLOCKING", "true"),
        ("CLAUDE_CODE_ENABLE_TASKS", "true"),
        ("LANG", "en_US.UTF-8"),
        ("TERM", "xterm-256color"),
        ("MY_FLAG", "on"),
        ("DISABLE_TELEMETRY", "0"),
        ("HTTPS_PROXY", "http://proxy.cursor.invalid:8080"),
        ("AWS_SECRET_ACCESS_KEY", secrets[0].as_str()),
        ("CLAUDE_CODE_OAUTH_TOKEN", secrets[1].as_str()),
        ("GITHUB_TOKEN", secrets[2].as_str()),
        ("OPENAI_API_KEY", secrets[3].as_str()),
        ("DB_PASSWORD", secrets[4].as_str()),
        ("APP_SECRET", secrets[5].as_str()),
    ];
    let mut envs = vec![("FAKE_ENV_DUMP", dump.as_str())];
    envs.extend_from_slice(&cursor);
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &envs);
    started(&mut h);
    closed(&mut h);
    let rig = h.rig();
    let dumps = rig.vm_env_dumps();
    assert_eq!(dumps.len(), 1, "one spawn: {dumps:?}");
    let mut env = dumps[0].clone();
    let path = env.remove("PATH").expect("the shim's PATH");
    assert!(!path.contains(&rig.root().display().to_string()), "the shim's own PATH, never the wrapper's: {path}");
    let (proxy, local) = (proxy_url(PROXY_IP, PROXY_PORT), "localhost,127.0.0.1,::1");
    let (home, config) = (rig.vm_home().display().to_string(), rig.vm_home().join(".claude").display().to_string());
    let mut want: BTreeMap<String, String> = [
        // The shim's own.
        ("HOME", home.as_str()),
        ("CLAUDE_CONFIG_DIR", config.as_str()),
        ("DISABLE_AUTOUPDATER", "1"),
        // A vpc row's proxy variables (the spawn's first; no session name replaces one).
        ("https_proxy", proxy.as_str()),
        ("HTTPS_PROXY", proxy.as_str()),
        ("http_proxy", proxy.as_str()),
        ("HTTP_PROXY", proxy.as_str()),
        ("no_proxy", local),
        ("NO_PROXY", local),
        // The wrapper's names (L4), over Cursor's values (its DISABLE_TELEMETRY forwarded, then set over).
        ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"),
        ("CLAUDE_CODE_DISABLE_ARTIFACT", "1"),
        ("DISABLE_TELEMETRY", "1"),
        ("DISABLE_ERROR_REPORTING", "1"),
        ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
        // Where the token is (fd 3); the token itself is in no variable.
        ("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "3"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
    .collect();
    // The env_forward names Cursor set, and env_extra's MY_FLAG (its DISABLE_TELEMETRY is the wrapper's, above).
    want.extend(cursor[..8].iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())));
    assert_eq!(env, want, "the VM's environment");
    for (name, value) in &dumps[0] {
        assert!(!name.starts_with("AWS_"), "{name} reached the VM");
        let credential_named = ["TOKEN", "KEY", "SECRET", "PASSWORD"].iter().any(|w| name.contains(w));
        assert!(!credential_named || (name == "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR" && value == "3"), "{name} reached the VM");
        assert!(!secrets.iter().any(|s| value.contains(s.as_str())), "a secret of Cursor's environment reached the VM as {name}");
    }
}

/// Invariant 11 on the remote link: the VM's CLI runs with the VM's own
/// config dir (its `CLAUDE_CONFIG_DIR` the agent's `~/.claude` in the VM, no
/// keychain pointer), and what it writes there (its settings, its transcript)
/// stays there. The Mac keeps no config dir for the session (no scratch dir,
/// as `local-scratch` makes one): its `~/.claude` holds the chat's view
/// alone (S9: the transcript is kept in S3), under the workspace's slug, and
/// the registry names the VM's config dir by its VM path (Design A).
#[test]
fn remote_child_runs_with_the_vm_config_dir_and_the_mac_keeps_none() {
    let settings = r#"{"permissions":{"allow":["Bash(ls:*)"]}}"#;
    let user = format!("user:{settings}");
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_WRITE_SETTINGS", user.as_str())]);
    started(&mut h);
    turn(&mut h, "hello");
    synced(&mut h, &common::fake_fixed_sid(), 1);
    closed(&mut h);
    let vm_config = h.rig().vm_home().join(".claude");
    let line = h.env_log().into_iter().next().expect("the VM's CLI logged its environment");
    assert_eq!((env_log_field(&line, "CLAUDE_CONFIG_DIR"), env_log_field(&line, "SECURESTORAGE")), (vm_config.to_str(), Some("absent")), "{line}");
    assert_eq!(read(&vm_config.join("settings.json")), format!("{settings}\n"), "what the CLI writes in its config dir stays in the VM");
    let transcript = format!("projects/{}/{}.jsonl", h.slug(), common::fake_fixed_sid());
    assert!(vm_config.join(&transcript).is_file(), "the CLI's transcript, in the VM");
    let mac_config = h.root().join(".claude");
    assert_eq!(files_under(&mac_config), std::slice::from_ref(&transcript), "the Mac's ~/.claude holds the chat's view alone");
    assert!(is_view(&mac_config.join(&transcript)), "the view, never the transcript");
    assert!(h.scratch_names().is_empty(), "no scratch config dir on the Mac: {:?}", h.scratch_names());
    let rows = h.registry_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!((rows[0].get("child_config_dir").and_then(toml::Value::as_str), rows[0].get("scratch_dir")), (mac_config.to_str(), None), "{rows:?}");
}

/// L2's remote close against a CLI that never exits on its own: the host's
/// EOF reaches the CLI's stdin at once, nothing comes back, and at +1.2 s the
/// wrapper sends `detach{final}`: it exits 0 within `CLOSE_BUDGET_MS` (v6
/// §2.8), and the shim's ladder ends the CLI (TERM, and KILL for one that
/// ignores TERM): no child is left on the VM. Measured with the binary's
/// wall-clock lane alone (no other remote session beside it).
#[test]
fn eof_closes_within_1500ms_and_leaves_no_child_on_the_vm() {
    use ai_env_cli::bridge::remote::CLOSE_BUDGET_MS;
    let _alone = common::remote::alone();
    for (what, knobs) in [("ignoring EOF", &[("FAKE_IGNORE_EOF", "1")][..]), ("ignoring EOF and TERM", &[("FAKE_IGNORE_EOF", "1"), ("FAKE_IGNORE_TERM", "1")][..])] {
        let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], knobs);
        started(&mut h);
        let vm_pid = h.fake_pid(1).unwrap_or_else(|| panic!("{what}: the VM's CLI logged no pid"));
        let took = closed(&mut h);
        assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "{what}: the host's EOF to the exit took {took:?}\n{}", h.transcript());
        let note = h.end_note();
        assert!(common::note_has(&note, "end:eof_kill"), "{what}: the wrapper's detach ended it: {note}");
        wait_for(&format!("{what}: no child left on the VM"), Duration::from_secs(10), || h.rig().shim.spawns.detail().is_empty() && !common::pid_alive(vm_pid));
    }
}

/// L2 with D5's config probe: the probe (a wrapper that initialised and
/// stays open, its CLI saying no init: 2.1.x sends one per turn, and a probe
/// has none) and the chat (one turn) run on the workspace's one VM. The chat
/// closes first: the probe's CLI lives on the VM (and the probe holds the
/// workspace's `.active` lock), so the chat's closing suspend fires nothing,
/// the log saying why: its first look, the VM's spawns (the shim's own
/// `/health/detail`), finds the probe's. The VM keeps running for the
/// probe, which adopted no session id and captured nothing. Once the probe
/// closes alone, its own closing suspend fires: one SuspendMicrovm.
#[test]
fn close_keeps_the_vm_running_while_the_config_probe_lives() {
    let mut probe = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_INIT_AT_TURN", "1")]);
    let init = probe.send_initialize();
    // Answered by the probe's CLI, which read its knobs at its start: the chat's below are its own.
    probe.expect_out(|v| is_response_to(v, &init), T);
    let mut chat = Harness::prepare().launch_wrapper(probe.rig().wrapper(&[], &[]));
    started(&mut chat);
    turn(&mut chat, "hello");
    closed(&mut chat);
    let vm = part_of(&end_note_of(&probe, chat.pid()), "vm").expect("the chat's VM");
    let kept = format!("closing: no suspend of {vm} (a spawn still lives on the VM)");
    wait_for("the chat's close kept the VM", T, || probe.wrapper_log().contains(&kept));
    assert_eq!(suspends(probe.rig()), 0, "no SuspendMicrovm while the probe lives");
    // The chat's CLI gone from the VM, the probe's alone there.
    wait_for("the chat's spawn gone from the shim", Duration::from_secs(10), || probe.rig().shim.spawns.detail().len() == 1);
    closed(&mut probe);
    assert_eq!(part_of(&end_note_of(&probe, probe.pid()), "vm").as_deref(), Some(vm.as_str()), "one VM for the probe and the chat");
    assert!(probe.out_matching(is_init).is_empty(), "the probe's CLI said no init");
    assert_eq!(probe.registry_rows().len(), 1, "the chat's row alone: the probe adopted no session");
    wait_for("the probe's closing suspend", Duration::from_secs(10), || suspends(probe.rig()) == 1);
}

/// Q9 (plan §11): a CLI whose own exit comes a second after the host's EOF,
/// its last mirror frame just before it (2.1.296 takes 0.5 to 1.1 s, S7
/// B11), ends the session itself before the remote ladder's `detach{final}`
/// at +1.2 s: exit 0 within 1.5 s, the end the CLI's own, its last frame
/// read to the end, dropped and counted (S9: the transcript is kept in S3:
/// nothing of it on the Mac, the line it carried on the VM's disk). Measured
/// with the binary's wall-clock lane alone.
#[test]
fn a_child_exiting_1s_after_eof_ends_the_session_itself() {
    use ai_env_cli::bridge::remote::{CLOSE_BUDGET_MS, REMOTE_EOF_DETACH_AFTER_MS};
    let _alone = common::remote::alone();
    let knobs = [("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_FINAL_MIRROR_MS", "850"), ("FAKE_EXIT_DELAY_MS", "1000")];
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &knobs);
    started(&mut h);
    turn(&mut h, "hello");
    let file = format!("{}.jsonl", common::fake_fixed_sid());
    let vm = h.rig().vm_projects().join(h.slug()).join(&file);
    let took = closed(&mut h);
    assert!(took >= Duration::from_millis(1000) && took < Duration::from_millis(CLOSE_BUDGET_MS), "the CLI's own exit, a second after the EOF, within the budget: {took:?}");
    assert!(read(&vm).lines().last().is_some_and(|l| l.contains(r#""type":"summary""#)), "the last entry, 850 ms after the EOF, on the VM's disk: {}", read(&vm));
    let mac = h.prepared.mac_projects();
    assert!(files_under(&mac).iter().all(|rel| is_view(&mac.join(rel))), "nothing but a view on the Mac: {:?}", files_under(&mac));
    let note = h.end_note();
    assert!(common::note_has(&note, "end:eof") && common::note_has(&note, "mirror:0/0") && common::note_has(&note, "mirror_dropped:1"), "the CLI's own exit, before the detach at {REMOTE_EOF_DETACH_AFTER_MS} ms, its last frame counted: {note}");
}

/// D5 and S4's workspace lock: Cursor's reload starts the config probe and
/// the chat at once, two wrappers on one workspace. SELECT_VM runs under
/// the workspace's lock, so one RunMicrovm starts the VM and the other
/// session finds it there (`vm_how` started and reused, the seed once); each
/// process costs its own Touch ID (D1). Their CLIs say init as 2.1.x does,
/// with a turn: the probe, which has none, says none.
#[test]
fn probe_and_chat_share_one_vm_under_the_workspace_lock() {
    let mut p = Harness::prepare();
    // Both commands are built first (the rig has one knobs file): both CLIs say init per turn.
    let (probe_cmd, chat_cmd, touch) = {
        let rig = p.rig();
        let at_turn = [("FAKE_INIT_AT_TURN", "1")];
        (rig.wrapper(&[], &at_turn), rig.wrapper(&[], &at_turn), rig.decrypts())
    };
    let mut probe = p.launch_wrapper(probe_cmd);
    let mut chat = Harness::prepare().launch_wrapper(chat_cmd);
    let (pi, ci) = (probe.send_initialize(), chat.send_initialize());
    probe.expect_out(|v| is_response_to(v, &pi), T);
    chat.expect_out(|v| is_response_to(v, &ci), T);
    turn(&mut chat, "hello");
    assert_eq!(chat.out_matching(is_init).len(), 1, "the chat's init came with its turn");
    closed(&mut chat);
    closed(&mut probe);
    assert!(probe.out_matching(is_init).is_empty(), "the probe's CLI said no init");
    let notes = [end_note_of(&probe, probe.pid()), end_note_of(&probe, chat.pid())];
    let vms: Vec<Option<String>> = notes.iter().map(|n| part_of(n, "vm")).collect();
    assert!(vms[0].is_some() && vms[0] == vms[1], "one VM: {notes:?}");
    let mut how: Vec<String> = notes.iter().filter_map(|n| part_of(n, "vm_how")).collect();
    how.sort();
    assert_eq!(how, ["reused", "started"], "{notes:?}");
    let mut seeds: Vec<String> = notes.iter().filter_map(|n| part_of(n, "seed")).collect();
    seeds.sort();
    assert_eq!(seeds, ["seeded", "up_to_date"], "{notes:?}");
    let rig = probe.rig();
    assert_eq!(runs(rig), 1, "one RunMicrovm: {:?}", rig.fake_calls());
    assert_eq!(rig.decrypts() - touch, 2, "a Touch ID per wrapper process (D1)");
}

/// `[vm].max_concurrent` (3 by default) at P2: three VMs run already (none
/// the workspace's), so the session's would be a fourth. Once the Touch ID
/// answered, the wrapper exits 9 with one line naming `vm list` and `vm
/// terminate ID` (`vm gc --yes` keeps every live VM, a suspended one too);
/// no RunMicrovm, the failure audited at `select`. The line followed frees
/// the slot: one VM terminated, the reopened chat starts its own.
#[test]
fn a_fourth_workspace_vm_is_refused_with_exit_9() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let mut ids = Vec::new();
    for n in 1..=3 {
        let o = rig.run(&["vm", "run", "--egress", "vpc", "--json"], None);
        assert!(o.status.success(), "vm run {n}: {}", String::from_utf8_lossy(&o.stderr));
        let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("vm run --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
        ids.push(v["id"].as_str().expect("the VM's id").to_string());
    }
    let before = runs(rig);
    assert_eq!(before, 3);
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(9), "{}", h.transcript());
    let err = h.err_text();
    assert_eq!(last_line(&err), "ai-env-claude: 3 VMs already run ([vm].max_concurrent, suspended ones included): ai-env vm list names them; ai-env vm terminate ID frees a slot, then reopen the chat", "{err}");
    assert_eq!(runs(h.rig()), before, "no fourth RunMicrovm");
    let failed = h.audit_events("session_remote_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!((failed[0]["detail"]["step"].as_str(), failed[0]["detail"]["code"].as_str(), failed[0]["detail"]["why"].as_str()), (Some("select"), Some("9"), Some("max_concurrent")), "{failed:?}");
    let rig = h.rig();
    let o = rig.run(&["vm", "terminate", &ids[0]], None);
    assert!(o.status.success(), "vm terminate: {}", String::from_utf8_lossy(&o.stderr));
    let mut again = Harness::prepare().launch_wrapper(rig.wrapper(&[], &[]));
    started(&mut again);
    closed(&mut again);
    assert_eq!(runs(rig), before + 1, "the freed slot took the reopened chat's VM");
}

/// SELECT_VM never takes a `--shell` VM for a session (plan §1: the
/// wrapper's plan asks for none): the workspace's running VM, started with
/// `vm run --shell`, is passed over, and the session starts its own.
#[test]
fn a_shell_row_is_never_selected() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work().display().to_string();
    let o = rig.run(&["vm", "run", "--egress", "vpc", "--shell", "--workspace", &work, "--json"], None);
    assert!(o.status.success(), "vm run --shell: {}", String::from_utf8_lossy(&o.stderr));
    let shell: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("vm run --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
    let shell = shell["id"].as_str().expect("the shell VM's id").to_string();
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[]);
    started(&mut h);
    closed(&mut h);
    let note = h.end_note();
    assert!(part_of(&note, "vm").is_some_and(|vm| vm != shell) && part_of(&note, "vm_how").as_deref() == Some("started"), "the shell VM {shell} passed over: {note}");
    assert_eq!(runs(h.rig()), 2, "the session's own VM");
}

/// L5: a VM of an image without `workspace_v1` (7.0: its `/health` names the
/// credential cache alone, as `vm health` recorded in its row) is never
/// taken for a session. Pinned (`AI_ENV_BRIDGE_VM`), the wrapper exits 7
/// before any Touch ID and any AWS call, naming `make deploy`; unpinned,
/// SELECT_VM passes it over and the session starts its own VM.
#[test]
fn a_vm_without_the_s8_caps_is_never_selected() {
    use ai_env_cli::wire::frame::CAP_WORKSPACE_V1;
    let mut p = Harness::prepare();
    let rig = p.rig();
    rig.update_fake(|s| s.health_caps.retain(|c| c != CAP_WORKSPACE_V1));
    let old = rig.start_vm();
    let o = rig.run(&["vm", "health", &old], None);
    assert!(o.status.success(), "vm health: {}", String::from_utf8_lossy(&o.stderr));
    rig.update_fake(|s| s.health_caps.push(CAP_WORKSPACE_V1.to_string()));
    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None);
    let caps = ai_env_cli::bridge::vm::registry::read_row(&paths, &old).ok().flatten().and_then(|r| r.caps);
    assert!(caps.as_ref().is_some_and(|c| !c.iter().any(|c| c == CAP_WORKSPACE_V1)), "the old image's caps in its row: {caps:?}");
    let (touch, calls) = (rig.decrypts(), rig.fake_calls().len());
    let (code, err) = remote_run(rig, None, &[("AI_ENV_BRIDGE_VM", old.as_str())]);
    assert_eq!(code, Some(7), "{err}");
    assert_eq!(last_line(&err), format!("ai-env-claude: {old} runs an image older than S8 (no workspace_v1): run make deploy, then reopen the chat"), "{err}");
    assert_eq!((rig.decrypts(), rig.fake_calls().len()), (touch, calls), "no Touch ID, no AWS call");
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[]);
    started(&mut h);
    closed(&mut h);
    let note = end_note_of(&h, h.pid());
    assert!(part_of(&note, "vm").is_some_and(|vm| vm != old) && part_of(&note, "vm_how").as_deref() == Some("started"), "the 7.0 VM {old} passed over: {note}");
    assert_eq!(runs(h.rig()), 2);
}

/// S9 (review CUT-1): SELECT_VM requires `transcript_s3_v1` of a VM it
/// starts too, whose caps no row recorded yet (`vm run` reads no
/// `/health`): its one `/health` names `workspace_v1` but not the transcript
/// store (an image that predates it yet holds an egress pass: a publish
/// that failed after the S9 deploy, a rollback). A fresh session there ends
/// at P2, exit 7 naming `make deploy`, with no seed and no spawn: never a
/// chat whose transcript no sync keeps and no session reuses. The VM's row
/// keeps the caps its `/health` named, so the reuse passes it over.
#[test]
fn a_started_vm_without_the_transcript_store_is_exit_7_before_any_seed() {
    use ai_env_cli::wire::frame::{CAP_TRANSCRIPT_S3_V1, CAP_WORKSPACE_V1};
    let mut p = Harness::prepare();
    p.rig().update_fake(|s| s.health_caps.retain(|c| c != CAP_TRANSCRIPT_S3_V1));
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(7), "{}", h.transcript());
    let failed = h.audit_events("session_remote_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(["step", "code", "why"].map(|k| failed[0]["detail"][k].as_str().unwrap_or_default().to_string()), ["select", "7", "old_image"], "{failed:?}");
    let vm = failed[0]["detail"]["id"].as_str().expect("the VM SELECT_VM started").to_string();
    let err = h.err_text();
    assert_eq!(last_line(&err), format!("ai-env-claude: {vm} runs an image older than S9 (no transcript_s3_v1): run make deploy, then reopen the chat"), "{err}");
    assert!(h.audit_events("seed").is_empty(), "no seed: {:?}", h.audit_events("seed"));
    assert_eq!((h.spawn_count(), h.audit_events("session_remote_start").len()), (0, 0), "no spawn");
    let rig = h.rig();
    assert_eq!(runs(rig), 1, "the VM SELECT_VM started, alone");
    assert!(!rig.vm_path(&rig.work()).join(".git").exists(), "nothing seeded on the VM");
    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None);
    let caps = ai_env_cli::bridge::vm::registry::read_row(&paths, &vm).ok().flatten().and_then(|r| r.caps);
    assert!(caps.as_ref().is_some_and(|c| c.iter().any(|c| c == CAP_WORKSPACE_V1) && !c.iter().any(|c| c == CAP_TRANSCRIPT_S3_V1)), "its row keeps the caps its /health named: {caps:?}");
}

/// S9 round 5 (R4): that state (an image that predates the transcript
/// store yet holds an egress pass) is real for `vm warm`, and the wrapper's
/// prewarm, too. No chat takes a VM without `transcript_s3_v1` (SELECT_VM
/// passes it over, a session refuses one it starts), so the warm of a
/// workspace the seed carries refuses the VM it started once its `/health`
/// names the caps: exit 7 naming `make deploy`, nothing seeded, no token
/// delivered, the VM named as one no chat or warm takes (never "a warm
/// again reuses it").
#[test]
fn vm_warm_never_seeds_or_delivers_to_a_vm_without_the_transcript_store() {
    use ai_env_cli::wire::frame::CAP_TRANSCRIPT_S3_V1;
    let mut p = Harness::prepare();
    let rig = p.rig();
    rig.update_fake(|s| s.health_caps.retain(|c| c != CAP_TRANSCRIPT_S3_V1));
    let work = rig.work().display().to_string();
    let o = rig.run(&["vm", "warm", &work, "--json"], None);
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(7), "{err}");
    assert_eq!(String::from_utf8_lossy(&o.stdout), "", "no warm's report");
    let vm = rig.fake().vms.keys().next().cloned().expect("the VM the warm started");
    assert!(err.contains(&format!("lacks {CAP_TRANSCRIPT_S3_V1}")) && err.contains("make deploy"), "{err}");
    assert!(err.contains(&format!("{vm} was started for this workspace and keeps running, but no chat or warm takes it: `ai-env vm terminate {vm}` ends it")), "{err}");
    assert!(!err.contains("again reuses it"), "{err}");
    assert!(!rig.vm_path(&rig.work()).join(".git").exists(), "nothing seeded on the VM");
    assert!(audit_rows(rig, "credential_deliver").is_empty() && !rig.shim.spawns.credential().has(), "no token delivered");
    assert_eq!(runs(rig), 1, "{:?}", rig.fake_calls());
}

/// D1: every wrapper process unseals the runtime key itself, once. Two
/// sessions, one after the other, on the workspace's one VM: a Touch ID
/// each, never one key shared between processes, never two in one. Each
/// CLI names a session of its own, as a fresh 2.1.x CLI does: both are
/// adopted (no `init_id_refused`), a registry row each.
#[test]
fn each_wrapper_process_unseals_once() {
    let mut p = Harness::prepare();
    let touch = p.rig().decrypts();
    let mut first = p.spawn_on(common::Link::Remote, "", &[], &[]);
    started(&mut first);
    turn(&mut first, "one");
    closed(&mut first);
    assert_eq!(first.rig().decrypts() - touch, 1, "the first process");
    let mut second = Harness::prepare().launch_wrapper(first.rig().wrapper(&[], &[]));
    started(&mut second);
    turn(&mut second, "two");
    closed(&mut second);
    assert_eq!(first.rig().decrypts() - touch, 2, "the second process: its own Touch ID");
    let notes = [end_note_of(&first, first.pid()), end_note_of(&first, second.pid())];
    assert!(notes.iter().all(|n| part_of(n, "legs").is_some_and(|l| l.starts_with("touchid="))), "{notes:?}");
    assert_eq!(part_of(&notes[0], "vm"), part_of(&notes[1], "vm"), "one VM: {notes:?}");
    let unseals = first.audit_events("credential_unseal");
    assert_eq!(unseals.len(), 2, "one unseal per process: {unseals:?}");
    assert!(notes.iter().all(|n| part_of(n, "init_id_refused").is_none()), "each CLI's own session adopted: {notes:?}");
    assert_eq!(first.registry_rows().len(), 2, "a row per chat");
}

/// D1 with a current `combined.env` (the rig's): a session on a VM that
/// does not hold the token costs one Touch ID, which opens the runtime key
/// and the token together (one `credential_unseal`, source `combined`); the
/// token goes to the VM once and the VM's CLI reads it on fd 3, never in a
/// variable (`credential:combined` in the census).
#[test]
fn a_session_costs_one_touch_id_with_a_current_combined_env() {
    let mut p = Harness::prepare();
    let (touch, token) = (p.rig().decrypts(), p.rig().token().to_string());
    let log = p.root.join("token.log").display().to_string();
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_TOKEN_LOG", log.as_str())]);
    started(&mut h);
    closed(&mut h);
    assert_eq!(h.rig().decrypts() - touch, 1, "one Touch ID for the key and the token");
    let unseals = h.audit_events("credential_unseal");
    assert_eq!(unseals.len(), 1, "{unseals:?}");
    assert_eq!((unseals[0]["detail"]["source"].as_str(), unseals[0]["detail"]["outcome"].as_str()), (Some("combined"), Some("ok")), "{unseals:?}");
    assert_eq!(h.audit_events("credential_deliver").len(), 1, "delivered once");
    assert!(common::note_has(&h.end_note(), "credential:combined"), "{}", h.end_note());
    let sha8 = &sha256_hex(&token)[..8];
    assert_eq!(read(&h.root().join("token.log")).trim(), format!("gen 1 source=fd len={} sha8={sha8} fdvar=3 envvar=absent", token.len()));
}

/// D1 without `combined.env`: a session on a VM that does not hold the token
/// costs two Touch IDs, the runtime key's, then, past the gate, the
/// setup-token's (`credential:setup-token`); the VM's CLI reads the token on
/// fd 3.
#[test]
fn without_combined_env_a_cold_session_costs_two() {
    let mut p = Harness::prepare();
    let (touch, token) = {
        let rig = p.rig();
        std::fs::remove_file(rig.bridge().join("credentials").join("combined.env")).expect("remove combined.env");
        (rig.decrypts(), rig.token().to_string())
    };
    let log = p.root.join("token.log").display().to_string();
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_TOKEN_LOG", log.as_str())]);
    started(&mut h);
    closed(&mut h);
    assert_eq!(h.rig().decrypts() - touch, 2, "the runtime key's Touch ID, then the token's");
    assert!(common::note_has(&h.end_note(), "credential:setup-token"), "{}", h.end_note());
    let sha8 = &sha256_hex(&token)[..8];
    assert_eq!(read(&h.root().join("token.log")).trim(), format!("gen 1 source=fd len={} sha8={sha8} fdvar=3 envvar=absent", token.len()));
    assert!(!h.err_text().lines().any(|l| l.starts_with("ai-env:")), "the note about combined.env goes to the log: {}", h.err_text());
}

/// D1 and S7's cache: a session on a VM that holds the token (another
/// session, still open, delivered it) sends none. Its `hello_ok` shows the
/// shim's cache holding this seal, so the spawn only names it (the log says
/// so; no second `credential_deliver`), and the VM's CLI reads the cached
/// copy on fd 3. The process still costs its own Touch ID (D1: the runtime
/// key; the token `combined.env` opened with it goes unused). The census
/// says what each CLI got: the first `credential:combined` (sent), the
/// second `credential:cached` (the VM's copy).
#[test]
fn a_session_on_a_vm_holding_the_token_sends_no_token() {
    let mut p = Harness::prepare();
    let (touch, token) = (p.rig().decrypts(), p.rig().token().to_string());
    let log = p.root.join("token.log").display().to_string();
    let mut first = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_TOKEN_LOG", log.as_str())]);
    started(&mut first);
    assert_eq!(first.audit_events("credential_deliver").len(), 1, "the first session delivered it");
    let mut second = Harness::prepare().launch_wrapper(first.rig().wrapper(&[], &[("FAKE_TOKEN_LOG", log.as_str())]));
    started(&mut second);
    closed(&mut second);
    closed(&mut first);
    assert_eq!(first.audit_events("credential_deliver").len(), 1, "nothing sent again");
    assert!(first.wrapper_log().contains(": the VM holds credential CLAUDE_CODE_OAUTH_TOKEN (tag "), "{}", first.wrapper_log());
    let sha8 = &sha256_hex(&token)[..8];
    let want: Vec<String> = (1..=2).map(|gen| format!("gen {gen} source=fd len={} sha8={sha8} fdvar=3 envvar=absent", token.len())).collect();
    assert_eq!(read(&first.root().join("token.log")).lines().map(str::to_string).collect::<Vec<_>>(), want, "both CLIs read the token on fd 3");
    assert_eq!(first.rig().decrypts() - touch, 2, "a Touch ID per process (D1)");
    let (one, two) = (end_note_of(&first, first.pid()), end_note_of(&first, second.pid()));
    assert_eq!(part_of(&one, "vm"), part_of(&two, "vm"));
    assert_eq!((part_of(&one, "credential").as_deref(), part_of(&two, "credential").as_deref()), (Some("combined"), Some("cached")), "the first sent combined.env's token; the second's CLI got the VM's copy:\n{one}\n{two}");
}

/// A1 (plans/s10-accounts-plan.md §5): a turn refused for the account's
/// weekly limit (the fake as claude 2.1.305, `FAKE_USAGE_LIMIT=1`) reaches
/// Cursor as the CLI printed it, then the exact note: account `default` (the
/// green world's token, adopted) hit its weekly limit, and `spare` (sealed,
/// never seen) is the account to go on with, and how. The limit is in
/// `[usage.default]` (`source` `chat`, its kind, the CLI's text), audited
/// `usage_limited`; nothing is recorded as refused; the wrapper exits 0 at
/// the host's EOF; the census `account:default` and `usage_limited:1`.
#[test]
fn a1_a_usage_limited_turn_gets_its_note_and_its_record() {
    use ai_env_cli::bridge::accounts::{self, usage};
    let mut p = Harness::prepare();
    p.rig().seal_account("spare", "Sp");
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_USAGE_LIMIT", "1")]);
    let init = started(&mut h);
    let sid = init["session_id"].as_str().expect("the session id").to_string();
    let u = h.send_user("one");
    let note = h.expect_out(|v| v["subtype"] == "informational", T);
    let want = format!("ai-env: account default hit its weekly limit (it resets 10am (UTC)); to go on now with account spare (its limits are unknown: ai-env creds account check): ai-env creds account use spare, then reopen this chat or run ai-env session migrate {sid}");
    assert_eq!(note["content"].as_str(), Some(want.as_str()));
    let out = h.out_json();
    let result = out.iter().position(|v| is_result_for(v, &u)).expect("the refused turn's result");
    assert_eq!((out[result]["api_error"].as_str(), out[result]["api_error_status"].as_u64()), (Some("usage_limit_reached"), Some(429)));
    assert_eq!(out[result + 1]["content"].as_str(), Some(want.as_str()), "the note right after the result");
    closed(&mut h);
    let paths = h.rig().paths();
    let state = accounts::read(&paths).unwrap().expect("the store");
    let rec = usage::read_record(&state.usage["default"]);
    let limited = rec.limited.clone().expect("limited");
    assert_eq!((rec.source.as_deref(), rec.status.as_deref(), limited.kind.as_str(), limited.text.as_str()), (Some("chat"), Some("rejected"), "seven_day", "You've hit your weekly limit · resets 10am (UTC)"));
    assert!(!state.usage.contains_key("spare"), "spare was never seen");
    let audited = h.audit_events("usage_limited");
    assert_eq!((audited.len(), audited[0]["detail"]["account"].as_str(), audited[0]["detail"]["kind"].as_str()), (1, Some("default"), Some("seven_day")), "{audited:#?}");
    assert!(!paths.creds_state().exists() && h.audit_events("credential_rejected").is_empty(), "a usage limit is no refusal");
    let note = h.end_note();
    assert!(note.contains("; account:default; usage_limited:1"), "{note}");
}

/// A1: the windows a turn's `rate_limit_event` reports
/// (`FAKE_RATE_LIMIT_INFO`) are recorded for the live generation's account
/// (`default`), `source` `chat`, the line reaching Cursor as the CLI printed
/// it; the census `rate_limit:1/1`.
#[test]
fn a1_a_rate_limit_event_records_the_accounts_windows() {
    use ai_env_cli::bridge::accounts::{self, usage};
    let mut p = Harness::prepare();
    p.rig().seal_account("spare", "Sp");
    let reset = ai_env_cli::wire::time::unix_now() + 3600;
    let info = format!(r#"{{"status":"allowed_warning","rateLimitType":"seven_day","utilization":0.81,"resetsAt":{reset},"unifiedWindows":{{"five_hour":{{"utilization":0.23,"resetsAt":{reset}}},"seven_day":{{"utilization":0.81,"resetsAt":{reset}}}}},"isUsingOverage":false}}"#);
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_RATE_LIMIT_INFO", info.as_str())]);
    started(&mut h);
    let u = h.send_user("one");
    h.expect_out(|v| is_result_for(v, &u), T);
    let event = h.out_lines().into_iter().find(|l| l.contains("rate_limit_event")).expect("the event");
    assert!(event.starts_with(&format!(r#"{{"type":"rate_limit_event","rate_limit_info":{info},"#)), "as the CLI printed it: {event}");
    closed(&mut h);
    let state = accounts::read(&h.rig().paths()).unwrap().expect("the store");
    let rec = usage::read_record(&state.usage["default"]);
    assert_eq!((rec.source.as_deref(), rec.status.as_deref(), rec.warning.as_deref()), (Some("chat"), Some("allowed_warning"), Some("seven_day")));
    assert_eq!((rec.five_hour.map(|w| (w.utilization, w.resets_at)), rec.seven_day.map(|w| (w.utilization, w.resets_at))), (Some((0.23, reset)), Some((0.81, reset))));
    assert!(h.end_note().contains("; account:default; rate_limit:1/1"), "{}", h.end_note());
}

/// D1 and plan §3 (P1): the Touch ID and the workspace's preparation run at
/// once. While the Touch ID waits (its decrypt held until a file appears),
/// the WIP snapshot and the seed's listing run all the same (the Mac's git
/// shows them) and nothing past P1 has happened (no VM); answered, the
/// session starts.
#[test]
fn the_unseal_runs_beside_the_seed() {
    let mut p = Harness::prepare();
    let release = p.root.join("age.release");
    let held = release.display().to_string();
    std::fs::write(p.rig().work().join("notes.txt"), "uncommitted on the Mac\n").expect("write notes.txt");
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_AGE_WAIT_FILE", held.as_str())]);
    let init = h.send_initialize();
    {
        let rig = h.rig();
        wait_for("the seed's listing while the Touch ID waits", T, || rig.mac_git_calls().iter().any(|c| c.sub() == Some("rev-list") && c.has("--objects")));
        assert_eq!((runs(rig), rig.vm_spawns().len()), (0, 0), "nothing past P1 while the Touch ID waits");
    }
    std::fs::write(&release, "go").expect("answer the Touch ID");
    h.expect_out(|v| is_response_to(v, &init), T);
    h.expect_out(is_init, T);
    closed(&mut h);
    assert!(common::note_has(&h.end_note(), "seed:seeded"), "{}", h.end_note());
}

/// S7's gate before any unseal, on the wrapper's path (P0): with no passing
/// egress check recorded for the image and the connector, the session is
/// refused at once: exit 9, one line, no Touch ID, no AWS call, the gate's
/// refusal audited.
#[test]
fn the_credential_gate_runs_before_any_unseal_in_the_wrapper_path() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    std::fs::remove_file(rig.bridge().join("state").join("egress-verified.toml")).expect("remove the egress check's record");
    let (touch, calls) = (rig.decrypts(), rig.fake_calls().len());
    let (code, err) = remote_run(rig, None, &[]);
    assert_eq!(code, Some(9), "{err}");
    assert!(last_line(&err).starts_with("ai-env-claude: refused before any Touch ID: "), "{err}");
    assert!(err.lines().all(|l| l.starts_with("ai-env-claude: ")), "one line, the wrapper's: {err}");
    assert_eq!((rig.decrypts(), rig.fake_calls().len()), (touch, calls), "no Touch ID, no AWS call");
    let gate = audit_rows(rig, "credential_gate");
    assert!(gate.iter().any(|r| r["detail"]["result"] == "refused"), "{gate:?}");
    let failed = audit_rows(rig, "session_remote_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!((failed[0]["detail"]["step"].as_str(), failed[0]["detail"]["code"].as_str()), (Some("precheck"), Some("9")), "{failed:?}");
}

/// S7 D6 on the remote link: the VM's CLI (the measured 2.1.296) answers
/// with B7's refusal (two retried 401s, the synthetic reply, the error
/// result 401). The 401 watch stops the session at once, its stdin still
/// open: exit 5 and S7 D6's line, the refusal recorded for its seal, nothing
/// started again, nothing left on the VM. The error result's code-out, cut
/// by the exit, may leave its scratch under `state/tmp` (no destructor runs
/// at the exit), and nothing else; the next import (`box fetch`) removes
/// what a process that is gone left (W4's lazy cleanup).
#[test]
fn a_401_from_the_vm_child_stops_it_and_exits_5_without_respawn() {
    let fixture = include_str!("fixtures/claude/refused-stream-json-2.1.296.jsonl");
    let p = Harness::prepare();
    // B7's run after its own init line (the fake sends the session's).
    let refused: String = fixture.lines().skip(1).map(|l| format!("{l}\n")).collect();
    let file = p.write_file("refused.jsonl", &refused).display().to_string();
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_STDOUT_FILE", file.as_str())]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(5), "{}", h.transcript());
    let err = h.err_text();
    assert_eq!(last_line(&err), "ai-env-claude: Anthropic refused the delivered setup-token (HTTP 401): the session was stopped and is not started again; seal a fresh one with `claude setup-token`, then `ai-env creds setup-token`", "{err}");
    let note = h.end_note();
    assert!(common::note_has(&note, "end:credential_rejected"), "{note}");
    assert_eq!((h.spawn_count(), h.audit_events("session_remote_start").len()), (1, 1), "nothing started again");
    let rejected = h.audit_events("credential_rejected");
    assert_eq!(rejected.len(), 1, "{rejected:?}");
    assert!(read(&h.bridge().join("state").join("creds.toml")).contains("[[rejected]]"), "the refusal recorded for its seal");
    wait_for("no child left on the VM", Duration::from_secs(10), || h.rig().vm_spawns().iter().all(|s| !s.alive));
    // The code-out's scratch (`fetch-<pid>-*`, its import's `codeout-<pid>-*`) is all the wrapper may leave.
    let tmp = h.bridge().join("state").join("tmp");
    let pid = h.pid();
    let codeout_scratch = |n: &String| ["fetch", "codeout"].iter().any(|p| n.starts_with(&format!("{p}-{pid}-")));
    let left = names_in(&tmp);
    assert!(left.iter().all(codeout_scratch), "state/tmp after the exit: {left:?}");
    let rig = h.rig();
    let o = rig.run(&["box", "fetch", &rig.work().display().to_string()], None);
    assert!(o.status.success(), "box fetch: {}", String::from_utf8_lossy(&o.stderr));
    let after = names_in(&tmp);
    assert!(!after.iter().any(codeout_scratch), "the next import removed the wrapper's scratch {left:?}: {after:?}");
}

/// A VM whose claude is not the one `AUTH_TIMERS` measured: the session
/// runs (its 401 watch keeps S7's retry rule alone), the census end row names
/// that claude and says `auth_timers:unmeasured(<version>)`, and
/// `auth_timers_unmeasured` is audited once for that version on this Mac: a
/// second session adds no row.
#[test]
fn a_vm_claude_other_than_auth_timers_is_noted() {
    use ai_env_cli::bridge::authwatch::AUTH_TIMERS;
    const OTHER: &str = "2.1.297";
    let mut p = Harness::prepare();
    p.rig_with_vm_knobs(&[("FAKE_VERSION", OTHER)]);
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_VERSION", OTHER)]);
    started(&mut h);
    turn(&mut h, "hello");
    closed(&mut h);
    let note = h.end_note();
    assert_eq!((part_of(&note, "claude").as_deref(), part_of(&note, "auth_timers")), (Some(OTHER), Some(format!("unmeasured({OTHER})"))), "{note}");
    let rows = h.audit_events("auth_timers_unmeasured");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!((rows[0]["detail"]["claude"].as_str(), rows[0]["detail"]["measured"].as_str()), (Some(OTHER), Some(AUTH_TIMERS.claude)), "{rows:?}");
    assert!(h.bridge().join("state").join("auth-timers").join(OTHER).is_file(), "the version's marker");
    let mut again = Harness::prepare().launch_wrapper(h.rig().wrapper(&[], &[("FAKE_VERSION", OTHER)]));
    started(&mut again);
    closed(&mut again);
    assert_eq!(h.audit_events("auth_timers_unmeasured").len(), 1, "once per version");
}

/// No secret reaches what the Mac keeps of a remote session (plan Part A
/// phase 4, the custody lens). A session that unsealed the runtime key,
/// delivered the token, carried the Mac's uncommitted work, and ran a turn
/// that edited, committed and wrote settings in the VM, its code-out
/// fetched: nothing under the bridge dir (census, audit, logs, the
/// registry, the workspace rows, the scan cache, `state/tmp`, quarantine)
/// or the Mac's `~/.claude` holds the token, the runtime key's secret or a
/// secret value Cursor's environment held, nor does the wrapper's output.
/// A seed a planted secret refuses (an untracked file: exit 9) names
/// the file and the rule, never the value, on stderr or under the bridge
/// dir, and leaves no scratch behind.
#[test]
fn secrets_never_reach_census_audit_log_or_registry_remote() {
    let shaped = |tag: &str| format!("{}-{}-{tag}{}", "sk", "ant", "Yh7".repeat(12));
    let (oauth, aws) = (shaped("w10"), format!("{}{}", "AKIA", "V".repeat(16)));
    // A session's records.
    {
        let mut p = Harness::prepare();
        let token = p.rig().token().to_string();
        std::fs::write(p.work().join("notes.txt"), "uncommitted on the Mac\n").expect("write notes.txt");
        let settings = r#"local:{"permissions":{"allow":["Bash(ls:*)"]}}"#;
        let knobs = [
            ("FAKE_WRITE_TRANSCRIPT", "1"),
            ("FAKE_EDIT", "agent.txt:from the VM"),
            ("FAKE_COMMIT", "the agent's commit"),
            ("FAKE_WIP_EDIT", "agent.txt:not committed yet"),
            ("FAKE_WRITE_SETTINGS", settings),
            ("FAKE_OAUTH_REFRESH", "1"),
            ("CLAUDE_CODE_OAUTH_TOKEN", oauth.as_str()),
            ("AWS_SECRET_ACCESS_KEY", aws.as_str()),
        ];
        let mut h = p.spawn_on(common::Link::Remote, "", &[], &knobs);
        started(&mut h);
        turn(&mut h, "hello");
        wait_for_fetch(h.rig());
        closed(&mut h);
        let needles = [token.clone(), token[13..].to_string(), oauth, aws, common::green_world::runtime_key_secret()];
        let (bridge, mac) = (h.bridge(), h.root().join(".claude"));
        assert!(files_under(&bridge).iter().any(|f| f.starts_with("logs/")) && files_under(&bridge).iter().any(|f| f.starts_with("state/sessions/")), "the records exist: {:?}", files_under(&bridge));
        assert_eq!(holding(&[&bridge, &mac], &needles), Vec::<String>::new(), "a secret in what the Mac keeps");
        let output = format!("{}\n{}", h.out_lines().join("\n"), h.err_text());
        assert!(!needles.iter().any(|n| output.contains(n.as_str())), "a secret in the wrapper's output");
    }
    // A planted secret refuses the seed: named by its file and rule, never by its value.
    let key = format!("{}{}", "AKIA", "U".repeat(16));
    let mut q = Harness::prepare();
    std::fs::write(q.rig().work().join("deploy.txt"), format!("aws_access_key_id = {key}\n")).expect("write deploy.txt");
    let mut h = q.spawn_on(common::Link::Remote, "", &[], &[]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(9), "{}", h.transcript());
    let err = h.err_text();
    let last = last_line(&err);
    assert!(last.starts_with("ai-env-claude: the seed would carry ") && last.contains("deploy.txt") && last.contains("aws-access-key-id"), "{err}");
    assert!(!err.contains(&key), "the value on stderr: {err}");
    assert_eq!(holding(&[&h.bridge()], std::slice::from_ref(&key)), Vec::<String>::new(), "the value under the bridge dir");
    let scratch: Vec<String> = files_under(&h.bridge().join("state").join("tmp"));
    assert!(scratch.is_empty(), "the seed's scratch removed: {scratch:?}");
    assert_eq!(runs(h.rig()), 0, "refused before any VM: the scans run before anything leaves the Mac");
}

/// The per-result code-out never holds a line back (plan §7): the turn's
/// `POST /codeout` held at the endpoint, the next turn still goes through
/// at once (its echo, its reply, its result) while the fetch waits; let go,
/// the fetch completes and brings the agent's commit into `box/main`. A
/// code-out still on its way at the close is abandoned within the close
/// budget (`codeout::CLOSE_WAIT`, 300 ms).
#[test]
fn per_result_fetch_never_holds_a_line_back() {
    use ai_env_cli::bridge::remote::CLOSE_BUDGET_MS;
    use ai_env_cli::wire::workspace::CODE_PORT;
    use common::fake_endpoint::Action;
    let knobs = [("FAKE_EDIT", "agent.txt:from the VM"), ("FAKE_COMMIT", "the agent's commit")];
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &knobs);
    started(&mut h);
    // The seed went in before the spawn: the code port's next request is the turn's code-out.
    h.rig().endpoint.script_port(CODE_PORT, [Action::Held]);
    turn(&mut h, "one");
    turn(&mut h, "two");
    assert!(audit_rows(h.rig(), "codeout_fetch").is_empty(), "the second turn came while the first's code-out was held");
    h.rig().endpoint.release();
    let rig = h.rig();
    let vm_head = git_in(&rig.vm_path(&rig.work()), &["rev-parse", "HEAD"]);
    wait_for("the code-out let go, its commit in box/main", T, || {
        let o = Command::new(common::git_real()).args(["rev-parse", "--verify", "-q", "refs/remotes/box/main"]).current_dir(rig.work()).output().expect("run git");
        String::from_utf8_lossy(&o.stdout).trim() == vm_head
    });
    wait_for_fetch(rig);
    closed(&mut h);
    // Held at the close: abandoned within the budget.
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &knobs);
    started(&mut h);
    h.rig().endpoint.script_port(CODE_PORT, [Action::Held]);
    turn(&mut h, "one");
    let took = closed(&mut h);
    assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "the held code-out cost the close {took:?}");
    assert!(audit_rows(h.rig(), "codeout_fetch").iter().all(|r| r["detail"]["outcome"] != "promoted"), "nothing went through the hold");
}

/// The session's detach grace covers the VM's idle policy (plan §11,
/// L3): with `[vm].max_idle_s = 1200` the spawn asks for
/// `max(900, 1200 + 90 + 60)`, 1350 s, so a wrapper gone without a word
/// (SIGKILL, no detach) leaves its CLI on the VM past an idle suspend, for a
/// reopened chat to find; the shim counts that grace down from the loss.
#[test]
fn the_session_detach_grace_covers_max_idle() {
    let mut p = Harness::prepare();
    add_config(p.rig(), "[vm]\nmax_idle_s = 1200\n");
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[]);
    started(&mut h);
    let vm_pid = h.fake_pid(1).expect("the VM's CLI logged its pid");
    h.child.kill().expect("SIGKILL the wrapper");
    let _ = h.child.wait();
    let mut left = None;
    wait_for("the spawn detached in the shim", T, || {
        left = h.rig().shim.spawns.detail().first().and_then(|d| d.detach_left_s);
        left.is_some()
    });
    let left = left.unwrap_or_default();
    assert!((1300..=1350).contains(&left), "the grace the spawn asked for: {left} s left");
    assert!(common::pid_alive(vm_pid), "the CLI lives on through its grace");
}

/// v6 L8(c) on a reused VM: the grace covers the idle policy of the VM the
/// session runs on, which keeps the one it was started with. The
/// workspace's VM came from `vm run --idle 3600` (the config keeps 300 s);
/// the session reuses it and asks for `max(900, 3600 + 90 + 60)`, 3750 s, so
/// a Mac asleep past 900 s (short of the VM's idle) still finds its CLI.
#[test]
fn a_reused_vm_with_a_longer_idle_keeps_the_session_through_its_idle() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work().display().to_string();
    let o = rig.run(&["vm", "run", "--egress", "vpc", "--workspace", &work, "--idle", "3600", "--json"], None);
    assert!(o.status.success(), "vm run --idle 3600: {}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("vm run --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
    let vm = v["id"].as_str().expect("the VM's id").to_string();
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[]);
    started(&mut h);
    let select = h.audit_events("vm_select");
    let last = select.last().map(|r| (r["detail"]["id"].as_str().map(str::to_string), r["detail"]["how"].as_str().map(str::to_string)));
    assert_eq!(last, Some((Some(vm), Some("reused".to_string()))), "{select:?}");
    let vm_pid = h.fake_pid(1).expect("the VM's CLI logged its pid");
    h.child.kill().expect("SIGKILL the wrapper");
    let _ = h.child.wait();
    let mut left = None;
    wait_for("the spawn detached in the shim", T, || {
        left = h.rig().shim.spawns.detail().first().and_then(|d| d.detach_left_s);
        left.is_some()
    });
    let left = left.unwrap_or_default();
    assert!((3700..=3750).contains(&left), "the grace the spawn asked for: {left} s left");
    assert!(common::pid_alive(vm_pid), "the CLI lives on through its grace");
}

/// T8.4 offline: the picker reopens a chat whose VM still lives (suspended
/// by the close), while a newer VM of the workspace runs (the one the
/// workspace's choice would take). The wrapper's `--resume` prefers the
/// session's VM (`vm_select` says `prefer`): it is resumed, not replaced
/// (`vm_how:resumed`, no RunMicrovm of its own), the transcript already
/// there is kept (S9: the VM holds what S3 committed, `transcript:kept`,
/// nothing pulled), and the CLI resumes the same session from it; its next
/// turn goes to S3 after the committed prefix, the Mac keeping the view.
#[test]
fn resume_on_the_same_vm_keeps_vm_and_session_id() {
    use ai_env_cli::bridge::api::VmState;
    let mut first = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_WRITE_TRANSCRIPT", "1")]);
    let init = started(&mut first);
    let sid = init["session_id"].as_str().expect("the session id").to_string();
    turn(&mut first, "first");
    // The turn's code-out and transcript step done: none still on its way (the endpoint would resume the VM the close suspends).
    synced(&mut first, &sid, 1);
    closed(&mut first);
    let vm = part_of(&end_note_of(&first, first.pid()), "vm").expect("the first session's VM");
    let rig = first.rig();
    let suspended = std::time::Instant::now();
    while !rig.fake().vms.get(&vm).is_some_and(|v| v.state == VmState::Suspended) {
        assert!(suspended.elapsed() < Duration::from_secs(10), "the closing suspend\n{}", first.wrapper_log());
        std::thread::sleep(Duration::from_millis(25));
    }
    // A newer VM of the workspace, running: newest first, the workspace's choice would take it.
    let work = rig.work().display().to_string();
    let o = rig.run(&["vm", "run", "--egress", "vpc", "--workspace", &work, "--new", "--json"], None);
    assert!(o.status.success(), "vm run --new: {}", String::from_utf8_lossy(&o.stderr));
    let newer: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("vm run --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
    let newer = newer["id"].as_str().expect("the newer VM's id").to_string();
    let resume = format!("--resume={sid}");
    let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_WRITE_TRANSCRIPT", "1")]));
    let init = started(&mut second);
    assert_eq!(init["session_id"].as_str(), Some(sid.as_str()), "the same session: {init}");
    turn(&mut second, "second");
    let views = || audit_rows(rig, "transcript_view").iter().filter(|r| r["detail"]["session"] == sid.as_str() && r["detail"]["outcome"] == "written").count();
    wait_for("the second turn's transcript synced and its view written", T, || views() >= 2);
    closed(&mut second);
    let note = end_note_of(&first, second.pid());
    assert_eq!((part_of(&note, "vm"), part_of(&note, "vm_how"), part_of(&note, "transcript")), (Some(vm.clone()), Some("resumed".into()), Some("kept".into())), "the session's VM, not the newer {newer}: {note}");
    assert!(audit_rows(rig, "transcript_pull").is_empty(), "nothing pulled for a VM that holds it");
    let selects = audit_rows(rig, "vm_select");
    let last = selects.last().expect("the resume's vm_select row");
    assert_eq!((last["detail"]["choice"].as_str(), last["detail"]["id"].as_str()), (Some("prefer"), Some(vm.as_str())), "{selects:?}");
    assert_eq!(runs(rig), 2, "the first session's VM and the newer one: none for the resume");
    assert!(first.env_log().iter().any(|l| l == "gen 2 resumed lines=4"), "the VM's copy, its api-request lines too: {:?}", first.env_log());
    let file = format!("{sid}.jsonl");
    let (mac, vm_copy) = (first.prepared.mac_projects().join(first.slug()).join(&file), rig.vm_projects().join(first.slug()).join(&file));
    assert_eq!((held_in_s3(rig, &sid), read(&vm_copy).lines().count()), (std::fs::read(&vm_copy).unwrap(), 8), "S3 holds both sessions' turns, byte for byte");
    assert!(is_view(&mac), "the Mac keeps the view");
    let rows = first.registry_rows();
    let row = rows.iter().find(|r| r.get("session_id").and_then(toml::Value::as_str) == Some(sid.as_str())).unwrap_or_else(|| panic!("{rows:?}"));
    assert_eq!(row.get("microvm_id").and_then(toml::Value::as_str), Some(vm.as_str()), "{row:?}");
}

/// T8.5 offline after the S3 cut-over: the picker reopens a chat whose VM
/// is gone (terminated; the registry row still names it) and whose Mac copy
/// is S8's mirror (a remote row without `transcript_home`). The wrapper's
/// `--resume` passes the VM over and starts one; before the spawn P3 sends
/// the mirror up in `session migrate-s9`'s gone-VM form (S3 then holds it
/// as the VM-begun chat's, `transcript_migrate` migrated; the Mac keeps its
/// view, the mirror deleted, nothing of it in `origin/`), then pulls it
/// into the new VM (`transcript_pull` before `session_remote_start`): the
/// CLI resumes from it at once (no miss), the same session goes on, its
/// turn to S3 after it (`transcript:staged`).
#[test]
fn resume_into_a_new_vm_restores_the_transcript_first() {
    use ai_env_cli::bridge::registry::{self, SessionRow, REGISTRY_SCHEMA_V};
    let mut p = Harness::prepare();
    let sid = common::uuid(0x8830);
    let earlier = format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, common::uuid(0x8831));
    let mirror = p.plant_transcript(&sid, &[earlier.as_str()]);
    let slug = p.slug();
    let rig = p.rig();
    // The chat's last VM: started for the workspace, then terminated (never run on this rig's shim).
    let gone = rig.start_vm();
    let o = rig.run(&["vm", "terminate", &gone, "--yes"], None);
    assert!(o.status.success(), "vm terminate: {}", String::from_utf8_lossy(&o.stderr));
    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None);
    let now = registry::now_rfc3339();
    let row = SessionRow {
        v: REGISTRY_SCHEMA_V,
        session_id: sid.clone(),
        slug: Some(slug.clone()),
        cwd: Some(rig.work().display().to_string()),
        transcript_rel: Some(format!("{slug}/{sid}.jsonl")),
        created: now.clone(),
        last_seen: now,
        status: "closed".into(),
        mode: "remote".into(),
        route: "remote".into(),
        exit: Some(0),
        microvm_id: Some(gone.clone()),
        ..SessionRow::default()
    };
    registry::write(&paths, &row).expect("the session's registry row");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_WRITE_TRANSCRIPT", "1")]);
    let init = started(&mut h);
    assert_eq!(init["session_id"].as_str(), Some(sid.as_str()), "{init}");
    assert!(h.env_log().iter().any(|l| l == "gen 1 resumed lines=1"), "the transcript was there before the CLI: {:?}", h.env_log());
    turn(&mut h, "after the VM was replaced");
    // The view the mirror's migration left, then the turn's sync's.
    synced(&mut h, &sid, 2);
    closed(&mut h);
    let note = h.end_note();
    let vm = part_of(&note, "vm").expect("the new VM");
    assert_ne!(vm, gone, "{note}");
    assert_eq!((part_of(&note, "vm_how"), part_of(&note, "transcript")), (Some("started".into()), Some("staged".into())), "{note}");
    assert_eq!(runs(h.rig()), 2, "a new VM");
    let events: Vec<(String, String)> = h.audit_rows().iter().map(|r| (r["event"].as_str().unwrap_or_default().to_string(), r["detail"]["outcome"].as_str().unwrap_or_default().to_string())).collect();
    let at = |event: &str, outcome: &str| events.iter().position(|(e, o)| e == event && (outcome.is_empty() || o == outcome)).unwrap_or_else(|| panic!("no {event} {outcome}: {events:?}"));
    let (migrated, pulled, start) = (at("transcript_migrate", "migrated"), at("transcript_pull", "written"), at("session_remote_start", ""));
    assert!(migrated < pulled && pulled < start, "up to S3, into the VM, then the spawn: {events:?}");
    let vm_copy = h.rig().vm_projects().join(&slug).join(format!("{sid}.jsonl"));
    assert!(read(&vm_copy).starts_with(&format!("{earlier}\n")) && read(&vm_copy).lines().count() == 5, "the conversation goes on from the mirror's line: {}", read(&vm_copy));
    assert_eq!(held_in_s3(h.rig(), &sid), std::fs::read(&vm_copy).unwrap(), "S3 holds the whole conversation");
    assert!(is_view(&mirror), "the Mac keeps the view in the mirror's place");
    assert!(!paths.transcript_origin(&sid).exists(), "an S8 mirror is not kept once S3 holds it");
    // S10 (FK-8): the reopen's carry off the terminated VM left nothing on the new one.
    h.assert_vm_empty();
}

// ---- S9 R5-AWS-1: a big chat is made ready in its VM ahead, and a reopen pulls at most 64 MiB ----------
//
// Generation 1's restore runs under T0 + 50 s, and at the proxy's 4 to 16
// MB/s a GiB takes minutes: a reopen pulls at most `wire::s3::INLINE_MAX`
// in all, and `session stage UUID --warm` restores a larger chat into its
// workspace's VM beforehand, where the reopen keeps it.

/// S9 R5-AWS-1 (a): `session stage UUID --warm` makes a chat begun on this
/// Mac ready in its workspace's VM. It is staged (the runtime key's Touch
/// ID), the workspace warmed (its VM started and seeded, the token
/// delivered: one Touch ID with the current combined.env), then the chat
/// restored from S3 into that VM with no deadline: the VM holds it byte for
/// byte, a `transcript_pull` row (written, its bytes and ms) names the VM,
/// and the `--json` document's `restore` says the same. Two Touch IDs in
/// all: the restore asks none. Run again it is idempotent: `already`, the
/// warm's Touch ID alone, the restore `kept` (nothing pulled). The chat's
/// reopen then takes that VM and keeps what it holds (`transcript:kept`, no
/// pull), the CLI resuming from it.
#[test]
fn session_stage_warm_restores_the_chat_into_its_vm_and_the_reopen_keeps_it() {
    let mut p = Harness::prepare();
    let sid = common::uuid(0x9101);
    let cwd = p.work();
    let lines: Vec<String> = (0..3).map(|i| serde_json::json!({"type": "user", "uuid": common::uuid(0x9110 + i), "sessionId": sid, "cwd": cwd, "message": {"role": "user", "content": format!("turn {i}")}}).to_string()).collect();
    let chat = p.plant_transcript(&sid, &lines.iter().map(String::as_str).collect::<Vec<_>>());
    let bytes = std::fs::read(&chat).expect("the chat");
    let slug = p.slug();
    let vm = {
        let rig = p.rig();
        let stage = |touch_ids: usize| {
            let before = rig.decrypts();
            let o = rig.run(&["session", "stage", &sid, "--warm", "--json"], None);
            assert!(o.status.success(), "session stage --warm: {}", String::from_utf8_lossy(&o.stderr));
            assert_eq!(rig.decrypts() - before, touch_ids, "Touch IDs: {}", String::from_utf8_lossy(&o.stderr));
            serde_json::from_slice::<Value>(&o.stdout).unwrap_or_else(|e| panic!("one JSON document ({e}): {}", String::from_utf8_lossy(&o.stdout)))
        };
        let doc = stage(2);
        assert_eq!(doc["outcome"], "staged", "{doc}");
        let restore = &doc["restore"];
        let vm = restore["vm"].as_str().unwrap_or_else(|| panic!("the warmed VM: {doc}")).to_string();
        assert_eq!((restore["outcome"].as_str(), restore["bytes"].as_u64()), (Some("restored"), Some(bytes.len() as u64)), "{doc}");
        assert!(restore["ms"].as_u64().is_some(), "{doc}");
        assert_eq!(std::fs::read(rig.vm_projects().join(&slug).join(format!("{sid}.jsonl"))).expect("the VM's copy"), bytes, "the VM holds the chat, byte for byte");
        let pulls = audit_rows(rig, "transcript_pull");
        assert_eq!(pulls.len(), 1, "{pulls:?}");
        let d = &pulls[0]["detail"];
        assert_eq!((d["session"].as_str(), d["vm"].as_str(), d["outcome"].as_str(), d["bytes"].as_str()), (Some(sid.as_str()), Some(vm.as_str()), Some("written"), Some(bytes.len().to_string().as_str())), "{d}");
        assert!(d["ms"].as_str().is_some_and(|ms| ms.parse::<u64>().is_ok()), "{d}");
        // Again: S3 holds it already, the VM too.
        let doc = stage(1);
        assert_eq!((doc["outcome"].as_str(), doc["restore"]["vm"].as_str(), doc["restore"]["outcome"].as_str(), doc["restore"]["bytes"].as_u64()), (Some("already"), Some(vm.as_str()), Some("kept"), Some(0)), "{doc}");
        assert_eq!(audit_rows(rig, "transcript_pull").len(), 1, "nothing pulled again");
        vm
    };
    let resume = format!("--resume={sid}");
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1")]);
    let init = started(&mut h);
    assert_eq!(init["session_id"].as_str(), Some(sid.as_str()), "{init}");
    closed(&mut h);
    let note = h.end_note();
    assert_eq!((part_of(&note, "vm"), part_of(&note, "transcript")), (Some(vm), Some("kept".into())), "the warmed VM, which holds the chat: {note}");
    assert!(matches!(part_of(&note, "vm_how").as_deref(), Some("reused" | "resumed")), "{note}");
    assert_eq!(audit_rows(h.rig(), "transcript_pull").len(), 1, "the reopen pulled nothing");
    assert!(h.env_log().iter().any(|l| *l == format!("gen 1 resumed lines={}", lines.len())), "the CLI resumed from the VM's copy: {:?}", h.env_log());
}

/// S9 R5-AWS-1 (b): a reopen of a chat S3 holds whose transcript is over
/// what a reopen pulls inline (its manifest commits 70 MiB; nothing is in
/// the tests' S3) is refused with no pull request, exit 9, the line naming
/// `ai-env session stage UUID --warm`. While no VM of the workspace lives
/// (a new one could not hold it), at P0: before any Touch ID and any AWS
/// call. Once one lives that does not hold it (P0 cannot tell; P3's stat
/// does), at P3 after the Touch ID: no part asked of S3, nothing pulled
/// into the VM, no `transcript_pull` row, the VM named.
#[test]
fn a_reopen_over_what_it_pulls_inline_is_refused_at_p0_or_p3_before_any_pull() {
    use ai_env_cli::bridge::s3::manifest::{self, Manifest, ManifestPart, ORIGIN_VM};
    use ai_env_cli::wire::s3::S3Key;
    let mut p = Harness::prepare();
    let sid = common::uuid(0x9102);
    let slug = p.slug();
    let resume = format!("--resume={sid}");
    let base = S3Key::Base { session: sid.clone(), gen: 1 }.render();
    let line = format!("ai-env-claude: the chat's transcript in S3 is 70.0 MiB, over the 64 MiB a reopen pulls inline: run ai-env session stage {sid} --warm in a terminal, then reopen the chat");
    let failed = |rig: &common::remote::RemoteRig| audit_rows(rig, "session_remote_failed").iter().map(|r| ["step", "code", "why", "id"].map(|k| r["detail"][k].as_str().unwrap_or_default().to_string())).collect::<Vec<_>>();
    {
        let rig = p.rig();
        let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None);
        let target = ai_env_cli::bridge::s3::S3Target { bucket: ai_env_cli::bridge::s3::LAB_BUCKET.into(), owner: ai_env_cli::bridge::s3::LAB_OWNER.into(), endpoint: ai_env_cli::bridge::s3::S3Endpoint::Lab(rig.s3().addr()) };
        let mut m = Manifest::new(&sid, &target, ORIGIN_VM, &format!("{slug}/{sid}.jsonl"), "2026-10-18T09:00:00.000Z");
        m.parts.push(ManifestPart { key: base.clone(), version_id: "fv1".into(), from: 0, len: 70 << 20, sha256: "a".repeat(64) });
        (m.gen, m.committed, m.fp) = (1, 70 << 20, "b".repeat(64));
        manifest::write(&paths, &m).expect("the chat's manifest");
        // P0: no VM of the workspace yet.
        let (before, calls) = (rig.decrypts(), rig.fake_calls().len());
        let out = common::bounded::run_within(rig.wrapper(&[&resume], &[]), None, common::remote::LIMIT, "the wrapper");
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(9), "{err}");
        assert_eq!(last_line(&err), line, "{err}");
        assert_eq!((rig.decrypts(), rig.fake_calls().len()), (before, calls), "no Touch ID, no AWS call");
        assert_eq!(failed(rig), [["precheck", "9", "transcript_pull_too_large", ""].map(str::to_string)]);
        // A VM of the workspace lives, holding nothing of the chat: P0 cannot tell.
        rig.start_vm();
    }
    let before = p.rig().decrypts();
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1")]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(9), "{}", h.transcript());
    let err = h.err_text();
    assert_eq!(last_line(&err), line, "{err}");
    let rig = h.rig();
    assert_eq!(rig.decrypts() - before, 1, "P1's Touch ID");
    let vm = h.audit_events("vm_select")[0]["detail"]["id"].as_str().expect("the VM P2 took").to_string();
    assert_eq!(failed(rig)[1], ["workspace", "9", "transcript_pull_too_large", vm.as_str()].map(str::to_string));
    assert!(audit_rows(rig, "transcript_pull").is_empty() && h.audit_events("session_remote_start").is_empty(), "nothing pulled, nothing spawned");
    assert!(!rig.s3().requests().iter().any(|q| q.key == base), "no part asked of S3: {:?}", rig.s3().requests());
    assert!(!rig.vm_projects().join(&slug).join(format!("{sid}.jsonl")).exists(), "nothing of the chat in the VM");
}

/// S9 R5-AWS-1 with `[vm] reuse_per_workspace = false`: every reopen starts
/// a new VM, which holds nothing, and `session stage --warm` would warm yet
/// another, so the refusal's line asks for the switch first. At P0 when the
/// committed parts alone are over the cap, though a VM of the workspace
/// runs: no Touch ID, no AWS call. At P3 when a last tail takes the chat
/// past it (P0 sees no tail): after the Touch ID and the new VM's start, no
/// object asked of S3, nothing pulled.
#[test]
fn with_reuse_off_a_reopen_over_what_it_pulls_inline_names_the_switch() {
    use ai_env_cli::bridge::s3::manifest::{self, Manifest, ManifestPart, ORIGIN_VM};
    use ai_env_cli::wire::s3::{S3Key, INLINE_MAX};
    let mut p = Harness::prepare();
    add_config(p.rig(), "[vm]\nreuse_per_workspace = false\n");
    let sid = common::uuid(0x9105);
    let slug = p.slug();
    let resume = format!("--resume={sid}");
    let base = S3Key::Base { session: sid.clone(), gen: 1 }.render();
    let tail_key = S3Key::Tail { session: sid.clone(), gen: 1, offset: INLINE_MAX }.render();
    let switch = format!(", and [vm] reuse_per_workspace is off: set it to true, run ai-env session stage {sid} --warm in a terminal, then reopen the chat");
    // A manifest of one base of `len` bytes; nothing of it is in the rig's S3.
    let manifest_of = |rig: &common::remote::RemoteRig, len: u64| {
        let target = ai_env_cli::bridge::s3::S3Target { bucket: ai_env_cli::bridge::s3::LAB_BUCKET.into(), owner: ai_env_cli::bridge::s3::LAB_OWNER.into(), endpoint: ai_env_cli::bridge::s3::S3Endpoint::Lab(rig.s3().addr()) };
        let mut m = Manifest::new(&sid, &target, ORIGIN_VM, &format!("{slug}/{sid}.jsonl"), "2026-10-18T09:00:00.000Z");
        m.parts.push(ManifestPart { key: base.clone(), version_id: "fv1".into(), from: 0, len, sha256: "a".repeat(64) });
        (m.gen, m.committed, m.fp) = (1, len, "b".repeat(64));
        manifest::write(&ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None), &m).expect("the chat's manifest");
    };
    let started_by_hand = {
        let rig = p.rig();
        let vm = rig.start_vm();
        manifest_of(rig, 70 << 20);
        let (before, calls) = (rig.decrypts(), rig.fake_calls().len());
        let out = common::bounded::run_within(rig.wrapper(&[&resume], &[]), None, common::remote::LIMIT, "the wrapper");
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(9), "{err}");
        assert_eq!(last_line(&err), format!("ai-env-claude: the chat's transcript in S3 is 70.0 MiB, over the 64 MiB a reopen pulls inline{switch}"), "{err}");
        assert_eq!((rig.decrypts(), rig.fake_calls().len()), (before, calls), "P0: no Touch ID, no AWS call, though {vm} runs");
        // The parts at the cap, and a tail past it that a /suspend pushed.
        manifest_of(rig, INLINE_MAX);
        rig.s3().put(&tail_key, format!("{}\n", serde_json::json!({"type": "user", "sessionId": sid, "message": {"role": "user", "content": "after the last sync"}})).as_bytes());
        vm
    };
    let before = p.rig().decrypts();
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1")]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(9), "{}", h.transcript());
    let err = h.err_text();
    assert!(last_line(&err).ends_with(&format!(" a reopen pulls inline{switch}")), "P3: {err}");
    let rig = h.rig();
    assert_eq!(rig.decrypts() - before, 1, "P1's Touch ID");
    let selects = h.audit_events("vm_select");
    let select = &selects[0]["detail"];
    let vm = select["id"].as_str().expect("the VM P2 took").to_string();
    assert_eq!(select["how"].as_str(), Some("started"), "reuse off: a new VM, never {started_by_hand}: {select}");
    let failed: Vec<[String; 4]> = audit_rows(rig, "session_remote_failed").iter().map(|r| ["step", "code", "why", "id"].map(|k| r["detail"][k].as_str().unwrap_or_default().to_string())).collect();
    assert_eq!(failed.last(), Some(&["workspace", "9", "transcript_pull_too_large", vm.as_str()].map(str::to_string)), "{failed:?}");
    assert!(audit_rows(rig, "transcript_pull").is_empty() && h.audit_events("session_remote_start").is_empty(), "nothing pulled, nothing spawned");
    assert!(!rig.s3().requests().iter().any(|q| q.key == base || q.key == tail_key), "no object asked of S3: {:?}", rig.s3().requests());
}

/// R5-AWS-1: a chat begun on a VM that the rig's S3 holds whole, past what
/// a reopen pulls inline: generation 1's base of `INLINE_MAX` bytes (64
/// lines of 1 MiB) committed in the manifest (P0's cap on the parts alone
/// passes it), and a tail of one line past it that its VM's `/suspend`
/// pushed. The base's and the tail's bytes.
fn chat_past_the_cap_in_s3(rig: &common::remote::RemoteRig, sid: &str, slug: &str) -> (Vec<u8>, Vec<u8>) {
    use ai_env_cli::bridge::s3::manifest::{self, Manifest, ManifestPart, ORIGIN_VM};
    use ai_env_cli::wire::s3::{S3Key, FP_SPAN, INLINE_MAX};
    let mut chat = vec![b'x'; usize::try_from(INLINE_MAX).unwrap()];
    for end in (1..=64).map(|i| i * (1 << 20) - 1) {
        chat[end] = b'\n';
    }
    let tail = format!("{}\n", serde_json::json!({"type": "user", "sessionId": sid, "message": {"role": "user", "content": "after the last sync"}})).into_bytes();
    let base = S3Key::Base { session: sid.to_string(), gen: 1 }.render();
    let version = rig.s3().put(&base, &chat);
    let sha256 = rig.s3().objects().into_iter().find(|o| o.key == base && o.version_id == version).expect("the base in S3").sha256;
    rig.s3().put(&S3Key::Tail { session: sid.to_string(), gen: 1, offset: INLINE_MAX }.render(), &tail);
    let target = ai_env_cli::bridge::s3::S3Target { bucket: ai_env_cli::bridge::s3::LAB_BUCKET.into(), owner: ai_env_cli::bridge::s3::LAB_OWNER.into(), endpoint: ai_env_cli::bridge::s3::S3Endpoint::Lab(rig.s3().addr()) };
    let mut m = Manifest::new(sid, &target, ORIGIN_VM, &format!("{slug}/{sid}.jsonl"), "2026-10-18T09:00:00.000Z");
    let fp = sha256_of(&chat[chat.len() - usize::try_from(FP_SPAN).unwrap()..]);
    m.parts.push(ManifestPart { key: base, version_id: version, from: 0, len: INLINE_MAX, sha256 });
    (m.gen, m.committed, m.fp) = (1, INLINE_MAX, fp);
    manifest::write(&ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None), &m).expect("the chat's manifest");
    (chat, tail)
}

/// S9 R5-AWS-1, the way end to end: a chat begun on a VM, its VM gone, S3
/// holding it whole past what a reopen pulls inline. Its reopen is refused
/// at P3 (the parts alone pass P0; the VM P2 started holds nothing): exit
/// 9, the line naming `ai-env session stage UUID --warm`. That command (a
/// chat begun on a VM: nothing staged, its registry row's cwd the
/// workspace) costs the warm's Touch ID alone and restores the chat into
/// the workspace's VM with no deadline, every byte (`already`, `restore`
/// `restored`). The reopen then takes that VM and keeps the chat
/// (`transcript:kept`, no other pull), the CLI resuming from it.
#[test]
fn a_chat_past_the_cap_reopens_after_session_stage_warm() {
    use ai_env_cli::bridge::registry::{self, SessionRow, REGISTRY_SCHEMA_V};
    let mut p = Harness::prepare();
    let sid = common::uuid(0x9104);
    let slug = p.slug();
    let (chat, tail) = {
        let rig = p.rig();
        let now = registry::now_rfc3339();
        let row = SessionRow {
            v: REGISTRY_SCHEMA_V,
            session_id: sid.clone(),
            slug: Some(slug.clone()),
            cwd: Some(rig.work().display().to_string()),
            created: now.clone(),
            last_seen: now,
            status: "closed".into(),
            mode: "remote".into(),
            route: "remote".into(),
            exit: Some(0),
            transcript_home: Some(ai_env_cli::bridge::s3::manifest::HOME_S3.into()),
            ..SessionRow::default()
        };
        registry::write(&ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None), &row).expect("the session's registry row");
        chat_past_the_cap_in_s3(rig, &sid, &slug)
    };
    let all = chat.len() + tail.len();
    let resume = format!("--resume={sid}");
    let mut first = p.spawn_on(common::Link::Remote, "", &[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1")]);
    first.send_initialize();
    let (status, _) = first.wait(EXIT);
    assert_eq!(status.code(), Some(9), "{}", first.transcript());
    let err = first.err_text();
    assert!(last_line(&err).ends_with(&format!(" a reopen pulls inline: run ai-env session stage {sid} --warm in a terminal, then reopen the chat")), "{err}");
    let rig = first.rig();
    let before = rig.decrypts();
    let o = rig.run(&["session", "stage", &sid, "--warm", "--json"], None);
    assert!(o.status.success(), "session stage --warm: {}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(rig.decrypts() - before, 1, "the warm's Touch ID alone: nothing staged, the restore asks none");
    let doc: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("one JSON document ({e}): {}", String::from_utf8_lossy(&o.stdout)));
    let vm = doc["restore"]["vm"].as_str().unwrap_or_else(|| panic!("the warmed VM: {doc}")).to_string();
    assert_eq!((doc["outcome"].as_str(), doc["restore"]["outcome"].as_str(), doc["restore"]["bytes"].as_u64()), (Some("already"), Some("restored"), Some(all as u64)), "{doc}");
    let held = std::fs::read(rig.vm_projects().join(&slug).join(format!("{sid}.jsonl"))).expect("the VM's copy");
    assert!(held.len() == all && held.starts_with(&chat) && held.ends_with(&tail), "the base, then the tail: {} bytes", held.len());
    let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1")]));
    let init = started(&mut second);
    assert_eq!(init["session_id"].as_str(), Some(sid.as_str()), "{init}");
    closed(&mut second);
    let note = end_note_of(&first, second.pid());
    assert_eq!((part_of(&note, "vm"), part_of(&note, "transcript")), (Some(vm), Some("kept".into())), "{note}");
    assert_eq!(audit_rows(rig, "transcript_pull").len(), 1, "the warm's pull alone");
    assert!(first.env_log().iter().any(|l| l == "gen 1 resumed lines=65"), "the CLI resumed from the VM's copy: {:?}", first.env_log());
}

/// S9 R5-AWS-1 (c): a resume miss's retry pulls whatever the size (its
/// restore has no deadline of its own; the generation's own bound aside).
/// A chat S3 holds ([`chat_past_the_cap_in_s3`]), more than generation 1's
/// P3 would pull. Generation 1 restores nothing
/// (`AI_ENV_BRIDGE_LAB_TRANSCRIPT=skip`) and its CLI misses after
/// `initialize`; the retry pulls the whole chat into the VM, every byte (one
/// `transcript_pull` row, written, two parts), and the CLI resumes from it
/// (`transcript:restored`). A debug build hashes 64 MiB in some seconds.
#[test]
fn a_resume_miss_retry_pulls_a_chat_over_the_inline_cap() {
    use ai_env_cli::wire::s3::INLINE_MAX;
    let mut p = Harness::prepare();
    let sid = common::uuid(0x9103);
    let slug = p.slug();
    let (chat, tail) = chat_past_the_cap_in_s3(p.rig(), &sid, &slug);
    let resume = format!("--resume={sid}");
    let knobs = [("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_RESUME_FAIL_AFTER_ACK", "1"), ("AI_ENV_BRIDGE_LAB_TRANSCRIPT", "skip")];
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &knobs);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    let u = h.send_user("after the miss");
    h.expect_out(|v| is_result_for(v, &u), T);
    closed(&mut h);
    let resumed: Vec<String> = h.env_log().into_iter().filter(|l| l.contains("resumed")).collect();
    assert_eq!(resumed, ["gen 1 resumed lines=missing".to_string(), "gen 2 resumed lines=65".to_string()], "the retry's CLI found the whole chat");
    let pulls = h.audit_events("transcript_pull");
    assert_eq!(pulls.len(), 1, "{pulls:?}");
    let d = &pulls[0]["detail"];
    let all = INLINE_MAX + tail.len() as u64;
    assert_eq!((d["outcome"].as_str(), d["parts"].as_str(), d["bytes"].as_str()), (Some("written"), Some("2"), Some(all.to_string().as_str())), "{d}");
    let held = std::fs::read(h.rig().vm_projects().join(&slug).join(format!("{sid}.jsonl"))).expect("the VM's copy");
    assert!(held.len() as u64 == all && held.starts_with(&chat) && held.ends_with(&tail), "the base, then the tail: {} bytes", held.len());
    assert!(common::note_has(&h.end_note(), "transcript:restored"), "{}", h.end_note());
}

/// T8.5's VM gone mid-session, S10's form: once the VM is terminated (`vm
/// terminate`; the platform's `/terminate`) the session's socket ends with
/// the hook's event and the chat moves (§A): with no turn in flight it waits
/// for the next line (L5, the note saying so), which is then answered on a
/// new VM (one RunMicrovm, one Touch ID for the setup token, `why`
/// `readdress:vm_gone`), and the session closes 0, its census counting the
/// move. L6 stays: `/terminate` takes no snapshot (the VM's disk dies with
/// it), so an edit made after the last fetch is in no new `refs/wip/*` and
/// on no new VM, whose carry seed came from the last fetch's record or,
/// without one, this Mac (`seed` `source`). S9's name was
/// `a_terminated_vm_mid_session_exits_8_naming_the_picker`.
#[test]
fn a_terminated_vm_mid_session_moves_with_the_next_line() {
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_WIP_EDIT", "agent.txt:from the VM, not committed")]);
    started(&mut h);
    turn(&mut h, "hello");
    wait_for_fetch(h.rig());
    let starts = h.audit_events("session_remote_start");
    let vm = starts[0]["detail"]["id"].as_str().expect("the VM").to_string();
    let rig = h.rig();
    let vm_dir = rig.vm_path(&rig.work());
    let wips = || git_in(&vm_dir, &["for-each-ref", "--format=%(refname)", "refs/wip/"]);
    let before = wips();
    assert!(!before.is_empty(), "the turn's code-out snapshot");
    std::fs::write(vm_dir.join("late.txt"), "after the last fetch\n").expect("write late.txt in the VM");
    let o = rig.run(&["vm", "terminate", &vm, "--yes"], None);
    assert!(o.status.success(), "vm terminate: {}", String::from_utf8_lossy(&o.stderr));
    // After the command's own Touch ID.
    let (runs_before, decrypts_before) = (runs(rig), rig.decrypts());
    h.expect_out(|v| v["subtype"] == "informational" && v["content"].as_str().is_some_and(|c| c.contains(&vm) && c.contains("with your next message")), T);
    turn(&mut h, "after the terminate");
    let starts = h.audit_events("session_remote_start");
    assert_eq!(starts.len(), 2, "{starts:?}");
    let moved = starts[1]["detail"]["id"].as_str().expect("the new VM").to_string();
    assert_ne!(moved, vm, "a new VM");
    assert_eq!(starts[1]["detail"]["why"].as_str(), Some("readdress:vm_gone"));
    let rig = h.rig();
    assert_eq!((runs(rig) - runs_before, rig.decrypts() - decrypts_before), (1, 1), "one RunMicrovm, one Touch ID");
    closed(&mut h);
    let note = h.end_note();
    assert!(common::note_has(&note, "moves:readdress=1,respawn=0,migrate=0"), "{note}");
    let rig = h.rig();
    assert!(rig.endpoint.hooks().iter().any(|k| k.vm == vm && k.name == "terminate" && k.status == 200), "{:?}", rig.endpoint.hooks());
    assert_eq!(wips(), before, "no snapshot at /terminate (L6)");
    let moved_dir = rig.vm_path_of(&moved, &rig.work());
    assert!(!moved_dir.join("late.txt").exists(), "an edit after the last fetch is on no new VM (L6)");
    let seeds = h.audit_events("seed");
    let carry = seeds.iter().find(|r| r["detail"]["vm"] == moved.as_str()).unwrap_or_else(|| panic!("the new VM's seed: {seeds:?}"));
    assert!(matches!(carry["detail"]["source"].as_str(), Some("box" | "mac")), "{carry}");
    // S10 (FK-8): the move left nothing on either VM.
    h.assert_vm_empty();
}

/// S9 (review CUT-5): before this Mac terminates a VM itself (`vm
/// terminate ID`, or `--all`), it syncs each session whose transcript S3
/// keeps there (`s3::commands::sync_before_terminate`). A line the VM's
/// claude wrote after the turn's sync (here appended to its copy, as a
/// summary written after the result) is committed to the manifest and held
/// in S3 byte for byte before the VM ends, with no warning. The shim's
/// `/terminate` tail push never moves the manifest's `committed`, so only
/// that sync passes this. The session then loses its VM, and (S10) its next
/// line is served on a new VM whose restore pulls that sync's commit.
#[test]
fn vm_terminate_syncs_a_live_sessions_transcript_to_s3_first() {
    terminate_syncs_the_transcript_first(false);
}

/// S9 (review CUT-5): `vm terminate --all --yes` syncs each target's
/// sessions first, as `vm terminate ID` does. (S10: the host then closes
/// while the chat waits for its next line: exit 0, nothing moved.)
#[test]
fn vm_terminate_all_syncs_each_live_sessions_transcript_to_s3_first() {
    terminate_syncs_the_transcript_first(true);
}

/// One session with a turn synced, a line on the VM after it, then `vm
/// terminate` (`all`: `--all`) as the two tests above say.
fn terminate_syncs_the_transcript_first(all: bool) {
    use std::io::Write as _;
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_WRITE_TRANSCRIPT", "1")]);
    let sid = started(&mut h)["session_id"].as_str().expect("the session id").to_string();
    turn(&mut h, "hello");
    // The turn's code-out and transcript step done: nothing of the session's own trigger still on its way.
    synced(&mut h, &sid, 1);
    let vm = h.audit_events("session_remote_start")[0]["detail"]["id"].as_str().expect("the VM").to_string();
    let vm_copy = h.rig().vm_projects().join(h.slug()).join(format!("{sid}.jsonl"));
    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(h.rig().bridge(), None);
    let committed = || ai_env_cli::bridge::s3::manifest::read(&paths, &sid).unwrap().unwrap_or_else(|| panic!("no manifest of {sid}")).committed;
    let at_turn = committed();
    assert_eq!(at_turn, std::fs::metadata(&vm_copy).expect("the VM's copy").len(), "the turn's sync committed the VM's copy");
    // What the VM's claude writes after the turn's sync: on the VM's disk alone.
    let last: Value = serde_json::from_str(read(&vm_copy).lines().last().expect("the turn's entries")).expect("a transcript line");
    let late = format!(r#"{{"type":"summary","summary":"written after the turn's sync","leafUuid":"{}"}}"#, last["uuid"].as_str().expect("its uuid"));
    let mut f = std::fs::OpenOptions::new().append(true).open(&vm_copy).expect("open the VM's transcript");
    writeln!(f, "{late}").expect("append the late line");
    drop(f);
    let held = std::fs::read(&vm_copy).expect("the VM's copy");
    let args = if all { vec!["vm", "terminate", "--all", "--yes"] } else { vec!["vm", "terminate", vm.as_str(), "--yes"] };
    let o = h.rig().run(&args, None);
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(o.status.success(), "vm terminate: {stderr}");
    assert!(String::from_utf8_lossy(&o.stdout).contains(&vm), "the session's VM terminated: {}", String::from_utf8_lossy(&o.stdout));
    assert!(!stderr.contains("not synced"), "the sync before the terminate warned: {stderr}");
    let now = committed();
    assert!(now > at_turn && now == held.len() as u64, "committed {now} of the VM's {} bytes (the turn's sync: {at_turn})", held.len());
    assert_eq!(held_in_s3(h.rig(), &sid), held, "S3 holds the VM's copy, the late line too");
    // S10 (§A, L5): the chat waits for its next line, served on a new VM; or the host closes meanwhile, exit 0.
    h.expect_out(|v| v["subtype"] == "informational" && v["content"].as_str().is_some_and(|c| c.contains(&vm) && c.contains("with your next message")), T);
    if all {
        closed(&mut h);
        assert_eq!(h.audit_events("session_remote_start").len(), 1, "a close moves nothing");
        return;
    }
    turn(&mut h, "after the terminate");
    let starts = h.audit_events("session_remote_start");
    let moved = starts.last().and_then(|r| r["detail"]["id"].as_str()).expect("the new VM").to_string();
    assert_ne!(moved, vm, "a new VM: {starts:?}");
    let copy = std::fs::read(h.rig().vm_projects_of(&moved).join(h.slug()).join(format!("{sid}.jsonl"))).expect("the new VM's copy");
    assert!(copy.len() > held.len() && copy.starts_with(&held), "the restore pulled what the sync committed, the late line too");
    closed(&mut h);
}

/// S9 round 5 (R1): `vm terminate` never wakes a VM the chat's closing
/// suspend left SUSPENDED to sync it first. After the host's EOF the CLI
/// writes one more line, which that suspend's `/suspend` pushed as the tail
/// (`g1/t/<committed>`, through the URL the turn's sync handed). S10 (R1,
/// the chain): the chat reopened on that VM (resumed, its copy kept) is
/// handed the chain's next tail, where the first one ends (the manifest
/// records it), so the line its CLI writes after the host's EOF reaches S3
/// through it at the next suspend, where S9 lost it to a 412. `vm terminate`
/// then ends the VM with no request to it: no `/resume` (the platform's
/// auto-resume), no warning, the manifest's commit as the turn's sync left
/// it, and S3 still holding both tails, byte for byte. A reopen on a new VM
/// restores the chain: the turn's base, then both tails, the CLI resuming
/// from all of it.
#[test]
fn vm_terminate_never_wakes_a_suspended_vm_to_sync_it() {
    use ai_env_cli::bridge::api::VmState;
    let knobs = [("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_FINAL_MIRROR_MS", "200"), ("FAKE_EXIT_DELAY_MS", "400")];
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &knobs);
    let sid = started(&mut h)["session_id"].as_str().expect("the session id").to_string();
    turn(&mut h, "hello");
    synced(&mut h, &sid, 1);
    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(h.rig().bridge(), None);
    let manifest = || ai_env_cli::bridge::s3::manifest::read(&paths, &sid).unwrap().unwrap_or_else(|| panic!("no manifest of {sid}"));
    let at_turn = manifest();
    closed(&mut h);
    let vm = h.audit_events("session_remote_start")[0]["detail"]["id"].as_str().expect("the VM").to_string();
    let vm_copy = h.rig().vm_projects().join(h.slug()).join(format!("{sid}.jsonl"));
    let written = std::fs::read(&vm_copy).expect("the VM's copy");
    assert!(written.len() as u64 > at_turn.committed, "the CLI wrote on after the turn's sync");
    let late = written[usize::try_from(at_turn.committed).unwrap()..].to_vec();
    let rig = h.rig();
    let suspended = || rig.fake().vms.get(&vm).is_some_and(|v| v.state == VmState::Suspended);
    wait_for("the VM suspended in the fake", Duration::from_secs(10), suspended);
    let tail = |from: u64| ai_env_cli::wire::s3::S3Key::Tail { session: sid.clone(), gen: at_turn.tail_gen(), offset: from }.render();
    let first = tail(at_turn.committed);
    wait_for("the tail /suspend pushed", T, || rig.s3().get(&first).is_some());
    assert_eq!(rig.s3().get(&first).as_deref(), Some(late.as_slice()), "the tail is what the CLI wrote after the sync");
    // The chat reopened on its VM: the chain's next tail, at the end of the first, handed and recorded.
    let next = tail(at_turn.committed + late.len() as u64);
    let resume = format!("--resume={sid}");
    let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &[("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_FINAL_MIRROR_MS", "200"), ("FAKE_EXIT_DELAY_MS", "400"), ("FAKE_RESUME_NEEDS_FILE", "1")]));
    assert_eq!(started(&mut second)["session_id"].as_str(), Some(sid.as_str()), "the same session");
    wait_for("the reopen's tail handed past the first and recorded", T, || manifest().tails.iter().any(|t| t.key == next));
    closed(&mut second);
    assert_eq!(part_of(&end_note_of(&h, second.pid()), "transcript").as_deref(), Some("kept"), "its VM held the chat");
    wait_for("the VM suspended again", Duration::from_secs(10), suspended);
    let written = std::fs::read(&vm_copy).expect("the VM's copy");
    let later = written[usize::try_from(at_turn.committed).unwrap() + late.len()..].to_vec();
    assert!(!later.is_empty(), "the reopened CLI wrote on after the host's EOF");
    wait_for("the next tail /suspend pushed", T, || rig.s3().get(&next).is_some());
    assert_eq!(rig.s3().get(&next).as_deref(), Some(later.as_slice()), "the line written after the first tail reached S3 through the next");
    let resumes = rig.endpoint.resumes();
    let o = rig.run(&["vm", "terminate", &vm, "--yes"], None);
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(o.status.success(), "vm terminate: {stderr}");
    assert!(!stderr.contains("not synced"), "{stderr}");
    assert_eq!(rig.endpoint.resumes(), resumes, "no request resumed the VM: {:?}", rig.endpoint.hooks());
    assert!(rig.fake().vms.get(&vm).is_some_and(|v| v.state.is_terminal()), "the VM ended");
    let now = manifest();
    assert_eq!((now.gen, now.committed, &now.parts, &now.fp), (at_turn.gen, at_turn.committed, &at_turn.parts, &at_turn.fp), "no sync ran");
    assert_eq!(now.tails.iter().map(|t| t.key.clone()).collect::<Vec<_>>(), [first.clone(), next.clone()], "the tails this Mac handed, recorded");
    assert_eq!((rig.s3().get(&first), rig.s3().get(&next)), (Some(late), Some(later)), "both tails stay in S3");
    // The chat reopened on a new VM: the turn's base, then the chain.
    let mut third = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &[("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_RESUME_NEEDS_FILE", "1")]));
    assert_eq!(started(&mut third)["session_id"].as_str(), Some(sid.as_str()), "the same session, resumed from the restored copy");
    let new_vm = rig.newest_vm().expect("the reopen's VM");
    assert_ne!(new_vm, vm, "a new VM");
    let restored = std::fs::read(rig.vm_projects_of(&new_vm).join(h.slug()).join(format!("{sid}.jsonl"))).expect("the new VM's copy");
    assert_eq!(restored, written, "the base, then both tails");
    let pull = audit_rows(rig, "transcript_pull");
    let pull = pull.last().expect("the restore's pull");
    assert_eq!((pull["detail"]["outcome"].as_str(), pull["detail"]["parts"].as_str()), (Some("written"), Some((at_turn.parts.len() + 2).to_string().as_str())), "{pull}");
    closed(&mut third);
}

/// T8.6 offline: the endpoint cuts every connection mid-turn (the turn's
/// stream held back by the host, its lines past the shim's window). The
/// session reattaches by itself and replays from its last mark: every line
/// arrives once, in order, the turn's result after them within B8's 30 s,
/// and the census counts one link drop.
#[test]
fn an_endpoint_cut_mid_turn_reattaches_within_budget() {
    const LINES: usize = 200;
    let (lines, pad) = (LINES.to_string(), (64 * 1024).to_string());
    let knobs = [("FAKE_INIT_AT_TURN", "1"), ("FAKE_STREAM_LINES", lines.as_str()), ("FAKE_STREAM_PAD", pad.as_str())];
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &knobs);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    // The turn's stream comes with its init (FAKE_INIT_AT_TURN): held back by the host, then cut.
    let u = h.send_user("stream");
    let streamed = |h: &Harness| h.seen_out.iter().filter(|l| l.starts_with(r#"{"type":"stream_event""#)).count();
    h.wait_until("the turn's first lines", T, |h| streamed(h) >= 10);
    h.pause_stdout();
    std::thread::sleep(Duration::from_millis(300));
    h.drain();
    assert!(streamed(&h) < LINES && !h.seen_out.iter().any(|l| l.starts_with(r#"{"type":"result""#)), "the cut comes mid-turn: {} lines seen", streamed(&h));
    h.rig().endpoint.cut_all();
    let cut = std::time::Instant::now();
    h.resume_stdout();
    h.expect_out(|v| is_result_for(v, &u), T);
    assert!(cut.elapsed() < Duration::from_secs(30), "the turn went on within 30 s of the cut: {:?}", cut.elapsed());
    let ns: Vec<u64> = h.out_json().iter().filter(|v| v["type"] == "stream_event").filter_map(|v| v["n"].as_u64()).collect();
    assert!(ns == (1..=LINES as u64).collect::<Vec<_>>(), "every line once, in order: {} lines", ns.len());
    assert_eq!(h.out_matching(is_init).len(), 1, "one init");
    closed(&mut h);
    assert!(common::note_has(&h.end_note(), "link_drops:1"), "{}", h.end_note());
    assert!(!h.audit_events("agent_reconnect").is_empty(), "the reattach audited");
}

/// T8.6 offline: a symlink planted in the VM at a component of the
/// workspace's path (the identical path, under the agent's home) is never
/// followed: the seed is refused with 409 `symlink_component`, and both
/// lines say what it is and what to do (remove it in the VM, or terminate
/// the VM and seed a new one): `box seed`'s for the operator, with the path,
/// and the wrapper's one line for Cursor (exit 9), whose cut (300
/// characters) takes the path's end, never the remedy. Nothing was written
/// through the link.
#[test]
fn a_symlinked_component_is_409_with_an_explanation() {
    use ai_env_cli::bridge::remote::LINE_MAX;
    let mut p = Harness::prepare();
    let (work, vm_dir, elsewhere) = {
        let rig = p.rig();
        rig.start_vm();
        let (work, vm_dir, elsewhere) = (rig.work(), rig.vm_path(&rig.work()), rig.vm_home().join("elsewhere"));
        std::fs::create_dir_all(&elsewhere).expect("mkdir the link's target");
        std::os::unix::fs::symlink(&elsewhere, &vm_dir).expect("plant the symlink in the VM");
        (work, vm_dir, elsewhere)
    };
    let explanation = "a component of the workspace path is a symlink, which the VM never follows: remove it in the VM, or terminate the VM and seed a new one";
    let o = p.rig().run(&["box", "seed", &work.display().to_string()], None);
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(9), "{err}");
    let whole = format!("{explanation} ({})", work.display());
    assert!(err.lines().any(|l| l.starts_with("ai-env: ") && l.contains("symlink_component") && l.contains(&whole)), "box seed: {err}");
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &[]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(9), "{}", h.transcript());
    let err = h.err_text();
    let last = last_line(&err);
    assert!(last.starts_with("ai-env-claude: workspace refused (symlink_component): ") && last.contains(explanation), "Cursor's line: {err}");
    assert!(last.chars().count() <= LINE_MAX, "{last}");
    assert!(vm_dir.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink()), "the link as planted");
    assert!(names_in(&elsewhere).is_empty(), "nothing written through the link");
}

/// T8.6 offline (D6's non-ASCII case): a git workspace at a Cyrillic path
/// written in NFD on the Mac (as macOS can hand it out) is seeded at its NFC
/// form, the only form the VM is sent (the VM's directory entry is NFC, the
/// Mac's stays NFD), and the chat of the CLI there (`FAKE_CWD` the NFC
/// path) has its view on the Mac under one slug (S9: its transcript in S3):
/// the NFC path's, the one Cursor's picker reads. That the spawn's cwd is the NFC path is the
/// pipeline's unit test (`the_spawn_runs_at_the_vm_path_never_the_macs_spelling`):
/// the rig's VM disk is APFS, where either spelling finds the seeded directory.
#[test]
fn an_nfd_workspace_path_is_seeded_at_its_nfc_form_and_viewed_under_one_slug() {
    // Й as И + U+0306 (NFD); the NFC form is the precomposed Й.
    let (nfd, nfc) = ("\u{0418}\u{0306}\u{043e}\u{0433}\u{0430}", "\u{0419}\u{043e}\u{0433}\u{0430}");
    let mut p = Harness::prepare();
    let (cmd, dir, vm_cwd) = {
        let rig = p.rig();
        let dir = rig.work().join(nfd);
        std::fs::create_dir(&dir).expect("mkdir the NFD workspace");
        git_in(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("notes.txt"), "a Cyrillic workspace\n").expect("write notes.txt");
        git_in(&dir, &["add", "notes.txt"]);
        git_in(&dir, &["-c", "user.name=fixture", "-c", "user.email=fixture@ai-env.invalid", "commit", "-q", "-m", "one"]);
        let vm_cwd = format!("{}/{nfc}", rig.work().display());
        let mut cmd = rig.wrapper(&[], &[("FAKE_CWD", vm_cwd.as_str()), ("FAKE_WRITE_TRANSCRIPT", "1")]);
        cmd.current_dir(&dir);
        (cmd, dir, vm_cwd)
    };
    let mut h = p.launch_wrapper(cmd);
    started(&mut h);
    turn(&mut h, "hello");
    synced(&mut h, &common::fake_fixed_sid(), 1);
    closed(&mut h);
    let rig = h.rig();
    assert_eq!(names_in(&rig.vm_path(&rig.work())), [nfc], "the VM's entry is the NFC name");
    assert!(names_in(&rig.work()).contains(&nfd.to_string()), "the Mac's entry stays NFD");
    let vm_dir = rig.vm_path(Path::new(&vm_cwd));
    assert_eq!(git_in(&vm_dir, &["rev-parse", "HEAD"]), git_in(&dir, &["rev-parse", "HEAD"]), "seeded");
    let slug = ai_env_cli::wire::slug::slug_of(&vm_cwd);
    assert_ne!(slug, ai_env_cli::wire::slug::slug_of(&format!("{}/{nfd}", rig.work().display())), "the two spellings' slugs differ");
    let mac_projects = h.prepared.mac_projects();
    assert_eq!(names_in(&mac_projects), std::slice::from_ref(&slug), "one slug on the Mac, the NFC path's");
    let file = format!("{}.jsonl", common::fake_fixed_sid());
    assert_eq!(names_in(&mac_projects.join(&slug)), std::slice::from_ref(&file), "the chat's view alone");
    assert!(is_view(&mac_projects.join(&slug).join(&file)), "the view, never the transcript");
    assert_eq!(held_in_s3(rig, &common::fake_fixed_sid()), std::fs::read(rig.vm_projects().join(&slug).join(&file)).unwrap(), "the transcript in S3, from the VM's NFC slug");
    let note = h.end_note();
    assert!(common::note_has(&note, "seed:seeded") && common::note_has(&note, "mirror:0/0"), "{note}");
}

/// FAKE_ENV_DUMP writes `--- gen <n>`, then every variable the fake started
/// with, sorted, but its knobs file's and the shell's own; FAKE_VERSION is
/// what `--version` alone prints.
#[test]
fn the_fake_dumps_its_environment_and_names_another_version() {
    let f = Fake::new();
    let dump = f.root.join("env-dump.log");
    common::write_knobs(&f.root.join("claude.knobs"), &[("FAKE_ENV_DUMP", dump.to_str().expect("a UTF-8 path")), ("FAKE_VERSION", "2.1.297")]);
    let (code, out, err) = f.run(&["--version"], &[], "");
    assert_eq!((code, out), (Some(0), vec!["2.1.297 (Claude Code)".to_string()]), "{err}");
    let (code, _, err) = f.run(&[], &[("MY_FLAG", "on")], &format!("{INIT}\n"));
    assert_eq!(code, Some(0), "{err}");
    let names: Vec<String> = read(&dump).lines().map(|l| l.split('=').next().unwrap_or_default().to_string()).collect();
    assert_eq!(names, ["--- gen 1", "CLAUDE_CONFIG_DIR", "FAKE_ENV_LOG", "HOME", "MY_FLAG", "PATH"], "{}", read(&dump));
    assert!(read(&dump).lines().any(|l| l == "MY_FLAG=on"));
}

// ---- S8 wave 1, W2: `vm warm`'s S8 modes, on the rig today ---------------------------------
//
// `vm warm --dry-run` and the prewarm's `vm warm --prewarm` need no remote
// session: they run against the rig as it is, the warm's seed through W4's
// data plane.

/// The rig's workspace lock file `<slug>.<suffix>` (`state/workspaces`).
fn workspace_lock(rig: &common::remote::RemoteRig, suffix: &str) -> PathBuf {
    let slug = ai_env_cli::wire::slug::project_dir_name(&rig.work()).unwrap();
    rig.bridge().join("state").join("workspaces").join(format!("{slug}.{suffix}"))
}

/// The rig's audit rows of `event`.
fn audit_rows(rig: &common::remote::RemoteRig, event: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(rig.bridge().join("audit.jsonl")).unwrap_or_default();
    text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|r| r["event"] == event).collect()
}

/// S8 §11: `vm warm --dry-run` says what a warm would do (the seed or why
/// there is none, the VM the registry offers or a new one, the token's seal)
/// and does nothing: no AWS call, no Touch ID, no row.
#[test]
fn vm_warm_dry_run_says_its_plan_with_no_aws_call_and_no_touch_id() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work().display().to_string();
    let (before, calls, rows) = (rig.decrypts(), rig.fake_calls().len(), audit_rows(rig, "vm_run").len());
    let o = rig.run(&["vm", "warm", &work, "--dry-run"], None);
    let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert_eq!(o.status.code(), Some(0), "{err}");
    assert!(out.contains("the VM: a new one with vpc egress (image version "), "{out}");
    assert!(out.trim_end().ends_with("nothing was started: no AWS call, no Touch ID"), "{out}");
    assert_eq!((rig.decrypts(), rig.fake_calls().len(), audit_rows(rig, "vm_run").len()), (before, calls, rows), "no Touch ID, no AWS call, no row");
    // With the workspace's VM in the registry: offered for reuse, still nothing done.
    let vm = rig.start_vm();
    let (before, calls) = (rig.decrypts(), rig.fake_calls().len());
    let o = rig.run(&["vm", "warm", &work, "--dry-run", "--json"], None);
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("--json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
    assert_eq!((v["dry_run"].as_bool(), v["reuse"].as_str(), v["workspace"].as_str()), (Some(true), Some(vm.as_str()), Some(work.as_str())), "{v}");
    assert!(v["seed"].is_object() && v["tag"].as_str().is_some_and(|t| !t.is_empty()), "{v}");
    assert_eq!((rig.decrypts(), rig.fake_calls().len()), (before, calls), "no Touch ID, no AWS call");
}

/// S8 §11: `vm warm --prewarm` as the wrapper's prewarm starts it (the
/// workspace's warm lock, held, on fd 3): quiet (nothing on stdout, no note
/// on stderr: they go to the log), its run recorded in the lock (`pid=`,
/// `started_at=`, `finished_at=`), its S4 rows of purpose `prewarm`, one
/// Touch ID behind `state/unseal.lock` whose `age` holds no fd 3 and not the
/// warm lock (a child of the prewarm never keeps it), and the token
/// delivered: the next warm finds it held.
#[test]
fn vm_warm_prewarm_is_quiet_and_records_its_run_in_the_inherited_warm_lock() {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work().display().to_string();
    let lock_path = workspace_lock(rig, "warm.lock");
    std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
    let lock = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&lock_path).unwrap();
    // SAFETY: flock(2) on a descriptor this test owns.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0, "the wrapper's hold");
    let before = rig.decrypts();
    // The Touch ID's decrypt writes its pid and waits for the release: its descriptors are read meanwhile.
    let (age_pid, release) = (rig.root().join("age.pid"), rig.root().join("age.release"));
    let mut cmd = rig.ai_env(&["vm", "warm", &work, "--prewarm"]);
    cmd.env("FAKE_AGE_PIDFILE", &age_pid).env("FAKE_AGE_WAIT_FILE", &release);
    let fd = lock.as_raw_fd();
    // SAFETY: dup2(2) and fcntl(2) are async-signal-safe, and the closure allocates nothing between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            // fd 3 is the lock, open across the exec (a dup2 onto itself would keep its close-on-exec flag).
            let kept = if fd == 3 { libc::fcntl(3, libc::F_SETFD, 0) } else { libc::dup2(fd, 3) };
            if kept < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let t = std::time::Instant::now();
    let pid = loop {
        if let Some(pid) = std::fs::read_to_string(&age_pid).ok().filter(|s| s.ends_with('\n')) {
            break pid.trim().to_string();
        }
        assert!(t.elapsed() < Duration::from_secs(30), "the Touch ID's decrypt never started");
        std::thread::sleep(Duration::from_millis(25));
    };
    let lsof = std::process::Command::new("/usr/sbin/lsof").args(["-nP", "-a", "-p", &pid, "-d", "0-255", "-F", "fn"]).output().unwrap();
    std::fs::write(&release, "go").unwrap();
    let o = common::bounded::finish_within(child, common::remote::LIMIT, "vm warm --prewarm");
    let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert_eq!(o.status.code(), Some(0), "{err}");
    let mut age_fds = std::collections::BTreeMap::new();
    let mut at = None;
    for line in String::from_utf8_lossy(&lsof.stdout).lines() {
        if let Some(n) = line.strip_prefix('f') {
            at = n.parse::<u32>().ok();
        } else if let (Some(f), Some(name)) = (at, line.strip_prefix('n')) {
            age_fds.insert(f, name.to_string());
        }
    }
    assert!(age_fds.contains_key(&0), "lsof read the decrypt's descriptors: {}", String::from_utf8_lossy(&lsof.stderr));
    assert!(!age_fds.contains_key(&3) && !age_fds.values().any(|n| n.ends_with(".warm.lock")), "the prewarm's age inherited the warm lock: {age_fds:?}");
    // Its notes go to the log; stderr (the wrapper's prewarm hands it /dev/null) has the dialog's countdown at most.
    assert_eq!(out, "", "a prewarm prints nothing");
    assert!(err.lines().all(|l| l.starts_with("ai-env-claude: waiting for Touch ID to unseal ")), "no note, no ai-env: line: {err}");
    let record = read(&lock_path);
    let field = |k: &str| record.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')?.parse::<u64>().ok());
    let (pid, started, finished) = (field("pid"), field("started_at"), field("finished_at"));
    assert!(pid.is_some_and(|p| p > 1) && started.is_some() && finished >= started, "{record}");
    assert_eq!(rig.decrypts() - before, 1, "one Touch ID (combined.env)");
    assert!(rig.bridge().join("state").join("unseal.lock").exists(), "the dialog took the unseal lock");
    let runs = audit_rows(rig, "vm_run");
    assert!(!runs.is_empty() && runs.iter().all(|r| r["detail"]["purpose"] == "prewarm"), "{runs:?}");
    let log = read(&rig.bridge().join("logs").join("ai-env.log"));
    assert!(log.contains("prewarmed"), "the outcome is in the log: {log}");
    // The seed went in beside the token, through the data plane: the VM's checkout is the Mac's HEAD.
    let vm_head = Command::new(common::git_real()).args(["rev-parse", "HEAD"]).current_dir(rig.vm_path(&rig.work())).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&vm_head.stdout).trim(), rig.head(), "the prewarm seeded the workspace");
    drop(lock);
    let o = rig.run(&["vm", "warm", &work, "--json"], None);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("--json ({e}): {}", String::from_utf8_lossy(&o.stderr)));
    assert_eq!((v["reused"].as_bool(), v["warmed"].as_str(), v["seed"].as_str()), (Some(true), Some("already_held"), Some("up_to_date")), "{v}");
}

// ---- phase 4 F2: the transcript scan -----------------------------------------------------
//
// Review CUSTODY-2, after the S3 cut-over: a `--resume` of a chat begun on
// the Mac (or of an S8 mirror) sends its copy up to S3 inline, and a chat
// holds whatever its tools printed. Every file the inline upload would send
// goes through the seed's tripwires first: at P1, beside the Touch ID (a
// finding starts no VM and closes the dialog), and again as it goes up (the
// restore's `s3::stage::scan_chat`, the resume miss's retry too). A chat S3
// holds is never read on the Mac, so what its VM holds refuses nothing
// (review F2-R1). The lib's units (`bridge::workspace::transcript`,
// `bridge::s3::stage`) hold the rest.

/// A local chat's transcript line: a tool's result, `text`, to the prompt
/// `parent` of session `sid`.
fn tool_output(sid: &str, parent: &str, text: &str) -> String {
    format!(r#"{{"type":"user","uuid":"{}","parentUuid":"{parent}","sessionId":"{sid}","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"toolu_01","content":"{text}"}}]}}}}"#, common::uuid(0x8869))
}

/// CUSTODY-2: a chat that ran on the Mac (no registry row: passthrough, the
/// kill switch, a local child) reopened from the picker in remote mode, a
/// line its tools printed holding an AWS access key id: in the transcript,
/// or in a subagent's file alone. The wrapper refuses at P1, beside the
/// Touch ID (in the second case one that never answers, which the refusal
/// closes): exit 9, the last line naming `transcript:REL`, the line and the
/// rule, never the value; no VM started, nothing in the VM's projects dir
/// or in S3, one `seed_refused` (step `transcript`) and the pipeline's
/// `session_remote_failed`; the value nowhere under the bridge dir.
#[test]
fn a_local_chats_transcript_with_a_tripwire_is_refused_before_any_byte_leaves() {
    let key = format!("{}{}", "AKIA", "T".repeat(16));
    for subagent in [false, true] {
        let p = Harness::prepare();
        let (sid, parent) = (common::uuid(0x8860), common::uuid(0x8861));
        let prompt = format!(r#"{{"type":"user","uuid":"{parent}","sessionId":"{sid}","message":{{"role":"user","content":"show me the deploy config"}}}}"#);
        let printed = tool_output(&sid, &parent, &format!("aws_access_key_id = {key}"));
        let rel = if subagent {
            let reply = tool_output(&sid, &parent, "nothing to see");
            p.plant_transcript(&sid, &[prompt.as_str(), reply.as_str()]);
            let rel = format!("{sid}/subagents/agent-a1.jsonl");
            p.plant_project_file(&rel, &format!("{prompt}\n{printed}\n"));
            rel
        } else {
            p.plant_transcript(&sid, &[prompt.as_str(), printed.as_str()]);
            format!("{sid}.jsonl")
        };
        let pidfile = p.root.join("age.pid");
        let pidfile_s = pidfile.display().to_string();
        let resume = format!("--resume={sid}");
        let mut knobs = vec![("FAKE_RESUME_NEEDS_FILE", "1")];
        if subagent {
            knobs.extend([("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", pidfile_s.as_str())]);
        }
        let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &knobs);
        h.send_initialize();
        let (status, _) = h.wait(EXIT);
        assert_eq!(status.code(), Some(9), "{}", h.transcript());
        let err = h.err_text();
        assert!(last_line(&err).starts_with(&format!("ai-env-claude: the chat's transcript would carry transcript:{rel} line 2: rule aws-access-key-id")), "{err}");
        assert!(!err.contains(&key), "the value on stderr: {err}");
        let rig = h.rig();
        assert_eq!(runs(rig), 0, "refused at P1: no VM started");
        assert_eq!(files_under(&rig.vm_projects()), Vec::<String>::new(), "nothing in the VM's projects dir");
        assert!(rig.s3().requests().is_empty() && h.audit_events("transcript_stage").is_empty(), "nothing went up");
        let refused = h.audit_events("seed_refused");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!((refused[0]["detail"]["step"].as_str(), refused[0]["detail"]["code"].as_str()), (Some("transcript"), Some("finding")), "{refused:?}");
        let failed = h.audit_events("session_remote_failed");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!((failed[0]["detail"]["step"].as_str(), failed[0]["detail"]["code"].as_str(), failed[0]["detail"]["why"].as_str()), (Some("workspace"), Some("9"), Some("finding")));
        assert_eq!(holding(&[&h.bridge()], std::slice::from_ref(&key)), Vec::<String>::new(), "the value under the bridge dir");
        // The dialog, when it came up before the refusal, ended with it.
        if let Some(dialog) = std::fs::read_to_string(&pidfile).ok().and_then(|s| s.trim().parse::<i32>().ok()) {
            // SAFETY: killpg(2) with signal 0 only checks for the fake age's group.
            h.wait_until("the Touch ID dialog's process group ended", T, |_| unsafe { libc::killpg(dialog, 0) } != 0);
        }
    }
}

/// CUSTODY-2, the resume miss's retry: what goes up is scanned again as it
/// goes. P1 scans the Mac's copy clean; generation 1 restores nothing
/// (`AI_ENV_BRIDGE_LAB_TRANSCRIPT=skip`) and its CLI misses once
/// `initialize` came; by then the Mac's copy has grown a line holding an
/// AWS access key id. The retry's restore scans the chat it would send up
/// and refuses before any request: exit 9 naming `transcript:UUID.jsonl`
/// line 2 and the rule, never the value; no copy on the VM's disk, nothing
/// in S3, one `seed_refused` (step `transcript`, the session's VM named),
/// and no second spawn.
#[test]
fn a_resume_miss_retry_scans_the_transcript_again_before_it_goes_up() {
    use std::io::Write as _;
    let key = format!("{}{}", "AKIA", "W".repeat(16));
    let p = Harness::prepare();
    let (sid, parent) = (common::uuid(0x8864), common::uuid(0x8865));
    let prompt = format!(r#"{{"type":"user","uuid":"{parent}","sessionId":"{sid}","message":{{"role":"user","content":"show me the deploy config"}}}}"#);
    let mac = p.plant_transcript(&sid, &[prompt.as_str()]);
    let slug = p.slug();
    let resume = format!("--resume={sid}");
    let knobs = [("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_RESUME_FAIL_AFTER_ACK", "1"), ("AI_ENV_BRIDGE_LAB_TRANSCRIPT", "skip")];
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &knobs);
    // Generation 1's CLI runs on the VM (P1 scanned the copy clean before it); its miss waits for `initialize`.
    wait_for("generation 1's CLI on the VM", T, || h.env_log().iter().any(|l| l == "gen 1 resumed lines=missing"));
    let mut file = std::fs::OpenOptions::new().append(true).open(&mac).expect("open the Mac's transcript");
    writeln!(file, "{}", tool_output(&sid, &parent, &format!("aws_access_key_id = {key}"))).expect("append the tool's output");
    drop(file);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(9), "{}", h.transcript());
    let err = h.err_text();
    assert!(last_line(&err).starts_with(&format!("ai-env-claude: the chat's transcript would carry transcript:{sid}.jsonl line 2: rule aws-access-key-id")), "{err}");
    assert!(!err.contains(&key), "the value on stderr: {err}");
    let rig = h.rig();
    assert!(!rig.vm_projects().join(&slug).join(format!("{sid}.jsonl")).exists(), "no copy on the VM");
    assert_eq!(holding(&[&rig.vm_root(), &h.bridge()], std::slice::from_ref(&key)), Vec::<String>::new(), "the value on the VM's disk or under the bridge dir");
    assert!(rig.s3().requests().is_empty() && h.audit_events("transcript_stage").is_empty(), "nothing went up");
    let starts = h.audit_events("session_remote_start");
    assert_eq!(starts.len(), 1, "generation 1's only: {starts:?}");
    let refused = h.audit_events("seed_refused");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!((refused[0]["detail"]["step"].as_str(), refused[0]["detail"]["vm"].as_str()), (Some("transcript"), starts[0]["detail"]["id"].as_str()), "{refused:?}");
    let failed = h.audit_events("session_remote_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!((failed[0]["detail"]["gen"].as_str(), failed[0]["detail"]["why"].as_str()), (Some("2"), Some("finding")), "{failed:?}");
    assert_eq!(h.spawn_count(), 1, "no second spawn");
}

/// Review F2-R1 after the S3 cut-over: a chat that ran on a VM holds what
/// that VM's tools printed; the Mac holds only its view and S3 its
/// transcript. Here a tool's line holding an AWS access key id lands on the
/// VM's disk after the last sync. The picker reopens the chat while its VM
/// lives (suspended by the close): S3 holds the chat (origin `vm`), so P1
/// reads nothing on the Mac, and P3 finds the VM holding the committed
/// prefix and keeps its copy: nothing is sent or pulled, nothing refused.
/// The session resumes on that VM (`vm_how:resumed`, `transcript:kept`),
/// the CLI from the line; the VM's copy as it was, no `seed_refused`.
#[test]
fn a_vm_chat_whose_tools_printed_a_key_shape_resumes_on_its_vm() {
    use ai_env_cli::bridge::api::VmState;
    use std::io::Write as _;
    let key = format!("{}{}", "AKIA", "V".repeat(16));
    let mut first = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_WRITE_TRANSCRIPT", "1")]);
    let sid = started(&mut first)["session_id"].as_str().expect("the session id").to_string();
    turn(&mut first, "show me the deploy config");
    // The turn's code-out and transcript step done: none still on its way (the endpoint would resume the VM the close suspends).
    synced(&mut first, &sid, 1);
    closed(&mut first);
    let vm = part_of(&end_note_of(&first, first.pid()), "vm").expect("the first session's VM");
    let rig = first.rig();
    wait_for("the closing suspend", T, || rig.fake().vms.get(&vm).is_some_and(|v| v.state == VmState::Suspended));
    // What a tool printed on the VM, after the last sync: on the VM's disk only.
    let file = format!("{sid}.jsonl");
    let (mac, vm_copy) = (first.prepared.mac_projects().join(first.slug()).join(&file), rig.vm_projects().join(first.slug()).join(&file));
    let last: Value = serde_json::from_str(read(&vm_copy).lines().last().expect("the turn's entries")).expect("a transcript line");
    let printed = tool_output(&sid, last["uuid"].as_str().expect("its uuid"), &format!("aws_access_key_id = {key}"));
    let mut f = std::fs::OpenOptions::new().append(true).open(&vm_copy).expect("open the VM's transcript");
    writeln!(f, "{printed}").expect("append the tool's output");
    drop(f);
    let held = read(&vm_copy);
    assert!(is_view(&mac) && !read(&mac).contains(&key), "the Mac keeps the view, never what the VM's tools printed");
    let resume = format!("--resume={sid}");
    let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1")]));
    let init = started(&mut second);
    assert_eq!(init["session_id"].as_str(), Some(sid.as_str()), "the same session: {init}");
    closed(&mut second);
    let note = end_note_of(&first, second.pid());
    assert_eq!((part_of(&note, "vm"), part_of(&note, "vm_how"), part_of(&note, "transcript")), (Some(vm.clone()), Some("resumed".into()), Some("kept".into())), "{note}");
    assert!(first.env_log().iter().any(|l| l == "gen 2 resumed lines=5"), "the CLI resumed from the VM's copy: {:?}", first.env_log());
    assert_eq!(read(&vm_copy), held, "the VM's copy as it was: nothing pulled");
    assert!(audit_rows(rig, "seed_refused").is_empty() && audit_rows(rig, "transcript_pull").is_empty(), "nothing refused, nothing pulled");
}

/// Review F2-R1, its other half, after the S3 cut-over: a chat whose VM is
/// gone (terminated, its disk with it; the registry row still names it)
/// and whose Mac copy is S8's mirror, holding a tool's line with an AWS
/// access key id (line 2). S3 does not hold it, so P3 would send the mirror
/// up inline (`session migrate-s9`'s gone-VM form): P1 scans it, whichever
/// VM the session names, and refuses before any VM. Exit 9 naming
/// `transcript:UUID.jsonl` line 2 and the rule, never the value; no new VM
/// (only the gone one's run), nothing in S3 or in the VM's projects dir,
/// the value nowhere under the bridge dir; one `seed_refused` naming no VM,
/// and no spawn.
#[test]
fn a_vm_chat_whose_tools_printed_a_key_shape_is_refused_before_any_vm() {
    use ai_env_cli::bridge::registry::{self, SessionRow, REGISTRY_SCHEMA_V};
    let key = format!("{}{}", "AKIA", "X".repeat(16));
    let mut p = Harness::prepare();
    let (sid, parent) = (common::uuid(0x8872), common::uuid(0x8873));
    let prompt = format!(r#"{{"type":"user","uuid":"{parent}","sessionId":"{sid}","message":{{"role":"user","content":"show me the deploy config"}}}}"#);
    let printed = tool_output(&sid, &parent, &format!("aws_access_key_id = {key}"));
    p.plant_transcript(&sid, &[prompt.as_str(), printed.as_str()]);
    let slug = p.slug();
    let rig = p.rig();
    // The chat's last VM: started for the workspace, then terminated (never run on this rig's shim).
    let gone = rig.start_vm();
    let o = rig.run(&["vm", "terminate", &gone, "--yes"], None);
    assert!(o.status.success(), "vm terminate: {}", String::from_utf8_lossy(&o.stderr));
    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None);
    let now = registry::now_rfc3339();
    let row = SessionRow {
        v: REGISTRY_SCHEMA_V,
        session_id: sid.clone(),
        slug: Some(slug.clone()),
        cwd: Some(rig.work().display().to_string()),
        transcript_rel: Some(format!("{slug}/{sid}.jsonl")),
        created: now.clone(),
        last_seen: now,
        status: "closed".into(),
        mode: "remote".into(),
        route: "remote".into(),
        exit: Some(0),
        microvm_id: Some(gone.clone()),
        ..SessionRow::default()
    };
    registry::write(&paths, &row).expect("the session's registry row");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1")]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(9), "{}", h.transcript());
    let err = h.err_text();
    assert!(last_line(&err).starts_with(&format!("ai-env-claude: the chat's transcript would carry transcript:{sid}.jsonl line 2: rule aws-access-key-id")), "{err}");
    assert!(!err.contains(&key), "the value on stderr: {err}");
    let rig = h.rig();
    assert_eq!(runs(rig), 1, "the gone VM's run alone: refused at P1, no new VM");
    assert_eq!(files_under(&rig.vm_projects()), Vec::<String>::new(), "nothing in the VM's projects dir");
    assert!(rig.s3().requests().is_empty(), "nothing went up: {:?}", rig.s3().requests());
    assert_eq!(holding(&[&rig.vm_root(), &h.bridge()], std::slice::from_ref(&key)), Vec::<String>::new(), "the value on the VM's disk or under the bridge dir");
    let failed = h.audit_events("session_remote_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!((failed[0]["detail"]["step"].as_str(), failed[0]["detail"]["code"].as_str(), failed[0]["detail"]["why"].as_str()), (Some("workspace"), Some("9"), Some("finding")), "{failed:?}");
    let refused = h.audit_events("seed_refused");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!((refused[0]["detail"]["step"].as_str(), refused[0]["detail"].get("vm")), (Some("transcript"), None), "P1's: no VM chosen yet: {refused:?}");
    assert_eq!(h.spawn_count(), 0, "no spawn");
}

// ---- phase 4 F3: vm warm and the prewarm ----------------------------------------------------
//
// S8 phase 4's review: the prewarm warms only a workspace a chat would use
// and refuses the rest before its Touch ID (POLICY-1, LIFECYCLE-3); `vm warm`
// takes the seed's snapshot and scans at its prechecks, which its dry run
// shows (POLICY-2, DOCS-1); the prewarm's record starts at the warm lock's
// first byte (LIFECYCLE-1); the closing suspend leaves the VM's row
// suspended, so the prewarm finds no token held (the lead's item).

/// `dir` made a git repository with no commit (an unborn HEAD) by the real
/// git, with neither the system's nor a global config.
fn unborn_repo(dir: &Path) {
    std::fs::create_dir_all(dir).expect("mkdir");
    let o = Command::new(common::git_real())
        .args(["init", "-q"])
        .current_dir(dir)
        .env_clear()
        .env("HOME", dir)
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::null())
        .output()
        .expect("run the real git");
    assert!(o.status.success(), "git init: {}", String::from_utf8_lossy(&o.stderr));
}

/// `vm warm <ws> --prewarm` as the wrapper's prewarm starts it: the warm
/// lock of `ws` held on fd 3, after the wrapper read the last record
/// (`last`) through that open file, as `prewarm::warm_lock` reads it, the
/// file's offset left at the record's end. Its output, its pid and the
/// lock's bytes once it ended.
fn prewarm_with_lock(rig: &common::remote::RemoteRig, ws: &Path, last: &str) -> (std::process::Output, u32, Vec<u8>) {
    use std::io::{Read as _, Seek as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let slug = ai_env_cli::wire::slug::project_dir_name(ws).expect("the workspace's slug");
    let path = rig.bridge().join("state").join("workspaces").join(format!("{slug}.warm.lock"));
    std::fs::create_dir_all(path.parent().expect("the lock's directory")).expect("mkdir");
    let mut lock = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).expect("the warm lock");
    // SAFETY: flock(2) on a descriptor this test owns.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0, "the wrapper's hold");
    lock.write_all(last.as_bytes()).expect("the last record");
    lock.seek(std::io::SeekFrom::Start(0)).expect("seek");
    let mut read_back = String::new();
    std::io::Read::by_ref(&mut lock).take(4096).read_to_string(&mut read_back).expect("the wrapper's read");
    assert_eq!(read_back, last);
    let mut cmd = rig.ai_env(&["vm", "warm", &ws.display().to_string(), "--prewarm"]);
    let fd = lock.as_raw_fd();
    // SAFETY: dup2(2) and fcntl(2) are async-signal-safe, and the closure allocates nothing between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            let kept = if fd == 3 { libc::fcntl(3, libc::F_SETFD, 0) } else { libc::dup2(fd, 3) };
            if kept < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn the prewarm");
    let pid = child.id();
    let o = child.wait_with_output().expect("its output");
    drop(lock);
    (o, pid, std::fs::read(&path).expect("the record"))
}

/// POLICY-1 and LIFECYCLE-3: the prewarm warms only a workspace a remote
/// session takes. In one that is no git repository (D6) or an unsupported
/// one (no commit yet), `vm warm --prewarm` refuses at its prechecks, as a
/// session's P0 does (exit 9, exit 1): no Touch ID, no AWS call, no VM, no
/// delivery. The refusal is in its log and its audit (`seed_refused`, step
/// `resolve`, purpose `prewarm`, its actor the prewarm's voice, `wrapper`,
/// as on the seed's other refusals), its run in the warm lock it inherits,
/// written from the lock's first byte though the wrapper left the open
/// file's offset at the last record's end (LIFECYCLE-1). `vm warm` by hand
/// still warms such a workspace without a seed (W2's decision 6).
#[test]
fn vm_warm_prewarm_refuses_a_workspace_no_session_takes_before_any_touch_id() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let (plain, fresh) = (rig.root().join("plain"), rig.root().join("fresh"));
    std::fs::create_dir_all(&plain).expect("mkdir plain");
    unborn_repo(&fresh);
    add_config(rig, &format!("[[workspace]]\npath = {plain:?}\n\n[[workspace]]\npath = {fresh:?}\n"));
    let counts = || (rig.decrypts(), rig.fake_calls().len(), audit_rows(rig, "vm_run").len(), audit_rows(rig, "credential_unseal").len(), audit_rows(rig, "credential_deliver").len());
    let before = counts();
    let now = ai_env_cli::wire::time::unix_now();
    let last = format!("pid=1\nstarted_at={}\nfinished_at={}\n", now - 400, now - 300);
    for (ws, code, why) in [(&plain, 9, "workspace refused (not_a_git_repo)"), (&fresh, 1, "workspace failed (unsupported_repo)")] {
        let (o, pid, record) = prewarm_with_lock(rig, ws, &last);
        assert_eq!(o.status.code(), Some(code), "{}: {}", ws.display(), String::from_utf8_lossy(&o.stderr));
        assert!(o.stdout.is_empty(), "a prewarm prints nothing");
        assert_eq!(counts(), before, "{}: no Touch ID, no AWS call, no VM, no delivery", ws.display());
        let text = String::from_utf8_lossy(&record).into_owned();
        assert!(record.starts_with(b"pid=") && !record.contains(&0), "the record from the lock's first byte: {text:?}");
        let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')?.parse::<u64>().ok());
        assert_eq!(field("pid"), Some(u64::from(pid)), "{text}");
        assert!(field("started_at").is_some() && field("finished_at") >= field("started_at"), "{text}");
        let code_word = why.split_once('(').and_then(|(_, w)| w.strip_suffix(')')).expect("the code");
        let rows = audit_rows(rig, "seed_refused");
        let ours = |r: &&Value| r["detail"]["workspace"] == ws.display().to_string().as_str();
        assert!(rows.iter().filter(ours).any(|r| r["detail"]["code"] == code_word && r["detail"]["step"] == "resolve" && r["detail"]["purpose"] == "prewarm" && r["detail"]["actor"] == "wrapper"), "{rows:?}");
        let log = read(&rig.bridge().join("logs").join("ai-env.log"));
        assert!(log.contains(&format!("no prewarm: {why}")), "said in its log: {log}");
    }
    // By hand: warmed without a seed, which is said (W2's decision 6).
    let o = rig.run(&["vm", "warm", &plain.display().to_string(), "--json"], None);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("--json ({e}): {}", String::from_utf8_lossy(&o.stderr)));
    assert_eq!((v["warmed"].as_str(), v["seed"].is_null()), (Some("delivered"), true), "{v}");
    assert!(v["seed_note"].as_str().is_some_and(|n| n.contains("not a git repository")), "{v}");
}

/// POLICY-2 and DOCS-1: `vm warm` takes the seed's snapshot and every scan
/// at its prechecks, as `box seed` does. A finding (an untracked file
/// holding an AWS key's shape, built at run time) is exit 9 naming where it
/// is and the rule, never the value, before any Touch ID, AWS call or VM,
/// from `vm warm`, its `--prewarm` and its `--dry-run` (text and JSON)
/// alike, each audited `seed_refused` at step `prepare` (the prewarm's
/// with its purpose, `prewarm`). On a clean tree the dry run says what the
/// seed carries and that its scan is clean; `vm --help` says `vm warm` seeds.
#[test]
fn vm_warm_refuses_a_seed_finding_before_any_touch_id_or_vm() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work().display().to_string();
    let key = format!("{}{}", "AKIA", "S".repeat(16));
    let planted = rig.work().join("deploy.conf");
    std::fs::write(&planted, format!("aws_access_key_id = {key}\n")).expect("plant the file");
    let cases: [&[&str]; 4] = [&["vm", "warm", work.as_str()], &["vm", "warm", work.as_str(), "--prewarm"], &["vm", "warm", work.as_str(), "--dry-run"], &["vm", "warm", work.as_str(), "--dry-run", "--json"]];
    for args in cases {
        let (decrypts, calls) = (rig.decrypts(), rig.fake_calls().len());
        let o = rig.run(args, None);
        let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert_eq!(o.status.code(), Some(9), "{args:?}: {out}{err}");
        assert!(err.contains("workspace refused (finding): wip:deploy.conf (blob ") && err.contains("rule aws-access-key-id"), "{args:?}: {err}");
        assert!(!out.contains(&key) && !err.contains(&key), "{args:?}: the value printed");
        assert_eq!((rig.decrypts(), rig.fake_calls().len()), (decrypts, calls), "{args:?}: no Touch ID, no AWS call");
    }
    assert!(audit_rows(rig, "vm_run").is_empty(), "no VM was started");
    // Each refusal audited at `prepare`: the prewarm's names its purpose, as its refusal at `resolve` does.
    let field = |r: &Value, k: &str| r["detail"][k].as_str().unwrap_or("-").to_string();
    let prepare: Vec<(String, String)> = audit_rows(rig, "seed_refused").iter().filter(|r| r["detail"]["step"] == "prepare").map(|r| (field(r, "actor"), field(r, "purpose"))).collect();
    assert_eq!(prepare, [("cli", "-"), ("wrapper", "prewarm"), ("cli", "-"), ("cli", "-")].map(|(a, p)| (a.to_string(), p.to_string())), "by hand, --prewarm, the two dry runs");
    std::fs::remove_file(&planted).expect("remove the file");
    let o = rig.run(&["vm", "warm", &work, "--dry-run"], None);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert_eq!(o.status.code(), Some(0), "{out}{}", String::from_utf8_lossy(&o.stderr));
    assert!(out.contains("\n  uncommitted: none carried\n") && out.lines().any(|l| l.starts_with("  scan: ") && l.ends_with("settings file(s): clean")), "{out}");
    let o = rig.run(&["vm", "warm", &work, "--dry-run", "--json"], None);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("--json ({e}): {}", String::from_utf8_lossy(&o.stderr)));
    assert!(v["seed"]["prepared"]["objects"].as_u64().is_some_and(|n| n > 0) && v["seed"]["prepared"]["head"] == rig.head(), "{v}");
    let o = rig.run(&["vm", "--help"], None);
    let help = String::from_utf8_lossy(&o.stdout).into_owned();
    let line = help.lines().find(|l| l.trim_start().starts_with("warm ")).unwrap_or_else(|| panic!("no warm line: {help}"));
    assert!(line.contains("seed it"), "vm --help's warm line names the seed: {line}");
}

/// `ai-env-claude <claude> auth status --json` in `cwd`, as Cursor runs it,
/// in remote mode with the rig's environment (its sibling the real
/// `ai-env` beside it).
fn auth_status(rig: &common::remote::RemoteRig, cwd: &Path) -> std::process::Output {
    let base = rig.ai_env(&[]);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env-claude"));
    for (k, v) in base.get_envs() {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    cmd.arg(rig.root().join("claude")).args(["auth", "status", "--json"]).current_dir(cwd).env("AI_ENV_BRIDGE_MODE", "remote");
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output().expect("run the wrapper")
}

/// The lead's item: a chat that closes alone suspends its VM, whose
/// `/suspend` hook empties the shim's credential cache (S7 D3), and the
/// VM's row says so (suspended, its credential record kept for `creds
/// status`), so the next `auth status` finds a VM to reuse but no token
/// held: `prewarm:skipped(vm_exists)`, never `token_held`.
#[test]
fn after_the_closing_suspend_the_prewarm_finds_no_token_held() {
    use ai_env_cli::bridge::vm::registry::{read_row, RowStatus};
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[]);
    started(&mut h);
    closed(&mut h);
    assert!(h.wrapper_log().contains("closing: suspended"), "the closing suspend fired: {}", h.wrapper_log());
    let vm = part_of(&h.end_note(), "vm").expect("the session's VM");
    let rig = h.rig();
    let row = read_row(&ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None), &vm).expect("read the row").expect("its row");
    assert_eq!(row.status, RowStatus::Suspended, "{row:?}");
    assert!(row.credential_at.is_some() && row.credential_tag.is_some(), "the token's record stays until it is terminated: {row:?}");
    // The prewarm's own condition: `touchid-gui` prompted.
    let probes = rig.bridge().join("lab").join("probes.jsonl");
    let mut text = read(&probes);
    text.push_str(&format!("{}\n", serde_json::json!({ "probe": "touchid-gui", "verdict": "prompted", "ts": ai_env_cli::wire::time::rfc3339_utc(ai_env_cli::wire::time::unix_now()) })));
    std::fs::write(&probes, text).expect("write the probes");
    let o = auth_status(rig, &rig.work());
    let note = h.census().last().and_then(|r| r["note"].as_str().map(str::to_string)).unwrap_or_default();
    assert_eq!(part_of(&note, "prewarm").as_deref(), Some("skipped(vm_exists)"), "{note}\n{}", String::from_utf8_lossy(&o.stderr));
}

// ---- phase 4 F4 -----------------------------------------------------------------------------
//
// S8 phase 4's review: a ref the VM's agent names after the setup-token never
// reaches the session's registry row (CUSTODY-3; `box fetch`'s side is in
// tests/workspace/codeout.rs), and a session no registry row keeps leaves no
// settings capture behind (LIFECYCLE-4).

/// `git <args>` in the VM's copy `dir` as its agent runs it (no hooks, no
/// automatic maintenance): its stdout, trimmed.
fn as_vm_agent(dir: &Path, args: &[&str]) -> String {
    let mut all = vec!["-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=false", "-c", "gc.auto=0"];
    all.extend_from_slice(args);
    git_in(dir, &all)
}

/// CUSTODY-3 through the per-result code-out: once the seed went in, the
/// agent names a snapshot ref and a branch after the token it can read in
/// the VM; the turn commits an edit and leaves another uncommitted. The
/// fetch brings the commit into `refs/remotes/box/main` and the turn's own
/// snapshot into `box/wip/*`, which is the session row's `last_wip_fetch`
/// (the agent's name sorts after every UTC stamp). The two refs kept out
/// are counted, never named: in the fetch's `codeout_fetch` row and in the
/// trigger's warning, which the wrapper's log holds. Neither the registry,
/// the workspace row nor anything else under the bridge dir or the Mac's
/// `~/.claude` holds the token, nor does a ref of the Mac's or the
/// wrapper's output.
#[test]
fn a_credential_shaped_snapshot_ref_never_reaches_the_session_row() {
    let mut p = Harness::prepare();
    let token = p.rig().token().to_string();
    let knobs = [("FAKE_EDIT", "agent.txt:from the VM"), ("FAKE_COMMIT", "the agent's commit"), ("FAKE_WIP_EDIT", "agent.txt:not committed yet")];
    let mut h = p.spawn_on(common::Link::Remote, "", &[], &knobs);
    started(&mut h);
    let (work, vm) = (h.rig().work(), h.rig().vm_path(&h.rig().work()));
    as_vm_agent(&vm, &["update-ref", &format!("refs/wip/zz-{token}"), "HEAD"]);
    as_vm_agent(&vm, &["branch", &format!("x-{token}")]);
    turn(&mut h, "hello");
    wait_for_fetch(h.rig());
    let masked = |text: &str| text.replace(&token, "<TOKEN>");
    let fetches = audit_rows(h.rig(), "codeout_fetch");
    assert!(fetches.iter().any(|r| r["detail"]["hidden"] == "2"), "the fetch's row counts the two refs kept out: {}", masked(&format!("{fetches:?}")));
    wait_for("the trigger's warning of the refs kept out, in the wrapper's log", T, || h.wrapper_log().lines().any(|l| l.contains("code-out of ") && l.contains(": 2 VM ref(s) skipped: a name that looks like a credential (not shown)")));
    closed(&mut h);
    assert_eq!(git_in(&work, &["rev-parse", "refs/remotes/box/main"]), git_in(&vm, &["rev-parse", "refs/heads/main"]), "the turn's commit came back");
    let rows = h.registry_rows();
    assert_eq!(rows.len(), 1, "{}", masked(&format!("{rows:?}")));
    let last = rows[0].get("last_wip_fetch").and_then(toml::Value::as_str).unwrap_or_default().to_string();
    assert!(last.starts_with("refs/remotes/box/wip/2"), "the turn's own snapshot: {}", masked(&last));
    assert_eq!(git_in(&work, &["show", &format!("{last}:agent.txt")]), "not committed yet");
    assert_eq!(holding(&[&h.bridge(), &h.root().join(".claude")], std::slice::from_ref(&token)), Vec::<String>::new(), "the token in what the Mac keeps");
    let refs = git_in(&work, &["for-each-ref", "--format=%(refname)"]);
    assert!(!refs.contains(&token), "{}", masked(&refs));
    let output = format!("{}\n{}", h.out_lines().join("\n"), h.err_text());
    assert!(!output.contains(&token), "the token in the wrapper's output");
}

/// LIFECYCLE-4: a remote session with `--no-session-persistence` (`args`,
/// the VM side's `knobs`), one turn to its code-out (the trigger runs a
/// start capture due before the fetch it runs), then EOF: no registry row,
/// no settings capture in quarantine (which no `session list` would show
/// and nothing would remove), no `settings_capture` audit row.
fn no_capture_without_persistence(args: &[&str], knobs: &[(&str, &str)]) {
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", args, knobs);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    let u = h.send_user("suggest something");
    h.expect_out(|v| is_result_for(v, &u), T);
    let sid = h.expect_out(is_init, T)["session_id"].as_str().expect("the init's session id").to_string();
    wait_for("the turn's code-out", T, || !audit_rows(h.rig(), "codeout_fetch").is_empty());
    closed(&mut h);
    assert!(h.registry_files().is_empty(), "{:#?}", h.registry_files());
    assert!(!h.bridge().join("quarantine").join(&sid).exists(), "a capture of a session no row keeps: {:?}", files_under(&h.bridge().join("quarantine")));
    assert_eq!(h.audit_events("settings_capture"), Vec::<Value>::new());
}

/// LIFECYCLE-4, as Cursor's prompt-suggestion query runs: the session's id
/// comes with its first init (the pump hands it to the trigger).
#[test]
fn a_session_without_persistence_leaves_no_settings_capture() {
    no_capture_without_persistence(&["--no-session-persistence"], &[]);
}

/// LIFECYCLE-4 for a `--resume`: its id is named to the trigger as its
/// spawn goes out (P4), before the CLI says its init with the turn.
#[test]
fn a_resumed_session_without_persistence_leaves_no_settings_capture() {
    let resume = format!("--resume={}", common::uuid(0x8860));
    no_capture_without_persistence(&["--no-session-persistence", &resume], &[("FAKE_INIT_AT_TURN", "1")]);
}

// ---- S8 wave 2, W8: settings persistence (T8.7) and session drop-transport (T8.6) ---------
//
// The real `ai-env-claude` in remote mode on the rig, and the real `ai-env`
// commands against its bridge. W8's own section: other builders add elsewhere.

/// The capture `<bridge>/quarantine/<session>/settings/<name>` of the rig, once it exists.
fn capture_file(rig: &common::remote::RemoteRig, session: &str, name: &str) -> Option<Value> {
    let text = std::fs::read_to_string(rig.bridge().join("quarantine").join(session).join("settings").join(name)).ok()?;
    serde_json::from_str(&text).ok()
}

/// The `local` scope's file of a capture.
fn local_file(capture: &Value) -> &Value {
    capture["files"].as_array().and_then(|f| f.iter().find(|f| f["scope"] == "local")).unwrap_or_else(|| panic!("no local scope in {capture}"))
}

/// T8.7 offline (plan section 9): a fresh session's settings are captured
/// once its id is known (its first `system/init`) into its quarantine
/// (`start.json`), and after the turn's code-out (`latest.json`), when the
/// VM's claude wrote a "don't ask again" rule into the workspace's
/// `settings.local.json`; nothing runs at the close, which keeps its 1.5 s.
/// `session show UUID --settings-diff` then prints the rule and writes the
/// diff beside the captures.
#[test]
fn the_vm_settings_diff_is_captured_into_quarantine() {
    use ai_env_cli::bridge::remote::CLOSE_BUDGET_MS;
    let rule = "Bash(git status)";
    let local = format!(r#"{{"permissions":{{"allow":["{rule}"]}}}}"#);
    let knob = format!("local:{local}");
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_WRITE_SETTINGS", knob.as_str())]);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    let started = h.expect_out(is_init, T);
    let sid = started["session_id"].as_str().expect("the init's session id").to_string();
    // The start capture: the VM's settings before the session changed anything.
    wait_for("the start capture in the session's quarantine", T, || capture_file(h.rig(), &sid, "start.json").is_some());
    let start = capture_file(h.rig(), &sid, "start.json").unwrap();
    assert_eq!(start["path"].as_str(), Some(h.rig().vm_cwd().as_str()), "{start}");
    assert_eq!(local_file(&start)["present"], false, "no local settings before the turn: {start}");
    let u = h.send_user("approve it");
    h.expect_out(|v| is_result_for(v, &u), T);
    wait_for_fetch(h.rig());
    wait_for("the capture after the turn's code-out", T, || capture_file(h.rig(), &sid, "latest.json").is_some());
    let latest = capture_file(h.rig(), &sid, "latest.json").unwrap();
    assert_eq!(local_file(&latest)["text"].as_str().map(str::trim), Some(local.as_str()), "{latest}");
    h.close_stdin();
    let (status, took) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "the close took {took:?}: no capture runs inside it\n{}", h.transcript());
    let rig = h.rig();
    let dir = rig.bridge().join("quarantine").join(&sid).join("settings");
    for (path, mode) in [(dir.clone(), 0o700), (dir.join("start.json"), 0o600), (dir.join("latest.json"), 0o600)] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, mode, "{}", path.display());
    }
    let captures: Vec<(String, String)> = audit_rows(rig, "settings_capture").iter().map(|r| (r["detail"]["phase"].as_str().unwrap_or_default().to_string(), r["detail"]["outcome"].as_str().unwrap_or_default().to_string())).collect();
    assert_eq!(captures, [("start".to_string(), "written".to_string()), ("turn".to_string(), "written".to_string())], "one start, one turn");
    assert!(audit_rows(rig, "settings_capture").iter().all(|r| r["session_id"] == sid.as_str()));
    // Each capture names the VM it was read in: the session's.
    let vm = part_of(&h.end_note(), "vm").expect("the session's VM");
    assert_eq!((start["vm"].as_str(), latest["vm"].as_str()), (Some(vm.as_str()), Some(vm.as_str())), "{start}\n{latest}");
    let o = rig.run(&["session", "show", &sid, "--settings-diff"], None);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{out}{}", String::from_utf8_lossy(&o.stderr));
    let lines: Vec<&str> = out.lines().collect();
    for want in [format!("  + allow {rule}  (local; {vm})"), format!("VM {vm}, the session's last (captured {}):", latest["at"].as_str().unwrap_or_default())] {
        assert!(lines.contains(&want.as_str()), "{want}: {out}");
    }
    let diff: Value = serde_json::from_str(&read(&dir.join("diff.json"))).unwrap();
    assert_eq!((diff["v"].as_u64(), diff["vms"][0]["scopes"][2]["allow"]["added"].clone(), diff["added"][0]["rule"].as_str()), (Some(3), serde_json::json!([rule]), Some(rule)), "{diff}");
}

/// T8.6 offline: `ai-env session drop-transport UUID` (the real command,
/// against the session's registry row) makes the owning wrapper close its
/// socket mid-stream: the CLI streams 300 lines of 64 KiB (past the shim's
/// 8 MiB window) while the host stops reading after the 10th; the session
/// reattaches (`agent_reconnect`), and once the host reads again every line
/// arrives exactly once, in order, from the same VM process, the turn ends
/// and EOF exits 0 within the close budget. The census counts the drop. A
/// closed session, an unknown one or no session id are refused.
#[test]
fn drop_transport_reattaches_without_a_lost_or_doubled_line() {
    use ai_env_cli::bridge::remote::CLOSE_BUDGET_MS;
    const LINES: u64 = 300;
    let pad = (64 * 1024).to_string();
    let lines = LINES.to_string();
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[("FAKE_INIT_AT_TURN", "1"), ("FAKE_STREAM_LINES", lines.as_str()), ("FAKE_STREAM_PAD", pad.as_str())]);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    let u = h.send_user("count");
    let started = h.expect_out(is_init, T);
    let sid = started["session_id"].as_str().expect("the init's session id").to_string();
    h.expect_out(|v| v["type"] == "stream_event" && v["n"] == 10, T);
    h.pause_stdout();
    let vm_pid = h.fake_pid(1).expect("the VM's CLI logged its pid");
    let row = h.registry_rows().into_iter().find(|r| r.get("session_id").and_then(toml::Value::as_str) == Some(sid.as_str())).unwrap_or_else(|| panic!("no row of {sid}"));
    assert_eq!((row.get("status").and_then(toml::Value::as_str), row.get("mode").and_then(toml::Value::as_str)), (Some("active"), Some("remote")), "{row:?}");
    let o = h.rig().run(&["session", "drop-transport", &sid], None);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{out}{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(out, format!("session {sid}: its wrapper (pid {}) drops the transport and reattaches (session show {sid}: detached, then active)\n", h.pid()));
    // Dropped and reattached while the host still reads nothing: lines were in flight.
    wait_for("the session reattached (agent_reconnect)", T, || !audit_rows(h.rig(), "agent_reconnect").is_empty());
    h.resume_stdout();
    h.expect_out(|v| is_result_for(v, &u), T);
    let ns: Vec<u64> = h.out_json().iter().filter(|v| v["type"] == "stream_event").filter_map(|v| v["n"].as_u64()).collect();
    assert!(ns == (1..=LINES).collect::<Vec<_>>(), "every line once, in order: {} lines, first gap at {:?}", ns.len(), ns.iter().zip(1..).find(|(n, i)| **n != *i));
    h.close_stdin();
    let (status, took) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "{took:?}\n{}", h.transcript());
    assert_eq!((h.spawn_count(), h.fake_pid(1)), (1, Some(vm_pid)), "one CLI process on the VM, never respawned");
    let note = h.end_note();
    assert!(note.split("; ").any(|p| p == "link_drops:1"), "{note}");
    assert_eq!((h.audit_events("session_remote_end").len(), h.audit_events("session_remote_failed").len()), (1, 0));
    // The session is closed now: nothing to drop; nor for no session, or no id at all.
    let rig = h.rig();
    for (args, code, says) in [
        (vec!["session", "drop-transport", sid.as_str()], 1, "is closed, not active"),
        (vec!["session", "drop-transport", "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"], 1, "no session 0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"),
        (vec!["session", "drop-transport", "../x"], 2, "not a session id"),
    ] {
        let o = rig.run(&args, None);
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(code), "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    }
}

/// T8.7: a `--resume`'s id is known before its CLI says a word, so its
/// start capture runs beside the spawn: here the CLI says its init only with
/// a first turn that never comes, and the baseline is taken all the same,
/// before anything the session does; no result, no turn's capture.
#[test]
fn a_resumed_sessions_start_capture_runs_before_its_first_init() {
    let sid = common::uuid(0x8830);
    let resume = format!("--resume={sid}");
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[&resume], &[("FAKE_INIT_AT_TURN", "1")]);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    wait_for("the resumed session's start capture", T, || capture_file(h.rig(), &sid, "start.json").is_some());
    assert!(!h.out_json().iter().any(is_init), "the CLI has said no init yet");
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(capture_file(h.rig(), &sid, "latest.json").is_none(), "no result, no turn's capture");
}

/// `ai-env <args>` against `h`'s bridge (`HOME` its tempdir, the
/// developer's knobs removed), run to its end within [`T`].
fn ai_env_for(h: &Harness, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env"));
    for k in common::REMOVED_ENV {
        cmd.env_remove(k);
    }
    cmd.args(args).env("HOME", h.root()).env("AI_ENV_BRIDGE_DIR", h.bridge()).env_remove("AI_ENV_BRIDGE_CONFIG").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn ai-env");
    let t = std::time::Instant::now();
    while child.try_wait().expect("try_wait").is_none() {
        if t.elapsed() > T {
            let _ = child.kill();
            panic!("ai-env {args:?} ran past {T:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().expect("its output")
}

/// T8.6: `session drop-transport` signals only the session's own wrapper.
/// The stand-in is the real `ai-env-claude` of a local-child session (its
/// handler logs the signal and keeps its child: a local link has no
/// transport) behind a planted active remote row. Another program at the
/// row's pid (`sleep`, which SIGUSR2 would end) and the wrapper under a row
/// written before it started (its pid taken as reused) are refused, exit 1,
/// nothing signalled; under a row written after it started it gets the
/// signal, and lives on.
#[test]
fn drop_transport_signals_only_the_wrapper_that_wrote_the_row() {
    struct Reaped(std::process::Child);
    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut h = Harness::spawn("local-child", &[], &[]);
    let init = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &init), T);
    // Another session's id: without a user line the wrapper registers none of its own.
    let sid = common::uuid(0x8840);
    let sessions = h.bridge().join("state").join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let plant = |pid: u32, created: u64| {
        let created = ai_env_cli::wire::time::rfc3339_utc(created);
        std::fs::write(sessions.join(format!("{sid}.toml")), format!("v = 1\nsession_id = \"{sid}\"\nstatus = \"active\"\nmode = \"remote\"\npid = {pid}\ncreated = \"{created}\"\n")).unwrap();
    };
    let now = ai_env_cli::wire::time::unix_now;
    let mut sleep = Reaped(Command::new("/bin/sleep").arg("30").stdin(Stdio::null()).spawn().unwrap());
    plant(sleep.0.id(), now() + 1);
    let o = ai_env_for(&h, &["session", "drop-transport", &sid]);
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains(&format!("pid {} is sleep, not ai-env-claude", sleep.0.id())), "{err}");
    assert!(sleep.0.try_wait().unwrap().is_none(), "another program is never signalled");
    plant(h.pid(), now() - 3600);
    let o = ai_env_for(&h, &["session", "drop-transport", &sid]);
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains(&format!("pid {} started after session {sid}'s row was written", h.pid())), "{err}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!h.wrapper_log().contains("drop-transport signal"), "a reused pid is never signalled: {}", h.wrapper_log());
    plant(h.pid(), now() + 1);
    let o = ai_env_for(&h, &["session", "drop-transport", &sid]);
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    wait_for("the wrapper got the drop-transport signal", T, || h.wrapper_log().contains("drop-transport signal"));
    assert!(!h.exited_now(), "a local session lives on");
    assert!(sleep.0.try_wait().unwrap().is_none());
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
}

// ---- S8 wave 3 (X2): the close's order, settings per VM ----------------------------------
//
// Wave 2's follow-ups: the closing suspend waits for the session's code-out
// trigger (plan §11), and a rule approved on a VM the session left stays in
// its settings diff (review W8-R3). The census's `credential:cached` is in
// `a_session_on_a_vm_holding_the_token_sends_no_token` above.

/// Plan §11's close order (L2): the closing suspend goes out only once the
/// session's code-out trigger is done. The turn's `POST /codeout` is held at
/// the endpoint until the wrapper's close began (its log says `pump done`,
/// after the census end row), then let go half the trigger's `CLOSE_WAIT`
/// into it, or as soon as a SuspendMicrovm went out: it passes the
/// endpoint's check and runs in the VM inside the close, and the suspend
/// fires only once that fetch ended, or was given up at `CLOSE_WAIT` (the
/// log says so in that order). So the VM ends suspended. With the wait
/// removed, the suspend goes out as the session task ends, when the close
/// begins: the code-out let go after it finds the VM suspended, and the
/// fake's auto-resume leaves it RUNNING. One code-out request, one
/// SuspendMicrovm, the close within 1.5 s. Measured with the binary's
/// wall-clock lane alone: the hold must go before the trigger gives the
/// fetch up, while the fetch still waits for its answer (a fetch given up
/// with its request already on its way may still reach the VM after the
/// suspend).
#[test]
fn the_closing_suspend_waits_for_the_last_code_out() {
    use ai_env_cli::bridge::api::VmState;
    use ai_env_cli::bridge::codeout::CLOSE_WAIT;
    use ai_env_cli::bridge::remote::CLOSE_BUDGET_MS;
    use ai_env_cli::wire::workspace::{CODEOUT_ROUTE, CODE_PORT};
    use common::fake_endpoint::Action;
    let _alone = common::remote::alone();
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[]);
    let init = started(&mut h);
    let sid = init["session_id"].as_str().expect("the init's session id").to_string();
    // The start capture (8080) done first; the code port's next request is the turn's code-out (S9: after its tail on
    // 8080, so the code-out's own hold is waited for, never any connection: a close before the fetch starts none).
    wait_for("the start capture", T, || capture_file(h.rig(), &sid, "start.json").is_some());
    h.rig().endpoint.script_port(CODE_PORT, [Action::Held]);
    turn(&mut h, "one");
    wait_for("the turn's code-out held at the endpoint", T, || h.rig().endpoint.held() > 0);
    // The host's EOF. Once the close began (the trigger closes there), the code-out goes on to the VM: half the
    // trigger's CLOSE_WAIT in, or as soon as a suspend went out (one that did not wait for the trigger).
    h.close_stdin();
    wait_for("the wrapper's close began", T, || h.wrapper_log().contains("pump done"));
    let began = std::time::Instant::now();
    while suspends(h.rig()) == 0 && began.elapsed() < CLOSE_WAIT / 2 {
        std::thread::sleep(Duration::from_millis(10));
    }
    h.rig().endpoint.release();
    let (status, took) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "the close took {took:?}\n{}", h.wrapper_log());
    let log = h.wrapper_log();
    let at = |what: &str| log.find(what).unwrap_or_else(|| panic!("{what}: {log}"));
    let ended = log.find("code-out fetch").or_else(|| log.find("code-out: the fetch still running at the close was given up")).unwrap_or_else(|| panic!("the code-out neither ended nor was given up: {log}"));
    assert!(at("pump done") < ended && ended < at("closing: suspended"), "the close began, the code-out ended or was given up, then the suspend: {log}");
    let rig = h.rig();
    // Recorded once the VM answered (200, 204), or with 0 when the close gave the fetch up first (its client
    // gone before the answer came; the run goes on in the VM): either way past the check, never refused.
    let codeout = || rig.endpoint.attempts().into_iter().filter(|a| a.port == CODE_PORT && a.path == CODEOUT_ROUTE).map(|a| a.status).collect::<Vec<u16>>();
    wait_for("the code-out's attempt at the endpoint", T, || !codeout().is_empty());
    assert!(matches!(codeout().as_slice(), [0 | 200 | 204]), "the held code-out passed the check: {:?}\n{log}", codeout());
    assert_eq!(suspends(rig), 1, "the closing suspend went out: {log}");
    let vm = part_of(&h.end_note(), "vm").expect("the session's VM");
    assert!(rig.fake().vms.get(&vm).is_some_and(|v| v.state == VmState::Suspended), "nothing woke the VM after the suspend: {:?}", rig.fake().vms.get(&vm).map(|v| &v.state));
}

/// T8.7 with T8.5 on the rig (review W8-R3's P2): a chat whose VM is gone
/// (terminated) had a rule approved there, kept in its captures as the
/// wrapper on that VM left them (`start.json`, `latest.json`, each naming
/// it). Reopened, the chat starts a new VM, seeded from the Mac (no rule):
/// its baseline is kept, and its turn's capture keeps the old VM's as that
/// VM's last (`latest-<VM id>.json`) beside its own (`latest.json`). The
/// rule stays in `session show --settings-diff`, the old VM named, and
/// `wrapper settings-sync` offers it.
#[test]
fn a_rule_approved_on_a_vm_the_session_left_survives_a_resume_on_a_new_vm() {
    use ai_env_cli::bridge::registry::{self, SessionRow, REGISTRY_SCHEMA_V};
    use ai_env_cli::bridge::settings_capture::{capture_path, CapturePhase, KeptCapture};
    use ai_env_cli::wire::workspace::{SettingsCapture, SettingsFile, SettingsScope};
    let rule = "Bash(git status)";
    let mut p = Harness::prepare();
    let sid = common::uuid(0x8850);
    let earlier = format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, common::uuid(0x8851));
    p.plant_transcript(&sid, &[earlier.as_str()]);
    let slug = p.slug();
    // The agent's home in the VM is the Mac's HOME there (the rig's root).
    let user_settings = p.root.join(".claude").join("settings.json").display().to_string();
    let rig = p.rig();
    let gone = rig.start_vm();
    let o = rig.run(&["vm", "terminate", &gone, "--yes"], None);
    assert!(o.status.success(), "vm terminate: {}", String::from_utf8_lossy(&o.stderr));
    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None);
    let now = registry::now_rfc3339();
    let row = SessionRow {
        v: REGISTRY_SCHEMA_V,
        session_id: sid.clone(),
        slug: Some(slug.clone()),
        cwd: Some(rig.work().display().to_string()),
        transcript_rel: Some(format!("{slug}/{sid}.jsonl")),
        created: now.clone(),
        last_seen: now,
        status: "closed".into(),
        mode: "remote".into(),
        route: "remote".into(),
        exit: Some(0),
        microvm_id: Some(gone.clone()),
        ..SessionRow::default()
    };
    registry::write(&paths, &row).expect("the session's registry row");
    // The captures the old VM left: no settings at the start, the rule after a turn.
    let vm_cwd = rig.vm_cwd();
    let kept = |local: Option<&str>, at: &str| {
        use sha2::Digest;
        let absent = |scope, path: String| SettingsFile { scope, path, present: false, size: 0, sha256: None, text: None, skipped: None };
        let local = match local {
            Some(t) => SettingsFile { scope: SettingsScope::Local, path: format!("{vm_cwd}/.claude/settings.local.json"), present: true, size: t.len() as u64, sha256: Some(hex::encode(sha2::Sha256::digest(t.as_bytes()))), text: Some(t.to_string()), skipped: None },
            None => absent(SettingsScope::Local, format!("{vm_cwd}/.claude/settings.local.json")),
        };
        let files = vec![absent(SettingsScope::User, user_settings.clone()), absent(SettingsScope::Project, format!("{vm_cwd}/.claude/settings.json")), local];
        KeptCapture { vm: Some(gone.clone()), capture: SettingsCapture { path: vm_cwd.clone(), files, project: std::collections::BTreeMap::new(), at: at.into() } }
    };
    let approved = format!(r#"{{"permissions":{{"allow":["{rule}"]}}}}"#);
    for (phase, capture) in [(CapturePhase::Start, kept(None, "2026-10-12T10:00:00Z")), (CapturePhase::Turn, kept(Some(&approved), "2026-10-12T10:30:00Z"))] {
        let path = capture_path(&paths, &sid, phase).expect("the capture's path");
        std::fs::create_dir_all(path.parent().expect("its directory")).expect("mkdir the quarantine");
        std::fs::write(&path, serde_json::to_string_pretty(&capture).expect("the capture's JSON")).expect("write the capture");
    }
    let resume = format!("--resume={sid}");
    let mut h = p.spawn_on(common::Link::Remote, "", &[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_WRITE_TRANSCRIPT", "1")]);
    started(&mut h);
    turn(&mut h, "after the VM was replaced");
    wait_for("the turn's code-out (nothing new)", T, || !audit_rows(h.rig(), "codeout_fetch").is_empty());
    let dir = h.rig().bridge().join("quarantine").join(&sid).join("settings");
    let left = format!("latest-{gone}.json");
    wait_for("the new VM's capture beside the old one's", T, || dir.join(&left).is_file());
    closed(&mut h);
    let vm = part_of(&h.end_note(), "vm").expect("the new VM");
    assert_ne!(vm, gone, "{}", h.end_note());
    let rig = h.rig();
    assert_eq!(names_in(&dir), [left.clone(), "latest.json".into(), "start.json".into()]);
    let file = |name: &str| -> Value { serde_json::from_str(&read(&dir.join(name))).unwrap() };
    assert_eq!((file("start.json")["vm"].as_str(), file(&left)["vm"].as_str(), file("latest.json")["vm"].as_str()), (Some(gone.as_str()), Some(gone.as_str()), Some(vm.as_str())), "the baseline kept, the old VM's last capture kept beside the new VM's");
    let o = rig.run(&["session", "show", &sid, "--settings-diff"], None);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{out}{}", String::from_utf8_lossy(&o.stderr));
    for want in [format!("  + allow {rule}  (local; {gone})"), format!("VM {gone}, left (captured 2026-10-12T10:30:00Z):")] {
        assert!(out.lines().any(|l| l == want), "{want}: {out}");
    }
    assert!(out.lines().any(|l| l.starts_with(&format!("VM {vm}, the session's last (captured "))), "{out}");
    // settings-sync's candidates hold it: a dry run against a minimal image.
    let image = h.root().join("image");
    std::fs::create_dir_all(image.join("claude")).unwrap();
    std::fs::write(image.join("MANIFEST"), "file claude/settings.json 0644\n").unwrap();
    std::fs::write(image.join("claude").join("settings.json"), "{\"permissions\":{\"allow\":[]}}\n").unwrap();
    let o = rig.run(&["wrapper", "settings-sync", &sid, "--all-safe", "--image-dir", &image.display().to_string()], None);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{out}{}", String::from_utf8_lossy(&o.stderr));
    for want in [format!("  allow {rule}  (local; {gone})  promote"), "dry run: nothing written; re-run with --write".to_string()] {
        assert!(out.lines().any(|l| l == want), "{want}: {out}");
    }
    // S10 (FK-8): the reopen's carry off the terminated VM left nothing on the new one.
    h.assert_vm_empty();
}

// ---- phase 4 F9: the shim's own /health/detail, the fake's init per turn -------------------
//
// S8 phase 4's review, packet F9. The rig's `/health/detail` is the shim's
// now (FIDELITY-1): L2's second condition (no other live spawn on the VM)
// and S7's `cached_on_vm` run end to end. The fake claude says init per turn
// and gives each later process a session of its own, as 2.1.x does
// (FIDELITY-6).

/// L2's second condition end to end: a spawn that holds no `.active` (here
/// a `vm exec` of the VM's claude, its stdin kept open) runs on the chat's
/// VM, so the chat's closing suspend, alone on the workspace, reads it from
/// the VM's `/health/detail` and fires nothing (the log says why). Once the
/// exec ended, the next chat's close, with no other spawn left, suspends the
/// VM: one SuspendMicrovm.
#[test]
fn a_closing_suspend_keeps_a_vm_where_a_vm_exec_spawn_lives() {
    let mut chat = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &[]);
    started(&mut chat);
    let rig = chat.rig();
    let vms: Vec<String> = rig.fake().vms.keys().cloned().collect();
    assert_eq!(vms.len(), 1, "the chat's VM alone: {vms:?}");
    let vm = vms[0].clone();
    let mut exec = rig.ai_env(&["vm", "exec", &vm, "--", "claude"]);
    exec.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut exec = exec.spawn().expect("spawn vm exec");
    wait_for("the vm exec's CLI alive on the VM beside the chat's", T, || rig.shim.spawns.detail().iter().filter(|d| d.status.alive).count() == 2);
    closed(&mut chat);
    let kept = format!("closing: no suspend of {vm} (a spawn still lives on the VM)");
    wait_for("the chat's close kept the VM", T, || chat.wrapper_log().contains(&kept));
    assert_eq!(suspends(chat.rig()), 0, "no SuspendMicrovm while the vm exec's CLI lives");
    drop(exec.stdin.take());
    let o = common::bounded::finish_within(exec, common::remote::LIMIT, "vm exec");
    assert_eq!(o.status.code(), Some(0), "vm exec: {}", String::from_utf8_lossy(&o.stderr));
    let rig = chat.rig();
    let mut again = Harness::prepare().launch_wrapper(rig.wrapper(&[], &[]));
    started(&mut again);
    closed(&mut again);
    assert_eq!(part_of(&end_note_of(&chat, again.pid()), "vm").as_deref(), Some(vm.as_str()), "the same VM");
    wait_for("the lone chat's closing suspend", Duration::from_secs(10), || suspends(rig) == 1);
}

/// S7's `cached_on_vm` end to end: without `combined.env`, a session on a
/// VM whose cache holds the token (an open session delivered it) reads that
/// from the VM's `/health/detail` and unseals nothing but the runtime key:
/// one Touch ID (D1), where the cold session cost two; the token went to the
/// VM once, and the second CLI got the cached copy (`credential:cached`).
#[test]
fn without_combined_env_a_session_on_a_vm_holding_the_token_costs_one_touch_id() {
    let mut p = Harness::prepare();
    let touch = {
        let rig = p.rig();
        std::fs::remove_file(rig.bridge().join("credentials").join("combined.env")).expect("remove combined.env");
        rig.decrypts()
    };
    let mut first = p.spawn_on(common::Link::Remote, "", &[], &[]);
    started(&mut first);
    assert_eq!(first.rig().decrypts() - touch, 2, "the cold session: the runtime key's Touch ID, then the token's");
    let mut second = Harness::prepare().launch_wrapper(first.rig().wrapper(&[], &[]));
    started(&mut second);
    closed(&mut second);
    closed(&mut first);
    assert_eq!(first.rig().decrypts() - touch, 3, "the second session: the runtime key's Touch ID alone");
    let tokens: Vec<Value> = first.audit_events("credential_unseal").into_iter().filter(|r| r["detail"]["source"] == "setup-token").collect();
    assert_eq!(tokens.len(), 1, "the token unsealed once: {tokens:?}");
    assert_eq!(first.audit_events("credential_deliver").len(), 1, "the token went to the VM once");
    let (one, two) = (end_note_of(&first, first.pid()), end_note_of(&first, second.pid()));
    assert_eq!(part_of(&one, "vm"), part_of(&two, "vm"), "one VM");
    assert_eq!((part_of(&one, "credential").as_deref(), part_of(&two, "credential").as_deref()), (Some("setup-token"), Some("cached")), "{one}\n{two}");
}

/// The fake's init as 2.1.x sends it (plans/s2-measurements.md): with
/// FAKE_INIT_AT_TURN, one init per turn under the session's id and none
/// without a turn (a config probe's shape); and every process after the
/// first on one spawn counter names a session of its own, unless it
/// resumes one. The default (the init after `initialize`, the first
/// process's fixed id) is unchanged.
#[test]
fn the_fake_says_an_init_per_turn_and_each_process_its_own_session() {
    let f = Fake::new();
    let count = f.root.join("spawn.count");
    let counter = [("FAKE_SPAWN_COUNT", count.to_str().unwrap())];
    let inits = |out: &[String]| -> Vec<Value> { json_lines(out).into_iter().filter(is_init).collect() };
    let (u1, u2) = (common::uuid(0x8811), common::uuid(0x8812));
    // Generation 1, the default: the init right after initialize, the fixed id.
    let (code, out, err) = f.run(&[], &counter, &format!("{INIT}\n{}\n", user(&u1)));
    assert_eq!(code, Some(0), "{err}");
    let first = inits(&out);
    assert_eq!(first.len(), 1, "{out:?}");
    assert_eq!(first[0]["session_id"].as_str(), Some(common::fake_fixed_sid().as_str()));
    let at_turn = [counter[0], ("FAKE_INIT_AT_TURN", "1")];
    // Generation 2, a config probe's shape: initialize, then EOF; no init.
    let (code, out, err) = f.run(&[], &at_turn, &format!("{INIT}\n"));
    assert_eq!((code, inits(&out).len()), (Some(0), 0), "{err}{out:?}");
    // Generation 3, two turns: an init with each, before its result, under its own id.
    let (code, out, err) = f.run(&[], &at_turn, &format!("{INIT}\n{}\n{}\n", user(&u1), user(&u2)));
    assert_eq!(code, Some(0), "{err}");
    let own = common::uuid(3054 + 65536 * 3);
    let frames = json_lines(&out);
    let at = |pred: &dyn Fn(&Value) -> bool| frames.iter().position(pred).unwrap_or_else(|| panic!("{out:?}"));
    let init_at: Vec<usize> = frames.iter().enumerate().filter(|(_, v)| is_init(v)).map(|(i, _)| i).collect();
    assert_eq!(init_at.len(), 2, "{out:?}");
    assert!(init_at[0] < at(&|v| is_result_for(v, &u1)) && at(&|v| is_result_for(v, &u1)) < init_at[1] && init_at[1] < at(&|v| is_result_for(v, &u2)), "each turn's init before its result: {out:?}");
    assert!(init_at.iter().all(|&i| frames[i]["session_id"].as_str() == Some(own.as_str())), "generation 3's own id: {out:?}");
    // Generation 4 resumes: the --resume id, as ever.
    let resumed = common::uuid(0x8813);
    let (code, out, err) = f.run(&["--resume", &resumed], &counter, &format!("{INIT}\n"));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(inits(&out).first().and_then(|v| v["session_id"].as_str()), Some(resumed.as_str()));
}

// ---- S9 phase 0: the tests' S3 and the fake curl ------------------------------------------

/// One HTTP/1.1 request to `url` (`http://<host:port><target>`) on a
/// connection of its own: `headers` as given, then `body` (a
/// `Content-Length` added for a body unless `headers` name one), read to the
/// server's close: (status, lowercased headers, body).
fn http_call(method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use std::io::{Read as _, Write as _};
    let rest = url.strip_prefix("http://").unwrap_or_else(|| panic!("not an http URL: {url}"));
    let (host, target) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let mut stream = std::net::TcpStream::connect(host).unwrap_or_else(|e| panic!("connect {host}: {e}"));
    stream.set_read_timeout(Some(T)).expect("a read timeout");
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).expect("send the head");
    stream.write_all(body).expect("send the body");
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).expect("read the answer");
    let end = answer.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| panic!("no head: {}", String::from_utf8_lossy(&answer)));
    let text = String::from_utf8_lossy(&answer[..end]).into_owned();
    let mut lines = text.split("\r\n");
    let status = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("no status: {text}"));
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    (status, headers, answer[end + 4..].to_vec())
}

/// The value of the (lowercase) header `name` among `headers`.
fn header_of<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// The `<Code>` of an S3 error body (empty for none).
fn s3_code(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    text.split_once("<Code>").and_then(|(_, rest)| rest.split_once("</Code>")).map(|(code, _)| code.to_string()).unwrap_or_default()
}

/// Lowercase hex of `bytes`' sha256.
fn sha256_of(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// S9 phase 0: the tests' S3 (`common::fake_s3`, plans/s9-contracts.md
/// §8.1) takes what is signed with the lab's key and refuses what S3 does:
/// a signature that is not the request's (tampered, or a query changed
/// after signing), a URL past its expiry, an unsigned `x-amz-*` header, a
/// bucket owner not sent, not `LAB_OWNER` or never signed, another bucket;
/// a PUT without its length or chunked, a checksum not its body's,
/// `If-None-Match: *` over an object. It keeps versions (read back by id; a
/// delete is a marker), lists the current objects, assembles a multipart
/// upload from its parts in order, and records every request without a
/// signature's value; a script answers a status, cuts a read, or waits.
#[test]
fn the_fake_s3_checks_signatures_checksums_and_conditions() {
    use ai_env_cli::bridge::s3::{LAB_BUCKET, LAB_KEY_ID, LAB_OWNER};
    use ai_env_cli::wire::s3::{sha256_b64, S3Key, SIGNED_HEADERS_GET, SIGNED_HEADERS_PUT};
    use common::fake_s3::{FakeS3, S3Action};
    let s3 = FakeS3::start();
    assert_eq!(s3.bucket(), LAB_BUCKET);
    let ttl = Duration::from_secs(300);
    let sid = common::uuid(0x9001);
    let key = S3Key::Base { session: sid.clone(), gen: 1 }.render();
    let owner = ("x-amz-expected-bucket-owner", LAB_OWNER);
    // A PUT as the shim's curl sends it: its length, its checksum, If-None-Match and the owner, all signed.
    let put = |key: &str, body: &[u8], checksum: &str| {
        let len = body.len().to_string();
        let url = s3.presign("PUT", key, &[], &[("content-length", len.as_str()), ("if-none-match", "*"), ("x-amz-checksum-sha256", checksum)], ttl);
        http_call("PUT", &url, &[("Content-Length", len.as_str()), ("If-None-Match", "*"), ("x-amz-checksum-sha256", checksum), owner], body)
    };
    let refused = |method: &str, url: &str, headers: &[(&str, &str)]| {
        let (status, _, body) = http_call(method, url, headers, b"");
        (status, s3_code(&body))
    };
    let one = b"line 1\n";
    let b64 = sha256_b64(&sha256_of(one)).expect("a sha256's base64");
    let etag = format!("\"{}\"", &sha256_of(one)[..32]);
    let (status, headers, _) = put(&key, one, &b64);
    assert_eq!((status, header_of(&headers, "x-amz-version-id"), header_of(&headers, "etag"), header_of(&headers, "x-amz-checksum-sha256")), (200, Some("fv1"), Some(etag.as_str()), Some(b64.as_str())));
    let (status, _, body) = put(&key, one, &b64);
    assert_eq!((status, s3_code(&body)), (412, "PreconditionFailed".to_string()), "If-None-Match: * over the current version");
    let other = S3Key::Base { session: sid.clone(), gen: 2 }.render();
    let (status, _, body) = put(&other, b"not those bytes\n", &b64);
    assert_eq!((status, s3_code(&body)), (400, "BadDigest".to_string()));
    let no_length = s3.presign("PUT", &other, &[], &[], ttl);
    assert_eq!(refused("PUT", &no_length, &[owner]), (411, "MissingContentLength".to_string()));
    assert_eq!(refused("PUT", &no_length, &[owner, ("Transfer-Encoding", "chunked")]), (501, "NotImplemented".to_string()));
    // A GET. No client of ours sends x-amz-checksum-mode (a pull checks each part's sha256 itself); sent
    // unsigned, as with any x-amz-* header, S3 refuses it.
    let get_url = s3.presign("GET", &key, &[], &[], ttl);
    let (status, _, body) = http_call("GET", &get_url, &[owner], b"");
    assert_eq!((status, body.as_slice()), (200, &one[..]));
    assert_eq!(refused("GET", &get_url, &[owner, ("x-amz-checksum-mode", "ENABLED")]), (403, "AccessDenied".to_string()), "x-amz-checksum-mode unsigned");
    // The refusals.
    let signature = get_url.split("X-Amz-Signature=").nth(1).expect("a signature").to_string();
    let flipped = format!("{}{}", &signature[..signature.len() - 1], if signature.ends_with('0') { '1' } else { '0' });
    assert_eq!(refused("GET", &get_url.replace(&signature, &flipped), &[owner]), (403, "SignatureDoesNotMatch".to_string()));
    let versioned = s3.presign("GET", &key, &[("versionId", "fv1")], &[], ttl);
    assert_eq!(refused("GET", &versioned.replace("versionId=fv1", "versionId=fv2"), &[owner]), (403, "SignatureDoesNotMatch".to_string()), "a query changed after signing");
    assert_eq!(refused("GET", &s3.presign("GET", &key, &[], &[], Duration::ZERO), &[owner]), (403, "AccessDenied".to_string()), "past its expiry");
    assert_eq!(refused("GET", &get_url, &[owner, ("x-amz-meta-note", "unsigned")]), (403, "AccessDenied".to_string()), "an unsigned x-amz-* header");
    assert_eq!(refused("GET", &get_url, &[("x-amz-expected-bucket-owner", "another-owner")]), (403, "AccessDenied".to_string()), "another owner");
    assert_eq!(refused("GET", &get_url, &[]), (403, "AccessDenied".to_string()), "no owner sent");
    let unsigned_owner = get_url.replace("X-Amz-SignedHeaders=host%3Bx-amz-expected-bucket-owner", "X-Amz-SignedHeaders=host");
    assert_ne!(unsigned_owner, get_url);
    assert_eq!(refused("GET", &unsigned_owner, &[]), (403, "AccessDenied".to_string()), "the owner never signed");
    assert_eq!(refused("GET", &get_url.replace(LAB_BUCKET, "another-bucket"), &[owner]), (404, "NoSuchBucket".to_string()));
    // Versions: a second one, the first read back by its id; a delete is a marker over both.
    assert_eq!(s3.put(&key, b"line 1\nline 2\n"), "fv2");
    let (status, _, body) = http_call("GET", &versioned, &[owner], b"");
    assert_eq!((status, body.as_slice()), (200, &one[..]));
    assert_eq!(refused("GET", &s3.presign("GET", &key, &[("versionId", "fv9")], &[], ttl), &[owner]), (404, "NoSuchVersion".to_string()));
    let (status, headers, _) = http_call("DELETE", &s3.presign("DELETE", &key, &[], &[], ttl), &[owner], b"");
    assert_eq!((status, header_of(&headers, "x-amz-delete-marker")), (204, Some("true")));
    assert_eq!(refused("GET", &get_url, &[owner]), (404, "NoSuchKey".to_string()), "behind the marker");
    assert_eq!(s3.get(&key), None);
    let versions: Vec<(String, bool, bool)> = s3.objects().into_iter().filter(|o| o.key == key).map(|o| (o.version_id, o.delete_marker, o.current)).collect();
    assert_eq!(versions, [("fv1".to_string(), false, false), ("fv2".to_string(), false, false), ("fv3".to_string(), true, true)]);
    // ListObjectsV2: the current objects alone.
    assert_eq!(s3.put(&other, b"other\n"), "fv4");
    let (status, _, body) = http_call("GET", &s3.presign("GET", "", &[("list-type", "2"), ("prefix", "v1/")], &[], ttl), &[owner], b"");
    let listed = String::from_utf8_lossy(&body).into_owned();
    assert!(status == 200 && listed.contains(&format!("<Key>{other}</Key>")) && !listed.contains(&format!("<Key>{key}</Key>")), "{status}: {listed}");
    // Multipart: initiate, two parts with their checksums, ListParts, complete in order.
    let big = S3Key::Segment { session: sid.clone(), gen: 1, offset: 0 }.render();
    let (status, _, body) = http_call("POST", &s3.presign("POST", &big, &[("uploads", "")], &[], ttl), &[owner], b"");
    let text = String::from_utf8_lossy(&body).into_owned();
    let upload = text.split_once("<UploadId>").and_then(|(_, r)| r.split_once("</UploadId>")).map(|(id, _)| id.to_string()).unwrap_or_else(|| panic!("{status}: {text}"));
    let parts: [&[u8]; 2] = [b"the first part\n", b"the second part\n"];
    let mut tags = Vec::new();
    for (n, part) in parts.iter().enumerate() {
        let (number, len, sum) = ((n + 1).to_string(), part.len().to_string(), sha256_b64(&sha256_of(part)).expect("a sha256's base64"));
        let url = s3.presign("PUT", &big, &[("partNumber", number.as_str()), ("uploadId", upload.as_str())], &[("content-length", len.as_str()), ("x-amz-checksum-sha256", sum.as_str())], ttl);
        let (status, headers, _) = http_call("PUT", &url, &[("Content-Length", len.as_str()), ("x-amz-checksum-sha256", sum.as_str()), owner], part);
        assert_eq!(status, 200, "part {number}");
        tags.push(header_of(&headers, "etag").expect("a part's ETag").to_string());
    }
    let (status, _, body) = http_call("GET", &s3.presign("GET", &big, &[("uploadId", upload.as_str())], &[], ttl), &[owner], b"");
    assert!(status == 200 && String::from_utf8_lossy(&body).matches("<Part>").count() == 2, "ListParts: {}", String::from_utf8_lossy(&body));
    let complete: String = tags.iter().enumerate().map(|(n, tag)| format!("<Part><PartNumber>{}</PartNumber><ETag>{tag}</ETag></Part>", n + 1)).collect();
    let complete = format!("<CompleteMultipartUpload>{complete}</CompleteMultipartUpload>");
    let (status, _, body) = http_call("POST", &s3.presign("POST", &big, &[("uploadId", upload.as_str())], &[], ttl), &[owner], complete.as_bytes());
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(s3.get(&big), Some(parts.concat()));
    // The script: a status, a cut read, a wait; each taken by one request.
    s3.script(vec![S3Action::Status { status: 503, code: "SlowDown" }, S3Action::CutAfter { bytes: 3 }, S3Action::Delay(Duration::from_millis(300))]);
    let current = s3.presign("GET", &other, &[], &[], ttl);
    assert_eq!(refused("GET", &current, &[owner]), (503, "SlowDown".to_string()));
    let (status, headers, body) = http_call("GET", &current, &[owner], b"");
    assert_eq!((status, header_of(&headers, "content-length"), body.as_slice()), (200, Some("6"), &b"oth"[..]), "cut after 3 of its 6 bytes");
    let asked = std::time::Instant::now();
    let (status, _, body) = http_call("GET", &current, &[owner], b"");
    assert!(status == 200 && body == b"other\n" && asked.elapsed() >= Duration::from_millis(300), "{status} after {:?}", asked.elapsed());
    // The records: every request, its names and signed headers, never a signature's or a credential's value.
    let requests = s3.requests();
    let first = &requests[0];
    assert_eq!((first.method.as_str(), first.key.as_str(), first.content_length, first.chunked, first.status, first.code.as_deref()), ("PUT", key.as_str(), Some(7), false, 200, None));
    assert_eq!((first.signed_headers.join(";"), first.query_names.clone()), (SIGNED_HEADERS_PUT.to_string(), ["X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature"].map(String::from).to_vec()));
    let got = requests.iter().find(|r| r.method == "GET" && r.status == 200).expect("the GET");
    assert_eq!(got.signed_headers.join(";"), SIGNED_HEADERS_GET);
    assert!(requests.iter().any(|r| r.chunked && r.status == 501) && requests.iter().filter(|r| r.status == 0).count() == 1, "{requests:?}");
    let shown = format!("{requests:?}");
    assert!(!shown.contains(&signature) && !shown.contains(LAB_KEY_ID), "{shown}");
}

/// S9 phase 0: the fake curl (`tests/fakes/s3-curl.sh`, §8.2) runs only as
/// `-q -K /dev/fd/3` (exit 2 else; `--version` lists https) and logs who ran
/// it, the descriptors it started with, the configuration fd 3 carried
/// (kept as `<log>.<n>.config`) and its argv. With its knobs file alone it
/// plays S3 (a PUT's body kept, a GET's body written, the status line on
/// stderr, an error's `<Code>`, an exit of its own); with `S3CURL_REAL` it
/// hands the configuration to a real curl, here against the tests' S3.
#[test]
fn the_fake_curl_logs_its_fd_3_config_and_plays_s3() {
    use ai_env_cli::bridge::s3::LAB_OWNER;
    use ai_env_cli::wire::s3::{sha256_b64, S3Key};
    use common::fake_s3::FakeS3;
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let (curl, log) = (root.join("curl"), root.join("curl.log"));
    // The shim's call: the configuration on fd 3 alone, an environment of PATH and LC_ALL.
    let run = |config: &str, stdin: &[u8]| {
        let file = root.join("config.in");
        std::fs::write(&file, config).unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("exec \"$0\" -q -K /dev/fd/3 3<\"$1\"").arg(&curl).arg(&file).env_clear().env("PATH", "/usr/bin:/bin").env("LC_ALL", "C");
        // fd 3 alone, as the shim's spawn leaves it: never a pipe a parallel test's spawn had open for a moment.
        common::without_stray_fds(&mut cmd);
        let o = common::bounded::run_within(cmd, Some(stdin), T, "the fake curl");
        (o.status.code(), o.stdout, String::from_utf8_lossy(&o.stderr).into_owned())
    };
    let config = |url: &str, proto: &str, tail: &[String]| {
        let write_out = r#"write-out = "%{stderr}ai-env-curl status=%{http_code} version=%header{x-amz-version-id} checksum=%header{x-amz-checksum-sha256} etag=%header{etag}\n""#;
        let mut lines = vec![format!("url = \"{url}\""), "silent".to_string(), "show-error".to_string(), format!("proto = \"={proto}\""), "connect-timeout = 20".to_string(), "max-time = 60".to_string(), write_out.to_string()];
        lines.extend_from_slice(tail);
        lines.join("\n") + "\n"
    };
    let put_tail = |len: usize, sum: &str| {
        let head = |h: &str| format!("header = \"{h}\"");
        vec!["request = \"PUT\"".to_string(), "upload-file = \"-\"".to_string(), head(&format!("Content-Length: {len}")), head("Transfer-Encoding:"), head("Expect:"), head(&format!("x-amz-checksum-sha256: {sum}")), head("If-None-Match: *"), head(&format!("x-amz-expected-bucket-owner: {LAB_OWNER}")), "output = \"-\"".to_string()]
    };
    let get_tail = vec!["request = \"GET\"".to_string(), format!("header = \"x-amz-expected-bucket-owner: {LAB_OWNER}\""), "fail".to_string(), "output = \"-\"".to_string()];
    let body = b"line 1\n";
    let sum = sha256_b64(&sha256_of(body)).expect("a sha256's base64");
    // Played: never reached.
    let url = "https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/v1/k";
    let saved = root.join("saved");
    common::install_fake_curl(&curl, &log, &[("S3CURL_SAVE", saved.to_str().unwrap())]);
    let put = config(url, "https", &put_tail(body.len(), &sum));
    let (code, out, err) = run(&put, body);
    assert_eq!((code, out.as_slice()), (Some(0), &b""[..]), "{err}");
    assert_eq!(err, format!("ai-env-curl status=200 version=fake-version-1 checksum={sum} etag=\"fake-1\"\n"));
    assert_eq!(std::fs::read(saved.join("1.put")).unwrap(), body, "the PUT's body, read to its end");
    let held = root.join("held");
    std::fs::write(&held, "held\n").unwrap();
    common::install_fake_curl(&curl, &log, &[("S3CURL_BODY", held.to_str().unwrap()), ("S3CURL_VERSION", "fv7")]);
    let get = config(url, "https", &get_tail);
    let (code, out, err) = run(&get, b"");
    assert_eq!((code, out.as_slice(), err.as_str()), (Some(0), &b"held\n"[..], "ai-env-curl status=200 version=fv7 checksum= etag=\"fake-2\"\n"));
    common::install_fake_curl(&curl, &log, &[("S3CURL_STATUS", "412"), ("S3CURL_CODE", "PreconditionFailed")]);
    let (code, out, err) = run(&put, body);
    assert_eq!((code, String::from_utf8_lossy(&out).into_owned()), (Some(0), "<Error><Code>PreconditionFailed</Code></Error>".to_string()), "{err}");
    assert!(err.starts_with("ai-env-curl status=412 "), "{err}");
    common::install_fake_curl(&curl, &log, &[("S3CURL_STATUS", "404"), ("S3CURL_BODY", held.to_str().unwrap())]);
    let (code, out, err) = run(&get, b"");
    assert_eq!((code, out.as_slice()), (Some(0), &b""[..]), "a GET that says `fail` writes nothing: {err}");
    common::install_fake_curl(&curl, &log, &[("S3CURL_FAIL", "28")]);
    let (code, _, err) = run(&get, b"");
    assert_eq!((code, err.as_str()), (Some(28), ""), "an exit of its own, no status line");
    for (args, code, stream) in [(&["-s", "https://example.invalid/"][..], 2, "fake curl: unexpected argv\n"), (&["--version"][..], 0, "")] {
        let mut cmd = Command::new(&curl);
        cmd.args(args).env_clear();
        let o = common::bounded::run_within(cmd, None, T, "the fake curl");
        assert_eq!((o.status.code(), String::from_utf8_lossy(&o.stderr).into_owned()), (Some(code), stream.to_string()), "{args:?}");
        if code == 0 {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            assert!(text.starts_with("curl 8.11.1 ") && text.lines().any(|l| l.starts_with("Protocols:") && l.split_whitespace().any(|p| p == "https")), "{text}");
        }
    }
    let calls = common::curl_calls(&log);
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    assert_eq!(calls.len(), 5, "every call with the right argv, and those alone: {calls:?}");
    assert!(calls.iter().all(|c| c.uid == uid && c.fds == [3] && c.args == ["-q", "-K", "/dev/fd/3"]), "{calls:?}");
    assert_eq!((calls[0].config.as_str(), calls[1].config.as_str()), (put.as_str(), get.as_str()), "fd 3's bytes, as they came");
    assert_eq!((calls[0].conf("url"), calls[0].conf("header").len(), calls[1].conf("fail")), (vec![url.to_string()], 6, vec![String::new()]));
    assert_eq!(std::fs::read_to_string(root.join("curl.log.2.config")).unwrap(), get, "kept as <log>.<n>.config");
    // S3CURL_REAL: the real curl takes the same configuration, here against the tests' S3.
    let s3 = FakeS3::start();
    let key = S3Key::Base { session: common::uuid(0x9002), gen: 1 }.render();
    let len = body.len().to_string();
    let put_url = s3.presign("PUT", &key, &[], &[("content-length", len.as_str()), ("if-none-match", "*"), ("x-amz-checksum-sha256", sum.as_str())], Duration::from_secs(300));
    common::install_fake_curl(&curl, &log, &[("S3CURL_REAL", "/usr/bin/curl")]);
    let (code, out, err) = run(&config(&put_url, "http", &put_tail(body.len(), &sum)), body);
    let etag = format!("\"{}\"", &sha256_of(body)[..32]);
    assert_eq!((code, out.as_slice(), err), (Some(0), &b""[..], format!("ai-env-curl status=200 version=fv1 checksum={sum} etag={etag}\n")));
    assert_eq!(s3.get(&key).as_deref(), Some(&body[..]));
    let get_url = s3.presign("GET", &key, &[], &[], Duration::from_secs(300));
    let (code, out, err) = run(&config(&get_url, "http", &get_tail), b"");
    assert_eq!((code, out.as_slice(), err), (Some(0), &body[..], format!("ai-env-curl status=200 version=fv1 checksum= etag={etag}\n")));
    let calls = common::curl_calls(&log);
    assert_eq!((calls.len(), calls[5].conf("url"), calls[6].conf("url")), (7, vec![put_url], vec![get_url]), "the real curl's calls logged too");
    assert!(s3.requests().iter().all(|r| r.status == 200), "{:?}", s3.requests());
}

/// S9 (D9, G5; plans/s9-contracts.md §10): a remote chat's transcript is
/// kept in S3, never on this Mac. The VM's CLI
/// runs without `--session-mirror`; the one frame it prints anyway (the
/// fake's last one after the EOF) is dropped and counted: the end row says
/// `mirror:0/0` then `mirror_dropped:1`. Nothing under the Mac's projects
/// directory holds a line of the VM's transcript: what is there, if
/// anything, is the chat's view (each file's head the view's mark).
#[test]
fn a_remote_session_writes_no_mirror() {
    let knobs = [("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_FINAL_MIRROR_MS", "200"), ("FAKE_EXIT_DELAY_MS", "400")];
    let mut h = Harness::prepare().spawn_on(common::Link::Remote, "", &[], &knobs);
    started(&mut h);
    turn(&mut h, "hello");
    closed(&mut h);
    let argv = read(&h.root().join("argv.log"));
    assert!(!argv.lines().any(|l| l == "--session-mirror"), "{argv}");
    let note = h.end_note();
    assert!(common::note_has(&note, "mirror:0/0") && common::note_has(&note, "mirror_dropped:1"), "{note}");
    assert!(note.contains("; mirror:0/0; mirror_dropped:1; dropped:"), "right after the mirror part: {note}");
    let vm = read(&h.rig().vm_projects().join(h.slug()).join(format!("{}.jsonl", common::fake_fixed_sid())));
    let needles: Vec<String> = vm.lines().filter(|l| l.contains("\"uuid\"") || l.contains("\"type\":\"summary\"")).map(str::to_string).collect();
    assert!(!needles.is_empty(), "the VM's transcript holds the turn: {vm}");
    let mac = h.prepared.mac_projects();
    assert!(holding(&[&mac], &needles).is_empty(), "no line of the VM's transcript on the Mac");
    for rel in files_under(&mac) {
        let head: Vec<u8> = std::fs::read(mac.join(&rel)).unwrap().into_iter().take(ai_env_cli::wire::view::VIEW_HEAD_READ).collect();
        assert!(ai_env_cli::wire::view::is_view_head(&head), "{rel} is a view, if anything");
    }
}
