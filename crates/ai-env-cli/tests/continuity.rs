//! T10 (S10): the continuity engine end to end, offline. The real
//! `ai-env-claude` in remote mode on the multi-VM rig (`common::remote`, one
//! in-process shim per fake VM): a re-address after a lost VM, a respawn on a
//! live one, a migration before the wall, a reopen near or after the wall,
//! `ai-env session migrate`, and the reaper (plans/s10-contracts.md §11.3).
//! Declared in S10 phase 0; S10 wave 1b (C) writes the tests here, wave 1a
//! (R) the rig's and the fakes' own self-tests (`continuity/rig.rs`).
//!
//! S10 wave 1b (C1): a lost VM moves the chat (§A). The platform ends a VM
//! here by fake surgery: the fake's state says TERMINATING (no
//! TerminateMicrovm, no sync from the Mac first), and the endpoint's next look
//! posts its `/terminate`, as the platform does. The fake claude runs as the
//! real CLI does (`FAKE_INIT_AT_TURN`: an init per turn), its transcript
//! written and needed for a resume.
//!
//! S10 wave 1c (C3): a VM near its wall moves the chat before it (§B: phase
//! A in the background, the switch at a quiet point), a reopen near the wall
//! or after it carries the chat before its CLI starts (§2.7), `ai-env
//! session migrate` asks a live wrapper for that move (§7.1), and the reaper
//! ends a claude a dead wrapper left parked (D5). The wall comes near by
//! `bring_wall_near` (the fake's start and the Mac's row aged alike), the
//! platform's own end of it by the fake's wall (`enforce_wall`).
mod common;
#[path = "continuity/rig.rs"]
mod rig;

use ai_env_cli::bridge::api::{Call, FakeFailure, VmState};
use ai_env_cli::wire::frame::{ParkOwner, SpawnId};
use common::remote::RemoteRig;
use common::{fake_reply_uuid, fake_tool_use_uuid, is_echo_of, is_init, is_response_to, is_result_for, note_has, Harness, Link};
use serde_json::value::RawValue;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Every wait's bound.
const T: Duration = Duration::from_secs(60);
const EXIT: Duration = Duration::from_secs(30);
/// The fake claude as the real CLI is: an init with each turn, its transcript written, a resume needing it.
const CLI: [(&str, &str); 3] = [("FAKE_INIT_AT_TURN", "1"), ("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_RESUME_NEEDS_FILE", "1")];

/// Part B (22 Oct): a move's line sent again is the host's line under a
/// fresh uuid (claude skips a line whose uuid its session holds, which
/// `FAKE_DEDUP_RESUMED` models in the moves that send one again): the same
/// JSON but its `uuid`, and that one another.
fn resent_as(got: Option<&String>, want: &str) -> bool {
    let (Some(got), Ok(mut want)) = (got.and_then(|g| serde_json::from_str::<serde_json::Value>(g).ok()), serde_json::from_str::<serde_json::Value>(want)) else { return false };
    let mut got = got;
    let fresh = got["uuid"].as_str().map(str::to_string);
    let own = want["uuid"].as_str().map(str::to_string);
    got["uuid"] = serde_json::Value::Null;
    want["uuid"] = serde_json::Value::Null;
    fresh.is_some() && fresh != own && got == want
}

/// `CLI`'s knobs, then `more`.
fn knobs<'a>(more: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    CLI.iter().copied().chain(more.iter().copied()).collect()
}

/// The host's start: `initialize`, `set_permission_mode` and
/// `apply_flag_settings{model}`, each answered; their ids, in that order.
fn started(h: &mut Harness) -> [String; 3] {
    let ids = [h.send_initialize(), h.send_control("set_permission_mode", r#"{"mode":"acceptEdits"}"#), h.send_control("apply_flag_settings", r#"{"settings":{"model":"claude-x"}}"#)];
    for id in &ids {
        h.expect_out(|v| is_response_to(v, id), T);
    }
    ids
}

/// One turn to its result: the user line's uuid.
fn turn(h: &mut Harness, text: &str) -> String {
    let u = h.send_user(text);
    h.expect_out(|v| is_result_for(v, &u), T);
    u
}

/// The host's EOF, then the exit, which must be 0.
fn closed(h: &mut Harness) {
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
}

/// The session id the CLI's first init named.
fn session_of(h: &mut Harness) -> String {
    let init = h.expect_out(is_init, T);
    init["session_id"].as_str().expect("the init's session id").to_string()
}

/// Until `views` views of session `sid`'s transcript were written: each
/// turn's code-out, then its transcript synced to S3, then its view.
fn synced(h: &mut Harness, sid: &str, views: usize) {
    h.wait_until("the turn's transcript synced to S3 and its view written", T, |h| {
        h.audit_events("transcript_view").iter().filter(|r| r["detail"]["session"] == sid && r["detail"]["outcome"] == "written").count() >= views
    });
}

/// The VM of each generation that started, in order (`session_remote_start`).
fn vms_started(h: &Harness) -> Vec<String> {
    h.audit_events("session_remote_start").iter().map(|r| r["detail"]["id"].as_str().expect("the VM").to_string()).collect()
}

/// The platform ends `vm` (the module doc's fake surgery).
fn platform_ends(rig: &RemoteRig, vm: &str) {
    rig.update_fake(|s| {
        let v = s.vms.get_mut(vm).unwrap_or_else(|| panic!("no VM {vm} in the fake"));
        v.state = VmState::Terminating;
        v.state_reason = Some("ended by the test".into());
    });
}

/// The note (L3, E4) that the chat moves off `vm` with the next message (L5).
fn moves_with_the_next_message(h: &mut Harness, vm: &str) {
    h.expect_out(|v| v["subtype"] == "informational" && v["content"].as_str().is_some_and(|c| c.contains(vm) && c.contains("with your next message")), T);
}

/// The client tokens of the RunMicrovm calls the fake took, in order.
fn run_tokens(rig: &RemoteRig) -> Vec<String> {
    rig.fake_calls().into_iter().filter_map(|c| if let Call::Run { client_token } = c { Some(client_token) } else { None }).collect()
}

/// The registry row's `vms` entries (the one row of the session).
fn vms_entries(h: &Harness) -> Vec<toml::Value> {
    let rows = h.registry_rows();
    assert_eq!(rows.len(), 1, "{rows:#?}");
    rows[0].get("vms").and_then(toml::Value::as_array).cloned().unwrap_or_default()
}

/// The top-level members of a JSON object line, as raw slices.
fn members(line: &str) -> BTreeMap<String, Box<RawValue>> {
    serde_json::from_str(line).unwrap_or_else(|e| panic!("not a JSON object line ({e}): {line}"))
}

/// `request_id` and the raw `request` object of a control_request line, as written.
fn request_parts(line: &str) -> (String, String) {
    let m = members(line);
    let id: String = serde_json::from_str(m.get("request_id").unwrap_or_else(|| panic!("no request_id: {line}")).get()).expect("a string id");
    (id, m.get("request").unwrap_or_else(|| panic!("no request: {line}")).get().to_string())
}

/// `stdin_of(gen)` starts with the host's three requests under fresh ids,
/// each request object byte for byte the host's (`sent`, the host's lines).
fn replayed_state(h: &Harness, gen: u32) -> Vec<String> {
    let lines = h.stdin_of(gen);
    assert!(lines.len() >= 3, "generation {gen} read the host's state again: {lines:#?}");
    for (i, sub) in ["initialize", "set_permission_mode", "apply_flag_settings"].into_iter().enumerate() {
        let (id, request) = request_parts(&lines[i]);
        let (host_id, host_request) = request_parts(&h.sent[i]);
        assert_ne!(id, host_id, "generation {gen}'s {sub} under a fresh id: {}", lines[i]);
        assert_eq!(request, host_request, "generation {gen}'s {sub}: the host's request, byte for byte");
    }
    lines
}

/// The audit rows, and the index of the first of `event` whose detail `pred` takes.
fn index_of(rows: &[Value], event: &str, pred: impl Fn(&Value) -> bool) -> usize {
    rows.iter().position(|r| r["event"] == event && pred(&r["detail"])).unwrap_or_else(|| panic!("no {event} row as asked: {rows:#?}"))
}

/// The value of `name` in a census note (`name:value`).
fn part_of(note: &str, name: &str) -> Option<String> {
    note.split("; ").find_map(|p| p.strip_prefix(name)?.strip_prefix(':')).map(str::to_string)
}

/// `git args` in `dir` (the real git, no config of the user's): its stdout, trimmed.
fn git_in(dir: &Path, args: &[&str]) -> String {
    let o = std::process::Command::new(common::git_real())
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("run git");
    assert!(o.status.success(), "git {args:?} in {}: {}", dir.display(), String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
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

/// Until the fake's long tool started in generation `gen`'s turn `turn` (`FAKE_TURN_MARK`).
fn wait_for_mark(mark: &Path, gen: u32, turn: u32) {
    let want = format!("gen {gen} turn {turn}");
    let t = std::time::Instant::now();
    while !std::fs::read_to_string(mark).unwrap_or_default().lines().any(|l| l == want) {
        assert!(t.elapsed() < T, "{want}: the long tool never started");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The move whose `session_move` is `rows[moved]` unsealed once before its
/// VM's spawn (`rows[start]`): M1's Touch ID, the setup token's
/// (`setup-token.env`, never `combined.env`; no VM named, none chosen yet),
/// and no other unseal between them.
fn one_setup_token_unseal(rows: &[Value], moved: usize, start: usize) {
    let unseals: Vec<&Value> = rows[moved..start].iter().filter(|r| r["event"] == "credential_unseal").map(|r| &r["detail"]).collect();
    assert_eq!(unseals.len(), 1, "one Touch ID between session_move and the spawn: {:#?}", &rows[moved..start]);
    assert_eq!((unseals[0]["source"].as_str(), unseals[0]["outcome"].as_str()), (Some("setup-token"), Some("ok")), "{}", unseals[0]);
    assert!(unseals[0].get("id").is_none(), "no VM named: {}", unseals[0]);
}

/// T10.1: the platform ends the chat's VM between turns (no sync from the
/// Mac first). The next line moves the chat (L5) to a new VM: one
/// RunMicrovm, one more Touch ID (the setup token's, E4's note first:
/// `credential_unseal` `source` `setup-token`, no `id`, the only unseal
/// after `session_move`); `session_move` before the new VM's seed and its
/// transcript's pull (M2 runs them at once), both before the new VM's spawn
/// (`session_remote_start`), then `session_move_end` `done` once the moved
/// CLI resumed. Generation 2 resumes the session (`--resume=<sid>`, no cut:
/// no line was out) and reads the host's `initialize`, `set_permission_mode`
/// and `apply_flag_settings` under fresh ids, each request the host's byte
/// for byte, then the line. The host sees one init and one echo per turn,
/// each turn's stream once; the row's `vms` has 2 entries; nothing the Mac
/// keeps holds a secret; the old VM's `refs/wip/*` are as its last code-out
/// left them (L6).
#[test]
fn t10_1_a_terminated_vm_moves_once() {
    let mut p = Harness::prepare();
    let token = p.rig().token().to_string();
    let mut h = p.spawn_on(Link::Remote, "", &[], &knobs(&[("FAKE_STREAM_LINES", "3"), ("FAKE_WIP_EDIT", "agent.txt:from the VM, not committed")]));
    started(&mut h);
    let u1 = turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let rig = h.rig();
    let vm1 = vms_started(&h)[0].clone();
    let old_checkout = rig.vm_path_of(&vm1, &rig.work());
    let wips = git_in(&old_checkout, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/wip/"]);
    assert!(!wips.is_empty(), "the turn's code-out snapshot");
    let (runs, decrypts) = (run_tokens(rig).len(), rig.decrypts());
    platform_ends(rig, &vm1);
    moves_with_the_next_message(&mut h, &vm1);
    let u2 = turn(&mut h, "two");
    closed(&mut h);
    let rig = h.rig();
    let vms = vms_started(&h);
    assert_eq!(vms.len(), 2, "{vms:?}");
    assert_ne!(vms[1], vm1);
    assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "one RunMicrovm, one Touch ID");
    let rows = h.audit_rows();
    let moved = index_of(&rows, "session_move", |d| d["gen"] == "2" && d["kind"] == "readdress" && d["cause"] == "vm_gone" && d["from_vm"] == vm1.as_str());
    let seed = index_of(&rows, "seed", |d| d["vm"] == vms[1].as_str());
    let pull = index_of(&rows, "transcript_pull", |d| d["vm"] == vms[1].as_str() && d["session"] == sid.as_str());
    let start = index_of(&rows, "session_remote_start", |d| d["id"] == vms[1].as_str());
    let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["to_vm"] == vms[1].as_str());
    assert!(moved < seed && moved < pull && seed < start && pull < start && start < done, "session_move {moved}, seed {seed}, transcript_pull {pull}, session_remote_start {start}, session_move_end {done}");
    one_setup_token_unseal(&rows, moved, start);
    assert_eq!(rows[moved..].iter().filter(|r| r["event"] == "credential_unseal").count(), 1, "no unseal after the move's (no combined.env)");
    assert_eq!(rows[done]["detail"]["touchid"], "asked");
    assert_eq!(h.audit_events("session_move_end").len(), 1, "the move's one end row");
    let argv = h.argv_log();
    assert!(argv[1].contains(&format!("--resume={sid}")) && !argv[1].iter().any(|a| a.starts_with("--resume-session-at")), "{:?}", argv[1]);
    let gen2 = replayed_state(&h, 2);
    assert_eq!(gen2[3..], [h.sent[4].clone()], "then the line that moved it");
    let out = h.out_json();
    for u in [&u1, &u2] {
        assert_eq!(out.iter().filter(|v| is_echo_of(v, u)).count(), 1, "one echo of {u}");
        assert_eq!(out.iter().filter(|v| is_result_for(v, u)).count(), 1, "one result for {u}");
    }
    assert_eq!(out.iter().filter(|v| is_init(v)).count(), 2, "one init per turn");
    let stream: Vec<u64> = out.iter().filter(|v| v["type"] == "stream_event").filter_map(|v| v["n"].as_u64()).collect();
    assert_eq!(stream, [1, 2, 3, 1, 2, 3], "each turn's stream once");
    assert_eq!(vms_entries(&h).len(), 2);
    let note = h.end_note();
    assert!(note_has(&note, "moves:readdress=1,respawn=0,migrate=0") && part_of(&note, "move_ms").is_some(), "{note}");
    let needles = [token.clone(), token[13..].to_string(), common::green_world::runtime_key_secret()];
    let (bridge, mac) = (h.bridge(), h.root().join(".claude"));
    assert_eq!(holding(&[&bridge, &mac], &needles), Vec::<String>::new(), "a secret in what the Mac keeps");
    let output = format!("{}\n{}", h.out_lines().join("\n"), h.err_text());
    assert!(!needles.iter().any(|n| output.contains(n.as_str())), "a secret in the wrapper's output");
    assert_eq!(git_in(&old_checkout, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/wip/"]), wips, "no snapshot at /terminate (L6)");
    h.assert_vm_empty();
}

/// The first 8 hex digits of `token`'s sha256: what the fake's
/// `FAKE_TOKEN_LOG` says of the token a CLI read.
fn sha8(token: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(token.as_bytes()))[..8].to_string()
}

/// The `FAKE_TOKEN_LOG` lines: each CLI's generation and the sha8 of the token it read on fd 3.
fn tokens_read(log: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| (l.split(' ').nth(1).unwrap_or_default().to_string(), common::env_log_field(l, "sha8").unwrap_or_default().to_string()))
        .collect()
}

/// A1 (plans/s10-accounts-plan.md §3, its Verification): a chat on
/// account `default` (the green world's token, adopted), then `work` made
/// the active one (`accounts::install`, as `creds account use work` makes
/// it): the running claude keeps `default`. The platform ends the VM, and
/// the move re-plans: its one Touch ID unseals `work`'s installed copy (its
/// `credential_unseal` names its seal and account), the moved CLI reads
/// `work`'s token on fd 3 (`FAKE_TOKEN_LOG`'s sha8), and the records say
/// so: `session_account` (`default` to `work`), `session_remote_start`'s
/// account per generation, `session_move_end` `done` with
/// `account=work, account_from=default`, the delivery's account, the row's
/// `vms` entries, the census `account:default,work`; the chat gets the
/// account's note right after the one that it goes on. A new chat after the
/// switch runs as `work` from its start. No token is in the clear on this
/// Mac.
#[test]
fn a1_a_move_after_a_switch_runs_as_the_active_account() {
    let mut p = Harness::prepare();
    let default = p.rig().token().to_string();
    let work = p.rig().seal_account("work", "Wk");
    let log = p.root.join("token.log");
    let logged = log.display().to_string();
    let mut h = p.spawn_on(Link::Remote, "", &[], &knobs(&[("FAKE_TOKEN_LOG", logged.as_str())]));
    started(&mut h);
    turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let rig = h.rig();
    let vm1 = vms_started(&h)[0].clone();
    let installed = ai_env_cli::bridge::accounts::install(&rig.paths(), "work").expect("work installed");
    assert_eq!((installed.from.as_deref(), installed.combined), (Some("default"), ai_env_cli::bridge::accounts::CombinedInstall::Absent));
    let work_tag = installed.tag.clone();
    let decrypts = rig.decrypts();
    platform_ends(rig, &vm1);
    moves_with_the_next_message(&mut h, &vm1);
    turn(&mut h, "two");
    closed(&mut h);
    let vms = vms_started(&h);
    assert_eq!(vms.len(), 2, "{vms:?}");
    assert_eq!(h.rig().decrypts() - decrypts, 1, "the move's one Touch ID");
    assert_eq!(tokens_read(&log), [("1".to_string(), sha8(&default)), ("2".to_string(), sha8(&work))], "the moved CLI runs as work");
    let rows = h.audit_rows();
    let moved = index_of(&rows, "session_move", |d| d["gen"] == "2" && d["from_vm"] == vm1.as_str());
    let start = index_of(&rows, "session_remote_start", |d| d["id"] == vms[1].as_str());
    let unseals: Vec<&Value> = rows[moved..start].iter().filter(|r| r["event"] == "credential_unseal").map(|r| &r["detail"]).collect();
    assert_eq!(unseals.len(), 1, "{unseals:#?}");
    assert_eq!((unseals[0]["source"].as_str(), unseals[0]["tag"].as_str(), unseals[0]["account"].as_str()), (Some("setup-token"), Some(work_tag.as_str()), Some("work")));
    let accounts: Vec<Option<String>> = h.audit_events("session_remote_start").iter().map(|r| r["detail"]["account"].as_str().map(str::to_string)).collect();
    assert_eq!(accounts, [Some("default".to_string()), Some("work".to_string())]);
    let switch = h.audit_events("session_account");
    assert_eq!(switch.len(), 1, "{switch:#?}");
    let d = &switch[0]["detail"];
    assert_eq!(["gen", "kind", "from", "to", "to_tag"].map(|k| d[k].as_str().unwrap_or_default().to_string()), ["2", "readdress", "default", "work", work_tag.as_str()].map(str::to_string));
    let done = h.audit_events("session_move_end");
    assert_eq!(done.len(), 1, "{done:#?}");
    assert_eq!((done[0]["detail"]["outcome"].as_str(), done[0]["detail"]["account"].as_str(), done[0]["detail"]["account_from"].as_str()), (Some("done"), Some("work"), Some("default")));
    let delivered: Vec<Value> = h.audit_events("credential_deliver").into_iter().filter(|r| r["detail"]["id"] == vms[1].as_str()).collect();
    assert_eq!(delivered.last().and_then(|r| r["detail"]["account"].as_str()), Some("work"));
    let entries = vms_entries(&h);
    assert_eq!(entries.iter().map(|v| v.get("account").and_then(toml::Value::as_str)).collect::<Vec<_>>(), [Some("default"), Some("work")]);
    assert_eq!(part_of(&h.end_note(), "account").as_deref(), Some("default,work"), "{}", h.end_note());
    let notes: Vec<String> = h.out_json().iter().filter(|v| v["subtype"] == "informational").filter_map(|v| v["content"].as_str().map(str::to_string)).collect();
    let continues = notes.iter().position(|n| n == &ai_env_cli::bridge::remote::note_continues(&vms[1])).expect("the chat goes on");
    assert_eq!(notes.get(continues + 1).map(String::as_str), Some(ai_env_cli::bridge::remote::note_account("work", "default").as_str()), "{notes:#?}");
    // A new chat after the switch runs as work from its start.
    let mut second = Harness::prepare().launch_wrapper(h.rig().wrapper(&[], &knobs(&[("FAKE_TOKEN_LOG", logged.as_str())])));
    started(&mut second);
    turn(&mut second, "three");
    closed(&mut second);
    assert_eq!(tokens_read(&log).last(), Some(&("3".to_string(), sha8(&work))), "a new chat reads work's token");
    let starts = h.audit_events("session_remote_start");
    assert_eq!(starts.last().and_then(|r| r["detail"]["account"].as_str()), Some("work"));
    let needles = [default.clone(), default[13..].to_string(), work.clone(), work[13..].to_string()];
    let (bridge, mac) = (h.bridge(), h.root().join(".claude"));
    assert_eq!(holding(&[&bridge, &mac], &needles), Vec::<String>::new(), "a token in what the Mac keeps");
    h.assert_vm_empty();
}

/// T10.1 twice: the VM the chat moved to is ended too, so a third VM
/// starts: two RunMicrovm, two Touch IDs (one setup-token unseal per move,
/// between its `session_move` and its VM's spawn), each move's seed and
/// transcript before that spawn, generation 3 reads the host's state again
/// and the line, the row's `vms` has 3 entries.
#[test]
fn t10_1_twice_in_a_row() {
    let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[]));
    started(&mut h);
    turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let rig = h.rig();
    let (runs, decrypts) = (run_tokens(rig).len(), rig.decrypts());
    let vm1 = vms_started(&h)[0].clone();
    platform_ends(rig, &vm1);
    moves_with_the_next_message(&mut h, &vm1);
    turn(&mut h, "two");
    synced(&mut h, &sid, 2);
    let vm2 = vms_started(&h)[1].clone();
    platform_ends(h.rig(), &vm2);
    moves_with_the_next_message(&mut h, &vm2);
    let u3 = turn(&mut h, "three");
    closed(&mut h);
    let rig = h.rig();
    let vms = vms_started(&h);
    assert_eq!(vms.len(), 3, "{vms:?}");
    assert!(vms[2] != vm1 && vms[2] != vm2, "{vms:?}");
    assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (2, 2), "a RunMicrovm and a Touch ID per loss");
    let rows = h.audit_rows();
    for (gen, from, to) in [("2", &vm1, &vms[1]), ("3", &vm2, &vms[2])] {
        let moved = index_of(&rows, "session_move", |d| d["gen"] == gen && d["from_vm"] == from.as_str());
        let seed = index_of(&rows, "seed", |d| d["vm"] == to.as_str());
        let pull = index_of(&rows, "transcript_pull", |d| d["vm"] == to.as_str() && d["session"] == sid.as_str());
        let start = index_of(&rows, "session_remote_start", |d| d["id"] == to.as_str());
        let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["to_vm"] == to.as_str());
        assert!(moved < seed && moved < pull && seed < start && pull < start && start < done, "generation {gen}: session_move {moved}, seed {seed}, transcript_pull {pull}, session_remote_start {start}, session_move_end {done}");
        one_setup_token_unseal(&rows, moved, start);
    }
    let first = index_of(&rows, "session_move", |d| d["gen"] == "2");
    assert_eq!(rows[first..].iter().filter(|r| r["event"] == "credential_unseal").count(), 2, "no unseal but the moves' (no combined.env)");
    assert_eq!(h.audit_events("session_move_end").len(), 2, "one end row per move");
    let gen3 = replayed_state(&h, 3);
    assert_eq!(gen3.last(), h.sent.last(), "generation 3 got the line that moved it");
    assert_eq!(h.out_json().iter().filter(|v| is_result_for(v, &u3)).count(), 1);
    assert_eq!(vms_entries(&h).len(), 3);
    assert!(note_has(&h.end_note(), "moves:readdress=2,respawn=0,migrate=0"), "{}", h.end_note());
    let argv = h.argv_log();
    assert!(argv[2].contains(&format!("--resume={sid}")), "{:?}", argv[2]);
    h.assert_vm_empty();
}

/// T10.1: one failure seen three ways at once (the socket cut as the VM
/// ends: the redial's 502, GetMicrovm TERMINATED, the platform's
/// `/terminate`) is one loss and one move: one new VM, its RunMicrovm
/// answered ambiguously after it made the VM (scripted `after_effect`) and
/// retried under the same client token.
#[test]
fn t10_1_one_provision_per_failure() {
    let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[]));
    started(&mut h);
    turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let rig = h.rig();
    let vm1 = vms_started(&h)[0].clone();
    let (runs, vms_in_fake) = (run_tokens(rig).len(), rig.fake().vms.len());
    rig.update_fake(|s| s.failures.push_back(FakeFailure { kind: "ambiguous".into(), message: "the answer was lost".into(), on: Some("run".into()), after_effect: true }));
    platform_ends(rig, &vm1);
    rig.endpoint.cut_all();
    moves_with_the_next_message(&mut h, &vm1);
    let u2 = turn(&mut h, "two");
    closed(&mut h);
    let rig = h.rig();
    let tokens = run_tokens(rig)[runs..].to_vec();
    assert_eq!(tokens.len(), 2, "the RunMicrovm and its retry: {tokens:?}");
    assert_eq!(tokens[0], tokens[1], "one client token");
    assert_eq!(rig.fake().vms.len() - vms_in_fake, 1, "one VM made");
    assert_eq!(h.audit_events("session_move").len(), 1, "one move");
    assert_eq!(vms_started(&h).len(), 2);
    assert_eq!(h.out_json().iter().filter(|v| is_result_for(v, &u2)).count(), 1);
    h.assert_vm_empty();
}

/// T10.3: the VM ends while a turn runs (the fake's long tool started, its
/// mark written) in a reopened chat (`--resume`, begun on this Mac): the
/// move starts at once, the line sent again. One echo and one result for the
/// line; generation 2's init swallowed (the turn had one); generation 2's
/// input ends with the line, verbatim. The turn shows generation 1's prefix
/// (its tool_use), then generation 2's whole stream (its tool_use, its
/// reply): that duplicate is the documented one. The cut is at the reply
/// before the line (`cut:at`, `--resume-session-at=<a0>`, which the fake
/// finds in the chain the dead CLI continued, FK-1): VM 1 held the tail's
/// key before its end, so its `/terminate` pushed the tail, and VM 2's
/// transcript pull went on only after that `/terminate` was answered. That
/// order is the rig's own (its endpoint posts the hooks the fake owes every
/// VM before it lets any request on), so it holds whatever the move waits
/// for: the move's wait for TERMINATED is pinned by pipeline.rs
/// `c1_tests::a_readdress_waits_for_terminated_and_runs_once`, FK-2 by its
/// own self-tests. The VMs are left with nothing (FK-8).
#[test]
fn t10_3_mid_turn_resends_the_line_once() {
    let p = Harness::prepare();
    let sid = common::uuid(0x5e55_0103);
    let (u0, a0) = (common::uuid(0x1001), common::uuid(0x1002));
    let lines = [
        format!(r#"{{"type":"user","uuid":"{u0}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#),
        format!(r#"{{"type":"assistant","uuid":"{a0}","parentUuid":"{u0}","sessionId":"{sid}","message":{{"role":"assistant","content":[{{"type":"text","text":"a reply"}}]}}}}"#),
    ];
    p.plant_transcript(&sid, &lines.iter().map(String::as_str).collect::<Vec<_>>());
    let mark = p.root.join("turn.mark");
    let mark_s = mark.display().to_string();
    let resume = format!("--resume={sid}");
    let mut h = p.spawn_on(Link::Remote, "", &[&resume], &knobs(&[("FAKE_TURN_MS", "60000"), ("FAKE_TURN_MARK", &mark_s), ("FAKE_DEDUP_RESUMED", "1")]));
    started(&mut h);
    let u1 = h.send_user("a line with a long tool");
    wait_for_mark(&mark, 1, 1);
    h.expect_out(|v| v["type"] == "assistant" && v["uuid"] == fake_tool_use_uuid(1, 1).as_str(), T);
    let vm1 = vms_started(&h)[0].clone();
    // The first init's tail key reached VM 1 (`transcript_begin` hands it asynchronously): its /terminate pushes the tail.
    h.wait_until("VM 1 holds the tail's key", T, |h| h.rig().endpoint.attempts().iter().any(|a| a.vm.as_deref() == Some(vm1.as_str()) && a.path.starts_with("/transcript/tail") && (200..300).contains(&a.status)));
    // Generation 2's tool is short.
    let rig = h.rig();
    rig.set_vm_knobs(&knobs(&[("FAKE_TURN_MS", "200"), ("FAKE_TURN_MARK", &mark_s)]));
    platform_ends(rig, &vm1);
    h.expect_out(|v| is_result_for(v, &u1), T);
    closed(&mut h);
    let out = h.out_json();
    assert_eq!(out.iter().filter(|v| is_echo_of(v, &u1)).count(), 1, "one echo");
    assert_eq!(out.iter().filter(|v| is_result_for(v, &u1)).count(), 1, "one result");
    assert_eq!(out.iter().filter(|v| is_init(v)).count(), 1, "one init for the turn: generation 2's swallowed");
    let note = h.end_note();
    assert!(note_has(&note, "inits:1/1") && note_has(&note, "moves:readdress=1,respawn=0,migrate=0"), "{note}");
    assert_eq!(part_of(&note, "cut").as_deref(), Some("at"), "{note}");
    let argv = h.argv_log();
    assert!(argv[1].contains(&resume), "{:?}", argv[1]);
    assert!(argv[1].contains(&format!("--resume-session-at={a0}")), "{:?}", argv[1]);
    assert!(h.env_log().iter().any(|l| *l == format!("gen 2 cut at={a0} found")), "{:?}", h.env_log());
    assert!(resent_as(h.stdin_of(2).last(), h.sent.last().expect("the line")), "the line again, its uuid fresh, last: {:?}", h.stdin_of(2).last());
    assert!(out.iter().any(|v| v["subtype"] == "informational" && v["content"].as_str().is_some_and(|c| c.contains(&vm1) && c.contains("the interrupted message is sent again"))), "the note");
    let echo = out.iter().position(|v| is_echo_of(v, &u1)).expect("the echo");
    let assistants: Vec<&str> = out[echo..].iter().filter(|v| v["type"] == "assistant").filter_map(|v| v["uuid"].as_str()).collect();
    assert_eq!(assistants, [fake_tool_use_uuid(1, 1), fake_tool_use_uuid(1, 2), fake_reply_uuid(1, 2)], "generation 1's prefix, then generation 2's whole turn");
    let result = out.iter().position(|v| is_result_for(v, &u1)).expect("the result");
    assert!(out[result + 1..].iter().all(|v| v["type"] != "assistant"), "the result ends the turn");
    let rig = h.rig();
    let vm2 = vms_started(&h)[1].clone();
    let hooks = rig.endpoint.hooks();
    let ended = hooks.iter().position(|k| k.vm == vm1 && k.name == "terminate").expect("VM 1's /terminate");
    let pull = rig.endpoint.attempts().into_iter().find(|a| a.vm.as_deref() == Some(vm2.as_str()) && a.path.starts_with("/transcript/pull")).expect("VM 2's transcript pull");
    assert!(pull.hooks > ended, "VM 2's first pull went on with {} hooks answered, VM 1's /terminate is hook {ended}: {hooks:?}", pull.hooks);
    h.assert_vm_empty();
}

/// T10.5: the session's subagent transcripts (`<sid>/subagents/`, the
/// manifest's `f/` files once the turn synced) follow the move: on the new
/// VM they are S3's, byte for byte (restored after the spawn, the code-out
/// trigger's first step, as S9 restores them), and the next turn's CLI
/// finds them (`subagents=2` at its start). The moved CLI writes none of
/// its own, so its count is the restore's.
#[test]
fn t10_5_subagents_follow_a_move() {
    let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[("FAKE_SUBAGENTS", "2"), ("FAKE_SUBTREE_LOG", "1")]));
    started(&mut h);
    turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(h.bridge(), None);
    let m = ai_env_cli::bridge::s3::manifest::read(&paths, &sid).unwrap().unwrap_or_else(|| panic!("no manifest of {sid}"));
    let files: Vec<(String, String)> = m.files.iter().map(|f| (f.rel.clone(), f.key.clone())).collect();
    assert_eq!(files.len(), 2, "the two subagent transcripts in S3: {files:?}");
    assert!(files.iter().all(|(rel, key)| rel.contains(&format!("/{sid}/subagents/agent-1-1-")) && key.contains("/vm/f/")), "{files:?}");
    let rig = h.rig();
    rig.set_vm_knobs(&knobs(&[("FAKE_SUBTREE_LOG", "1")]));
    let vm1 = vms_started(&h)[0].clone();
    platform_ends(rig, &vm1);
    moves_with_the_next_message(&mut h, &vm1);
    turn(&mut h, "two");
    let rig = h.rig();
    let vm2 = vms_started(&h)[1].clone();
    let projects = rig.vm_projects_of(&vm2);
    let held: Vec<(PathBuf, Vec<u8>)> = files.iter().map(|(rel, key)| (projects.join(rel), rig.s3().get(key).unwrap_or_else(|| panic!("{key} not in S3")))).collect();
    let t = std::time::Instant::now();
    while !held.iter().all(|(copy, bytes)| std::fs::read(copy).is_ok_and(|b| b == *bytes)) {
        assert!(t.elapsed() < T, "the subtree on the new VM, byte for byte: {:?}", held.iter().map(|(c, _)| (c.display().to_string(), std::fs::read(c).map(|b| b.len()))).collect::<Vec<_>>());
        std::thread::sleep(Duration::from_millis(25));
    }
    turn(&mut h, "three");
    closed(&mut h);
    assert!(h.env_log().iter().any(|l| l == "gen 2 turn 2 subagents=2"), "{:?}", h.env_log());
    h.assert_vm_empty();
}

/// A fresh chat (no `--resume`, no result yet) whose VM ends in its first
/// turn moves with its session id and no resume (`Cut::Fresh`): generation
/// 2 runs `--session-id=<sid>` on a new VM where nothing was restored (the
/// dead CLI's transcript would make it refuse the id); the line is sent
/// again and answered once; the chat goes on there.
#[test]
fn a_fresh_chats_first_turn_moves_with_session_id() {
    let p = Harness::prepare();
    let mark = p.root.join("turn.mark");
    let mark_s = mark.display().to_string();
    let mut h = p.spawn_on(Link::Remote, "", &[], &knobs(&[("FAKE_TURN_MS", "60000"), ("FAKE_TURN_MARK", &mark_s)]));
    started(&mut h);
    let u1 = h.send_user("the first line");
    let sid = session_of(&mut h);
    wait_for_mark(&mark, 1, 1);
    let rig = h.rig();
    rig.set_vm_knobs(&knobs(&[("FAKE_TURN_MS", "200"), ("FAKE_TURN_MARK", &mark_s)]));
    let vm1 = vms_started(&h)[0].clone();
    platform_ends(rig, &vm1);
    h.expect_out(|v| is_result_for(v, &u1), T);
    let u2 = turn(&mut h, "the second line");
    closed(&mut h);
    let vm2 = vms_started(&h)[1].clone();
    assert_ne!(vm2, vm1);
    let argv = h.argv_log();
    assert!(argv[1].contains(&format!("--session-id={sid}")), "{:?}", argv[1]);
    assert!(!argv[1].iter().any(|a| a.starts_with("--resume") || a == "-r"), "no resume: {:?}", argv[1]);
    assert!(h.env_log().iter().any(|l| *l == format!("gen 2 session-id={sid}")), "{:?}", h.env_log());
    let out = h.out_json();
    for u in [&u1, &u2] {
        assert_eq!(out.iter().filter(|v| is_result_for(v, u)).count(), 1, "one result for {u}");
    }
    assert_eq!(out.iter().filter(|v| is_echo_of(v, &u1)).count(), 1, "one echo");
    assert!(h.audit_events("transcript_pull").iter().all(|r| r["detail"]["vm"] != vm2.as_str()), "nothing restored on the new VM");
    let note = h.end_note();
    assert!(note_has(&note, "cut:fresh") && note_has(&note, "moves:readdress=1,respawn=0,migrate=0"), "{note}");
    h.assert_vm_empty();
}

/// The frames wrapper `pid` traced (`AI_ENV_BRIDGE_TRACE=2`:
/// `<bridge>/logs/frames-<pid>.jsonl`), every socket of the process in the
/// order the frames were sent or read: `{socket, dir, frame}` each.
fn traced(bridge: &Path, pid: u32) -> Vec<Value> {
    let path = bridge.join("logs").join(format!("frames-{pid}.jsonl"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("a frame line ({e}): {l}"))).collect()
}

/// The traced sockets whose `hello_ok` named `vm`.
fn sockets_on(frames: &[Value], vm: &str) -> Vec<u64> {
    frames.iter().filter(|f| f["dir"] == "vm" && f["frame"]["t"] == "hello_ok" && f["frame"]["microvm_id"] == vm).filter_map(|f| f["socket"].as_u64()).collect()
}

/// The traced frames a failure names: each socket's VM, every spawn,
/// signal, detach and exit, by index.
fn frame_summary(frames: &[Value]) -> Vec<String> {
    let kept = ["hello_ok", "spawn", "signal", "detach", "exit"];
    frames
        .iter()
        .enumerate()
        .filter(|(_, f)| f["frame"]["t"].as_str().is_some_and(|t| kept.contains(&t)))
        .map(|(i, f)| format!("{i}: socket {} {} {} {} {}", f["socket"], f["dir"], f["frame"]["t"], f["frame"]["spawn_id"], f["frame"]["microvm_id"].as_str().or(f["frame"]["sig"].as_str()).unwrap_or_default()))
        .collect()
}

/// M1's stop of `spawn` on `vm` (`agent::stop_spawn`) in `frames`
/// ([`traced`]), answered by the VM's shim: its TERM (`signal`, the group)
/// on a socket whose `hello_ok` named `vm`, then that spawn's `exit` read
/// back on the same socket; and no `detach` of it there (a spawn that
/// outlived `STOP_SPAWN_WITHIN` would get `detach{final}` and the shim's
/// ladder: the stop answered within its bound needs none). The two indices.
fn answered_stop(frames: &[Value], vm: &str, spawn: &str) -> (usize, usize) {
    let on = sockets_on(frames, vm);
    let term = frames
        .iter()
        .position(|f| f["dir"] == "mac" && f["frame"]["t"] == "signal" && f["frame"]["spawn_id"] == spawn && f["frame"]["sig"] == "TERM" && f["socket"].as_u64().is_some_and(|n| on.contains(&n)))
        .unwrap_or_else(|| panic!("no TERM to {spawn} on a socket to {vm} ({on:?}): {:#?}", frame_summary(frames)));
    let socket = frames[term]["socket"].clone();
    let exit = frames
        .iter()
        .enumerate()
        .skip(term + 1)
        .find(|(_, f)| f["socket"] == socket && f["dir"] == "vm" && f["frame"]["t"] == "exit" && f["frame"]["spawn_id"] == spawn)
        .map(|(i, _)| i)
        .unwrap_or_else(|| panic!("no exit of {spawn} after its TERM on socket {socket}: {:#?}", frame_summary(frames)));
    assert!(!frames.iter().any(|f| f["socket"] == socket && f["dir"] == "mac" && f["frame"]["t"] == "detach"), "an answered stop sends no detach: {:#?}", frame_summary(frames));
    (term, exit)
}

/// S10 §2.7, C-1 (phase 4b V-6): a fresh chat's first turn lost as a
/// `Gap` moves as a re-address, and M1 stops the gapped spawn on the old
/// VM, still running, before anything spawns on the new one. The gap: the
/// wrapper's socket is cut while generation 1's tool runs (its redial held),
/// the turn ends on the VM, and a second attachment (here one made on the
/// VM's shim in-process, as `ai-env vm attach` would make one) acks that
/// output and leaves, so the wrapper's resume finds it gone. The old VM's
/// shim then gets TERM for the gapped spawn on a socket of its own (its
/// `hello_ok` names the old VM), the gapped claude dies of it (its `exit`,
/// signal 15, read back there; no `detach`: the stop was answered) and the
/// shim releases it, all before generation 2's `spawn` on the new VM, which
/// runs the line once (`--session-id`): two claudes never run the turn.
#[test]
fn a_fresh_chats_gap_stops_the_gapped_claude_before_the_new_vms_spawn() {
    use ai_env_cli::wire::frame::{ResumePoint, ResumeStatus};
    use ai_env_cli::wire::workspace::APP_PORT;
    use common::fake_endpoint::Action;
    let p = Harness::prepare();
    let mark = p.root.join("turn.mark");
    let mark_s = mark.display().to_string();
    // Generation 1's tool ends 3 s after its mark, its socket down by then; its edit says the turn ended on the VM.
    let gen1 = knobs(&[("FAKE_TURN_MS", "3000"), ("FAKE_TURN_MARK", &mark_s), ("FAKE_EDIT", "gapped.txt:the gapped turn ended"), ("AI_ENV_BRIDGE_TRACE", "2")]);
    let mut h = p.spawn_on(Link::Remote, "", &[], &gen1);
    started(&mut h);
    let u1 = h.send_user("the first line");
    let sid = session_of(&mut h);
    wait_for_mark(&mark, 1, 1);
    h.expect_out(|v| v["type"] == "assistant" && v["uuid"] == fake_tool_use_uuid(1, 1).as_str(), T);
    let rig = h.rig();
    let vm1 = vms_started(&h)[0].clone();
    let shim = rig.shim_of(&vm1);
    let live: Vec<_> = shim.spawns.status(None).into_iter().filter(|s| s.alive).collect();
    assert_eq!(live.len(), 1, "generation 1's claude: {live:?}");
    let (gapped, seen) = (live[0].spawn_id.clone(), live[0].out_seq);
    // The wrapper's socket cut, its redial held until the gap is made; generation 2's tool short, no edit.
    rig.endpoint.script_port(APP_PORT, vec![Action::Held; 16]);
    rig.endpoint.cut_all();
    rig.set_vm_knobs(&knobs(&[("FAKE_TURN_MS", "200"), ("FAKE_TURN_MARK", &mark_s)]));
    let ended = rig.vm_path_of(&vm1, &rig.work()).join("gapped.txt");
    let t = std::time::Instant::now();
    loop {
        let s = shim.spawns.status(None).into_iter().find(|s| s.spawn_id == gapped).expect("the gapped spawn");
        // The turn ended on the VM (its edit, then its result) and the shim took the socket's loss.
        if ended.exists() && s.out_seq > seen && !s.attached {
            break;
        }
        assert!(t.elapsed() < T, "the gapped turn's end on the VM, its socket lost: {s:?}");
        std::thread::sleep(Duration::from_millis(25));
    }
    std::thread::sleep(Duration::from_millis(300));
    // The second attachment: it resumes the spawn, acks all of its output and leaves (its detach grace runs again).
    let conn = shim.agents.next_gen();
    let resumed = shim.spawns.attach(conn, &[ResumePoint { spawn_id: gapped.clone(), from_seq: None, err_from_seq: None }]);
    assert!(resumed.len() == 1 && resumed[0].status == ResumeStatus::Ok, "{resumed:?}");
    let s = shim.spawns.status(None).into_iter().find(|s| s.spawn_id == gapped).expect("the gapped spawn");
    shim.spawns.ack(conn, &gapped, s.out_seq, s.err_seq).expect("the second attachment's ack");
    shim.spawns.detach(conn, &gapped, false).expect("the second attachment's detach");
    rig.endpoint.release();
    note_with(&mut h, &[&vm1, "a replay gap", "the interrupted message is sent again"]);
    h.expect_out(|v| is_result_for(v, &u1), T);
    closed(&mut h);
    let vm2 = vms_started(&h).get(1).cloned().expect("the new VM's spawn");
    assert_ne!(vm2, vm1);
    let rows = h.audit_rows();
    let moved = index_of(&rows, "session_move", |d| d["gen"] == "2" && d["kind"] == "readdress" && d["cause"] == "gap" && d["from_vm"] == vm1.as_str());
    let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
    assert!(moved < start, "session_move {moved}, session_remote_start {start}");
    let argv = h.argv_log();
    assert!(argv[1].contains(&format!("--session-id={sid}")), "a fresh chat's move: {:?}", argv[1]);
    let frames = traced(&h.bridge(), h.pid());
    let (term, exit) = answered_stop(&frames, &vm1, &gapped.0);
    assert_eq!(frames[exit]["frame"]["signal"], 15, "the gapped claude died of the TERM: {}", frames[exit]);
    let on2 = sockets_on(&frames, &vm2);
    let spawn2 = frames
        .iter()
        .position(|f| f["dir"] == "mac" && f["frame"]["t"] == "spawn" && f["socket"].as_u64().is_some_and(|n| on2.contains(&n)))
        .unwrap_or_else(|| panic!("generation 2's spawn on {vm2}: {:#?}", frame_summary(&frames)));
    assert!(exit < spawn2, "the stop ended before the new VM's spawn: TERM {term}, exit {exit}, spawn {spawn2}: {:#?}", frame_summary(&frames));
    let left = h.rig().shim_of(&vm1).spawns.status(None);
    assert!(!left.iter().any(|s| s.spawn_id == gapped), "the old VM's shim released the gapped spawn: {left:?}");
    let out = h.out_json();
    assert_eq!(out.iter().filter(|v| is_result_for(v, &u1)).count(), 1, "one result");
    assert!(note_has(&h.end_note(), "moves:readdress=1,respawn=0,migrate=0"), "{}", h.end_note());
    h.assert_vm_empty();
}

// ---- S10 wave 1c (C3): the migration, the reopen's carry, `session migrate`, the reaper ----

/// The rig's state, as its commands and wrappers resolve it (`AI_ENV_BRIDGE_DIR`).
fn paths_of(rig: &RemoteRig) -> ai_env_cli::bridge::config::Paths {
    ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None)
}

/// The census end row's note of wrapper `pid` (a reopen's wrapper writes its rows beside the first's).
fn end_note_of(h: &Harness, pid: u32) -> String {
    let rows = h.census();
    let ends: Vec<&Value> = rows.iter().filter(|r| r.get("end").is_some() && r["pid"].as_u64() == Some(u64::from(pid))).collect();
    assert_eq!(ends.len(), 1, "one end row of wrapper {pid}: {rows:#?}");
    ends[0]["note"].as_str().unwrap_or_default().to_string()
}

/// Until the rig's audit holds a row of `event` whose detail `pred` takes.
fn wait_for_row(h: &mut Harness, what: &str, event: &str, pred: impl Fn(&Value) -> bool) {
    h.wait_until(what, T, |h| h.audit_events(event).iter().any(|r| pred(&r["detail"])));
}

/// Until the fake says `vm` is in a state `f` takes.
fn wait_for_state(rig: &RemoteRig, vm: &str, what: &str, f: impl Fn(&VmState) -> bool) {
    let t = std::time::Instant::now();
    while !rig.fake().vms.get(vm).is_some_and(|v| f(&v.state)) {
        assert!(t.elapsed() < T, "{what}: {vm} is {:?}", rig.fake().vms.get(vm).map(|v| v.state.clone()));
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The L3 note (an `informational` line) holding every one of `parts`.
fn note_with(h: &mut Harness, parts: &[&str]) -> Value {
    h.expect_out(|v| v["subtype"] == "informational" && v["content"].as_str().is_some_and(|c| parts.iter().all(|p| c.contains(p))), T)
}

/// The index of the first row of `event` after `rows[from]` whose detail `pred` takes.
fn index_after(rows: &[Value], from: usize, event: &str, pred: impl Fn(&Value) -> bool) -> usize {
    rows.iter().enumerate().skip(from + 1).find(|(_, r)| r["event"] == event && pred(&r["detail"])).map(|(i, _)| i).unwrap_or_else(|| panic!("no {event} row as asked after row {from}: {rows:#?}"))
}

/// `rel` in `dir`, as text; `None` when it is not there.
fn text_of(dir: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(rel)).ok()
}

/// The pid of a process that ran and exited: no live wrapper has it.
fn dead_pid() -> u32 {
    let mut child = std::process::Command::new("/usr/bin/true").spawn().expect("run true");
    child.wait().expect("wait for true");
    child.id()
}

/// The fake age's calls on `rig` so far (its `age.log`: the version probe and every decrypt).
fn age_calls(rig: &RemoteRig) -> usize {
    std::fs::read_to_string(rig.root().join("age.log")).unwrap_or_default().lines().count()
}

/// The Mac's `box/wip/*` snapshots of the workspace (what each code-out
/// promoted, `refs/remotes/box/wip/<UTC>-<n>`), the newest first.
fn box_wips(rig: &RemoteRig) -> Vec<String> {
    git_in(&rig.work(), &["for-each-ref", "--sort=-refname", "--format=%(refname)", "refs/remotes/box/wip/"]).lines().map(str::to_string).collect()
}

/// The files of commit `rev`'s tree in the Mac's workspace.
fn tree_files(rig: &RemoteRig, rev: &str) -> Vec<String> {
    git_in(&rig.work(), &["ls-tree", "-r", "--name-only", rev]).lines().map(str::to_string).collect()
}

/// The fake claude's knobs that leave the turn's uncommitted edit (`agent.txt`).
const WIP: (&str, &str) = ("FAKE_WIP_EDIT", "agent.txt:from the VM, not committed");
/// What `WIP` leaves in the VM's checkout.
const WIP_TEXT: &str = "from the VM, not committed\n";

/// A chat closed on its VM after one turn whose WIP and transcript the Mac
/// holds (its code-out, then its sync to S3 and its view), its VM then
/// suspended by the closing suspend: the harness (whose rig the reopen
/// shares), the session id and the VM.
fn closed_chat() -> (Harness, String, String) {
    let mut first = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[WIP]));
    started(&mut first);
    turn(&mut first, "one");
    let sid = session_of(&mut first);
    synced(&mut first, &sid, 1);
    closed(&mut first);
    let vm = vms_started(&first)[0].clone();
    wait_for_state(first.rig(), &vm, "the closing suspend", |s| *s == VmState::Suspended);
    (first, sid, vm)
}

/// T10.4 (a): the chat's VM nears its wall between turns (`bring_wall_near`:
/// 600 s left, inside the default `migrate_before_wall_s` of 1200). The next
/// result starts phase A: L3's note, `session_move` (`migrate`, `wall`,
/// generation 1), one Touch ID for the setup token beside SELECT_VM
/// (`vm_select` avoiding the old VM: a new one), and the token left in the
/// new VM's cache (`credential_deliver` `warm`), while the chat goes on. A
/// turn running then (held at its permission prompt past phase A's end) is
/// never cut: nothing switches until its result. At the quiet point after it
/// the old CLI gets its EOF, the old VM's work is fetched and the chat synced
/// there; the new VM is seeded with the branch and the WIP (the turn's
/// uncommitted edit and one made on the old VM while the turn was held, both
/// in the new checkout before its first turn) and the transcript restored;
/// the CLI resumes the session there (`--resume=<sid>`, no cut) and reads the
/// host's state again, then the next line, never the held turn's.
/// `session_move_end` `done` (the Touch ID `asked`); only after the new VM's
/// spawn is the old VM terminated, by `migrate`. One RunMicrovm and one
/// Touch ID in all: the switch never unseals.
#[test]
fn t10_4_wall_migration_between_turns() {
    let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[WIP, ("FAKE_ASK", "Bash"), ("FAKE_ASK_TURN", "3")]));
    started(&mut h);
    let u1 = turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let rig = h.rig();
    let vm1 = vms_started(&h)[0].clone();
    let (runs, decrypts) = (run_tokens(rig).len(), rig.decrypts());
    rig.bring_wall_near(&vm1, 600);
    let u2 = turn(&mut h, "two");
    note_with(&mut h, &[&vm1, "its 8-hour wall", "the chat goes on meanwhile"]);
    // A turn running at the threshold, held at its permission prompt until phase A is done.
    let u3 = h.send_user("three");
    let ask = h.expect_out(common::is_permission_request, T);
    let ask_id = ask["request_id"].as_str().expect("the permission request's id").to_string();
    wait_for_row(&mut h, "phase A: the setup token in the new VM's cache", "credential_deliver", |d| d["id"] != vm1.as_str() && d["source"] == "warm");
    let rig = h.rig();
    std::fs::write(rig.vm_path_of(&vm1, &rig.work()).join("held.txt"), "written while the turn was held\n").expect("an edit on the old VM");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(vms_started(&h), [vm1.as_str()], "no switch while a turn runs");
    assert_eq!(h.argv_log().len(), 1, "the old CLI serves the turn");
    h.answer_permission(&ask_id, true);
    h.expect_out(|v| is_result_for(v, &u3), T);
    note_with(&mut h, &["the chat continues on"]);
    let vm2 = vms_started(&h).get(1).cloned().expect("the new VM's spawn");
    assert_ne!(vm2, vm1);
    let rig = h.rig();
    let checkout = rig.vm_path_of(&vm2, &rig.work());
    assert_eq!(text_of(&checkout, "agent.txt").as_deref(), Some(WIP_TEXT), "the turn's WIP, seeded");
    assert_eq!(text_of(&checkout, "held.txt").as_deref(), Some("written while the turn was held\n"), "the old VM's work up to the switch");
    wait_for_row(&mut h, "the old VM terminated", "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
    let u4 = turn(&mut h, "four");
    closed(&mut h);
    let rig = h.rig();
    assert_eq!(vms_started(&h), [vm1.clone(), vm2.clone()]);
    assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "one RunMicrovm, one Touch ID");
    let rows = h.audit_rows();
    let moved = index_of(&rows, "session_move", |d| d["kind"] == "migrate" && d["trigger"] == "wall" && d["gen"] == "1" && d["from_vm"] == vm1.as_str() && d["session"] == sid.as_str());
    let select = index_of(&rows, "vm_select", |d| d["id"] == vm2.as_str() && d["avoid"] == vm1.as_str());
    let warm = index_of(&rows, "credential_deliver", |d| d["id"] == vm2.as_str() && d["source"] == "warm");
    let fetched = index_after(&rows, warm, "codeout_fetch", |d| d["vm"] == vm1.as_str());
    let seed = index_of(&rows, "seed", |d| d["vm"] == vm2.as_str());
    let pull = index_of(&rows, "transcript_pull", |d| d["vm"] == vm2.as_str() && d["session"] == sid.as_str());
    let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
    let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["kind"] == "migrate" && d["to_vm"] == vm2.as_str());
    let ended = index_of(&rows, "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
    assert!(
        moved < select && select < warm && fetched < seed && warm < pull && seed < start && pull < start && start < done && start < ended,
        "session_move {moved}, vm_select {select}, credential_deliver {warm}, codeout_fetch {fetched}, seed {seed}, transcript_pull {pull}, session_remote_start {start}, session_move_end {done}, vm_terminate {ended}"
    );
    one_setup_token_unseal(&rows, moved, start);
    assert_eq!(rows[moved..].iter().filter(|r| r["event"] == "credential_unseal").count(), 1, "the switch never unseals");
    assert_eq!((rows[start]["detail"]["why"].as_str(), rows[done]["detail"]["touchid"].as_str()), (Some("migrate:wall"), Some("asked")), "{} {}", rows[start], rows[done]);
    assert_eq!(h.audit_events("session_move_end").len(), 1, "the move's one end row");
    let argv = h.argv_log();
    assert_eq!(argv.len(), 2, "{argv:?}");
    assert!(argv[1].contains(&format!("--resume={sid}")) && !argv[1].iter().any(|a| a.starts_with("--resume-session-at")), "{:?}", argv[1]);
    let gen2 = replayed_state(&h, 2);
    assert_eq!(gen2[3..], [h.sent.last().cloned().expect("the last line")], "then the next line: the held turn's never again");
    let out = h.out_json();
    for u in [&u1, &u2, &u3, &u4] {
        assert_eq!(out.iter().filter(|v| is_echo_of(v, u)).count(), 1, "one echo of {u}");
        assert_eq!(out.iter().filter(|v| is_result_for(v, u)).count(), 1, "one result for {u}");
    }
    let note = h.end_note();
    assert!(note_has(&note, "moves:readdress=0,respawn=0,migrate=1") && part_of(&note, "vm").as_deref() == Some(vm2.as_str()), "{note}");
    h.assert_vm_empty();
}

/// T10.4 (b), near the wall: a chat closed on its VM is reopened once that
/// VM nears its wall (`bring_wall_near`: 600 s left). The reopen moves it
/// before its CLI starts, in generation 1 (one Touch ID, as every start):
/// `session_move` (`migrate`, trigger `reopen`) at P0's choice; P2 resumes
/// the old VM, fetches its work and syncs the chat there beside SELECT_VM (a
/// new VM, the old one avoided); P3 seeds the new VM from that fetch (the
/// old VM's WIP in its checkout: this CLI writes none) and restores the
/// transcript, which the CLI resumes. `session_remote_start` and the row's
/// `vms` entry say `migrate:reopen`, `session_move_end` `done`; once the new
/// spawn runs the old VM is terminated by `migrate`. The census says
/// `carried:migrate` and counts the move.
#[test]
fn t10_4b_reopen_near_the_wall_migrates_first() {
    let (mut first, sid, vm1) = closed_chat();
    let rig = first.rig();
    let (runs, decrypts) = (run_tokens(rig).len(), rig.decrypts());
    rig.bring_wall_near(&vm1, 600);
    let resume = format!("--resume={sid}");
    let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &knobs(&[])));
    started(&mut second);
    // The old VM's end runs once the spawn does: before the turn, so the two never interleave.
    wait_for_row(&mut first, "the old VM terminated", "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
    let vm2 = vms_started(&first).get(1).cloned().expect("the new VM's spawn");
    assert_ne!(vm2, vm1);
    // Before this wrapper writes the chat's row (at its first line), that row names the new VM: the old VM's last
    // sync took the rows naming it and left this chat alone (its copy there is behind what the new VM commits).
    let row = ai_env_cli::bridge::registry::read(&paths_of(first.rig()), &sid).expect("the row").expect("the chat's row");
    assert_eq!((row.microvm_id.as_deref(), row.spawn_id.as_deref(), row.status.as_str()), (Some(vm2.as_str()), None, "closed"), "{row:?}");
    let u = turn(&mut second, "after the move");
    let init = second.expect_out(is_init, T);
    assert_eq!(init["session_id"].as_str(), Some(sid.as_str()), "the same session: {init}");
    closed(&mut second);
    let rig = first.rig();
    assert_eq!(vms_started(&first), [vm1.as_str(), vm2.as_str()]);
    assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "a new VM, and the start's one Touch ID");
    let rows = first.audit_rows();
    let moved = index_of(&rows, "session_move", |d| d["kind"] == "migrate" && d["trigger"] == "reopen" && d["gen"] == "1" && d["from_vm"] == vm1.as_str() && d["session"] == sid.as_str());
    let fetched = index_after(&rows, moved, "codeout_fetch", |d| d["vm"] == vm1.as_str());
    let seed = index_after(&rows, moved, "seed", |d| d["vm"] == vm2.as_str());
    let pull = index_after(&rows, moved, "transcript_pull", |d| d["vm"] == vm2.as_str() && d["session"] == sid.as_str());
    let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
    let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["kind"] == "migrate" && d["to_vm"] == vm2.as_str());
    let ended = index_of(&rows, "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
    assert!(fetched < seed && seed < start && pull < start && start < done && start < ended, "session_move {moved}, codeout_fetch {fetched}, seed {seed}, transcript_pull {pull}, session_remote_start {start}, session_move_end {done}, vm_terminate {ended}");
    assert_eq!((rows[start]["detail"]["gen"].as_str(), rows[start]["detail"]["why"].as_str()), (Some("1"), Some("migrate:reopen")), "{}", rows[start]);
    assert!(rig.fake_calls().iter().any(|c| matches!(c, Call::Resume(id) if *id == vm1)), "P2 resumed the old VM");
    assert_eq!(text_of(&rig.vm_path_of(&vm2, &rig.work()), "agent.txt").as_deref(), Some(WIP_TEXT), "the old VM's WIP on the new one");
    let entries = vms_entries(&first);
    let last = entries.last().expect("the reopen's vms entry");
    assert_eq!((last.get("vm").and_then(toml::Value::as_str), last.get("why").and_then(toml::Value::as_str)), (Some(vm2.as_str()), Some("migrate:reopen")), "{entries:?}");
    assert!(first.env_log().iter().any(|l| l.starts_with("gen 2 resumed")), "the transcript was there before the CLI: {:?}", first.env_log());
    assert_eq!(second.out_json().iter().filter(|v| is_result_for(v, &u)).count(), 1);
    let note = end_note_of(&first, second.pid());
    assert!(note_has(&note, "carried:migrate") && note_has(&note, "moves:readdress=0,respawn=0,migrate=1") && part_of(&note, "vm").as_deref() == Some(vm2.as_str()), "{note}");
    // On the harness that owns the rig (FK-8): `second` has neither the rig nor its logs.
    first.assert_vm_empty();
}

/// T10.4 (b), after the wall: the chat's VM passed its wall while the chat
/// was closed (the platform ended it: the fake's wall, its `/terminate`).
/// The reopen re-addresses the chat before its CLI starts, in generation 1:
/// `session_move` (`readdress`, cause `vm_gone`) at P0's choice, from local
/// state alone; the old VM is left alone (gone: no resume, no fetch, no
/// terminate); a new VM is seeded from the box record (the last turn's WIP
/// in its checkout) and the transcript restored from S3, which the CLI
/// resumes. `session_remote_start` says `readdress:vm_gone`,
/// `session_move_end` `done`; the census says `carried:readdress` and
/// counts it among the re-addresses.
#[test]
fn t10_4b_reopen_after_the_wall_readdresses() {
    let (first, sid, vm1) = closed_chat();
    let rig = first.rig();
    rig.bring_wall_near(&vm1, 1);
    wait_for_state(rig, &vm1, "the platform's wall", |s| matches!(s, VmState::Terminating | VmState::Terminated));
    let (runs, decrypts, calls) = (run_tokens(rig).len(), rig.decrypts(), rig.fake_calls().len());
    let resume = format!("--resume={sid}");
    let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &knobs(&[])));
    started(&mut second);
    let u = turn(&mut second, "after the wall");
    let init = second.expect_out(is_init, T);
    assert_eq!(init["session_id"].as_str(), Some(sid.as_str()), "the same session: {init}");
    closed(&mut second);
    let rig = first.rig();
    let vms = vms_started(&first);
    assert_eq!(vms.len(), 2, "{vms:?}");
    let vm2 = vms[1].clone();
    assert_ne!(vm2, vm1);
    assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "a new VM, and the start's one Touch ID");
    let rows = first.audit_rows();
    let moved = index_of(&rows, "session_move", |d| d["kind"] == "readdress" && d["cause"] == "vm_gone" && d["gen"] == "1" && d["from_vm"] == vm1.as_str() && d["session"] == sid.as_str());
    let seed = index_after(&rows, moved, "seed", |d| d["vm"] == vm2.as_str());
    let pull = index_after(&rows, moved, "transcript_pull", |d| d["vm"] == vm2.as_str() && d["session"] == sid.as_str());
    let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
    let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["kind"] == "readdress" && d["to_vm"] == vm2.as_str());
    assert!(seed < start && pull < start && start < done, "session_move {moved}, seed {seed}, transcript_pull {pull}, session_remote_start {start}, session_move_end {done}");
    assert_eq!((rows[start]["detail"]["gen"].as_str(), rows[start]["detail"]["why"].as_str()), (Some("1"), Some("readdress:vm_gone")), "{}", rows[start]);
    assert!(!rows[moved..].iter().any(|r| r["event"] == "codeout_fetch" && r["detail"]["vm"] == vm1.as_str()), "nothing fetched from the gone VM");
    assert!(!rows.iter().any(|r| r["event"] == "vm_terminate" && r["detail"]["by"] == "migrate"), "no VM retired by a move");
    assert!(!rig.fake_calls()[calls..].iter().any(|c| matches!(c, Call::Resume(id) if *id == vm1)), "the gone VM is never resumed");
    assert_eq!(text_of(&rig.vm_path_of(&vm2, &rig.work()), "agent.txt").as_deref(), Some(WIP_TEXT), "the box record's WIP on the new VM");
    assert!(first.env_log().iter().any(|l| l.starts_with("gen 2 resumed")), "the transcript was there before the CLI: {:?}", first.env_log());
    assert_eq!(second.out_json().iter().filter(|v| is_result_for(v, &u)).count(), 1);
    let note = end_note_of(&first, second.pid());
    assert!(note_has(&note, "carried:readdress") && note_has(&note, "moves:readdress=1,respawn=0,migrate=0") && part_of(&note, "vm").as_deref() == Some(vm2.as_str()), "{note}");
    first.assert_vm_empty();
}

/// T10.4 (c): an edit made on the VM after the last turn's end (no result
/// follows it, so no code-out fetches it) is lost when the platform ends
/// the VM: the documented loss. The Mac's newest `box/wip` is the last
/// turn's boundary (the turn's WIP, without the late edit); the next line
/// moves the chat to a new VM seeded from that record: the turn's WIP is
/// there (this CLI writes none), the late edit is not, and no snapshot the
/// Mac holds ever has it.
#[test]
fn t10_4c_an_edit_after_the_last_turn_is_the_documented_loss() {
    let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[WIP]));
    started(&mut h);
    turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let rig = h.rig();
    let vm1 = vms_started(&h)[0].clone();
    std::fs::write(rig.vm_path_of(&vm1, &rig.work()).join("late.txt"), "after the last turn\n").expect("the late edit");
    let wips = box_wips(rig);
    let newest = wips.first().unwrap_or_else(|| panic!("the turn's snapshot on the Mac: {wips:?}"));
    let files = tree_files(rig, newest);
    assert!(files.iter().any(|f| f == "agent.txt") && !files.iter().any(|f| f == "late.txt"), "the newest box/wip is the turn's boundary: {files:?}");
    // The moved CLI writes nothing of its own.
    rig.set_vm_knobs(&knobs(&[]));
    platform_ends(rig, &vm1);
    moves_with_the_next_message(&mut h, &vm1);
    let u2 = turn(&mut h, "two");
    closed(&mut h);
    let rig = h.rig();
    let vm2 = vms_started(&h).get(1).cloned().expect("the new VM");
    assert_ne!(vm2, vm1);
    let checkout = rig.vm_path_of(&vm2, &rig.work());
    assert_eq!(text_of(&checkout, "agent.txt").as_deref(), Some(WIP_TEXT), "the last turn's WIP");
    assert_eq!(text_of(&checkout, "late.txt"), None, "the edit after the last turn is lost");
    for wip in box_wips(rig) {
        assert!(!tree_files(rig, &wip).iter().any(|f| f == "late.txt"), "{wip} holds the late edit");
    }
    let rows = h.audit_rows();
    let moved = index_of(&rows, "session_move", |d| d["kind"] == "readdress" && d["cause"] == "vm_gone" && d["from_vm"] == vm1.as_str());
    let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["to_vm"] == vm2.as_str());
    assert!(moved < done);
    assert!(!rows[moved..].iter().any(|r| r["event"] == "codeout_fetch" && r["detail"]["vm"] == vm1.as_str()), "nothing fetched from the ended VM");
    assert_eq!(h.out_json().iter().filter(|v| is_result_for(v, &u2)).count(), 1);
    h.assert_vm_empty();
}

/// §7.1, live: `ai-env session migrate <sid> --json` on a chat whose S10
/// wrapper runs, idle between turns. The command writes the request,
/// signals the wrapper (`session_migrate_request` `live`, its pid) and
/// waits; the wrapper takes the request (the file gone), prepares a new VM
/// at once (`session_move` `migrate`, trigger `command`, the request's nonce;
/// one Touch ID for the setup token) and, the chat being quiet, switches:
/// `session_move_end` `done` with that nonce, which the command reports
/// (exit 0; `outcome` `done`, `how` `live`, from the old VM to the new). The
/// next turn runs on the new VM, the CLI resuming the session there; the old
/// VM is terminated by `migrate`.
#[test]
fn session_migrate_moves_a_live_session() {
    let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[]));
    started(&mut h);
    turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let rig = h.rig();
    let vm1 = vms_started(&h)[0].clone();
    let (runs, decrypts) = (run_tokens(rig).len(), rig.decrypts());
    let o = rig.run(&["session", "migrate", &sid, "--json"], None);
    assert_eq!(o.status.code(), Some(0), "session migrate: {}\n{}", String::from_utf8_lossy(&o.stderr), h.wrapper_log());
    let doc: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("session migrate --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
    let vm2 = doc["to_vm"].as_str().expect("the new VM").to_string();
    assert_ne!(vm2, vm1);
    assert_eq!((doc["session"].as_str(), doc["outcome"].as_str(), doc["how"].as_str(), doc["from_vm"].as_str(), doc["code"].as_i64()), (Some(sid.as_str()), Some("done"), Some("live"), Some(vm1.as_str()), Some(0)), "{doc}");
    assert!(doc["ms"].is_u64(), "{doc}");
    assert!(!paths_of(rig).session_migrate_request(&sid).exists(), "the wrapper took the request");
    let rows = h.audit_rows();
    let asked = index_of(&rows, "session_migrate_request", |d| d["session"] == sid.as_str() && d["how"] == "live");
    let nonce = rows[asked]["detail"]["nonce"].as_str().expect("the request's nonce").to_string();
    assert_eq!(rows[asked]["detail"]["wrapper_pid"], h.pid().to_string());
    let moved = index_of(&rows, "session_move", |d| d["kind"] == "migrate" && d["trigger"] == "command" && d["request"] == nonce.as_str() && d["from_vm"] == vm1.as_str());
    let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["request"] == nonce.as_str() && d["to_vm"] == vm2.as_str());
    // The command audits its request after its signal (§7.1), so the wrapper's `session_move` may come first.
    assert!(moved < done, "session_migrate_request {asked}, session_move {moved}, session_move_end {done}");
    wait_for_row(&mut h, "the old VM terminated", "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
    let u2 = turn(&mut h, "two");
    closed(&mut h);
    let rig = h.rig();
    assert_eq!(vms_started(&h), [vm1.clone(), vm2.clone()]);
    assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "one RunMicrovm, the wrapper's one Touch ID");
    let argv = h.argv_log();
    assert!(argv[1].contains(&format!("--resume={sid}")), "{:?}", argv[1]);
    assert_eq!(h.out_json().iter().filter(|v| is_result_for(v, &u2)).count(), 1);
    assert!(note_has(&h.end_note(), "moves:readdress=0,respawn=0,migrate=1"), "{}", h.end_note());
    assert!(h.wrapper_log().contains("session migrate signal"), "the wrapper logs the signal: {}", h.wrapper_log());
    h.assert_vm_empty();
}

/// §7.1's checks before any Touch ID: a chat that runs on this Mac (its
/// row's mode not `remote`) is exit 9 naming why, having asked nothing (no
/// age call, no decrypt), signalled no one and left no request; an id that
/// is no uuid is exit 2, an unknown session exit 1, neither asking anything
/// either.
#[test]
fn session_migrate_refuses_a_local_chat_before_any_touch_id() {
    use ai_env_cli::bridge::registry::{self, SessionRow, REGISTRY_SCHEMA_V};
    let mut p = Harness::prepare();
    let rig = p.rig();
    let paths = paths_of(rig);
    let sid = common::uuid(0x5e55_0701);
    let now = registry::now_rfc3339();
    let row = SessionRow {
        v: REGISTRY_SCHEMA_V,
        session_id: sid.clone(),
        cwd: Some(rig.work().display().to_string()),
        created: now.clone(),
        last_seen: now,
        status: "active".into(),
        mode: "local-child".into(),
        route: "local".into(),
        pid: dead_pid(),
        ..SessionRow::default()
    };
    registry::write(&paths, &row).expect("the local chat's row");
    let (ages, decrypts) = (age_calls(rig), rig.decrypts());
    let o = rig.run(&["session", "migrate", &sid], None);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(9), "{err}");
    assert!(err.contains(&format!("session {sid} runs on this Mac: there is no VM to move it from")), "{err}");
    assert!(!paths.session_migrate_request(&sid).exists(), "no request");
    let o = rig.run(&["session", "migrate", "not-a-session"], None);
    assert_eq!(o.status.code(), Some(2), "{}", String::from_utf8_lossy(&o.stderr));
    let unknown = common::uuid(0x5e55_0702);
    let o = rig.run(&["session", "migrate", &unknown], None);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains(&format!("no session {unknown}")), "{err}");
    assert_eq!((age_calls(rig), rig.decrypts()), (ages, decrypts), "no Touch ID");
    let audit = std::fs::read_to_string(paths.audit()).unwrap_or_default();
    assert!(!audit.contains("session_migrate_request") && !audit.contains("credential_unseal"), "{audit}");
}

/// §7.1: a live wrapper whose row says `v` 1 (S9's, which SIGUSR1 would
/// end) is never signalled: exit 1 naming why (`predates S10`), before any
/// Touch ID; no request is left for it, nothing audited; the wrapper and its
/// chat go on, on their VM.
#[test]
fn session_migrate_never_signals_an_s9_wrapper() {
    use ai_env_cli::bridge::registry;
    let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[]));
    started(&mut h);
    turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let rig = h.rig();
    let paths = paths_of(rig);
    // The live wrapper's row as an S9 wrapper writes it (it writes its own again only at its next event).
    let mut row = registry::read(&paths, &sid).expect("the row").expect("the live chat's row");
    assert_eq!(row.v, registry::REGISTRY_SCHEMA_V);
    row.v = 1;
    registry::write(&paths, &row).expect("the row as S9's");
    let (ages, decrypts) = (age_calls(rig), rig.decrypts());
    let o = rig.run(&["session", "migrate", &sid], None);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains(&format!("session {sid}'s wrapper (pid {}) predates S10: close the chat and reopen it, then run ai-env session migrate again", h.pid())), "{err}");
    assert!(!paths.session_migrate_request(&sid).exists(), "no request left");
    assert_eq!((age_calls(rig), rig.decrypts()), (ages, decrypts), "no Touch ID");
    assert!(!h.exited_now(), "the wrapper lives");
    assert!(h.audit_events("session_migrate_request").is_empty() && h.audit_events("session_move").is_empty());
    let u2 = turn(&mut h, "two");
    closed(&mut h);
    assert_eq!(vms_started(&h).len(), 1, "still on its VM");
    assert_eq!(h.out_json().iter().filter(|v| is_result_for(v, &u2)).count(), 1);
    // The wrapper here is an S10 one, which a SIGUSR1 would not end: its log says whether one came (every one is logged).
    assert!(!h.wrapper_log().contains("session migrate signal"), "an S9 wrapper is never signalled: {}", h.wrapper_log());
    h.assert_vm_empty();
}

/// §7.1, offline: `ai-env session migrate <sid> --json` on a chat no
/// wrapper serves (closed, its VM suspended) moves it itself, its row
/// `migrating` with the command's pid meanwhile: one Touch ID (the runtime
/// key's; `session_migrate_request` `offline`), the old VM resumed, its work
/// fetched and the chat synced there, a new VM chosen avoiding it, the carry
/// seed (the old VM's WIP in the new checkout) beside the restore, the row's
/// VM rewritten (a `vms` entry `migrate:command`, the row given back
/// `closed`), and the old VM terminated by `migrate`; exit 0, `how`
/// `offline`. The chat's reopen then takes the new VM and what it holds: no
/// carry, no further VM.
#[test]
fn session_migrate_moves_a_closed_chat_offline() {
    use ai_env_cli::bridge::registry;
    let (first, sid, vm1) = closed_chat();
    let rig = first.rig();
    let (runs, decrypts) = (run_tokens(rig).len(), rig.decrypts());
    let o = rig.run(&["session", "migrate", &sid, "--json"], None);
    assert_eq!(o.status.code(), Some(0), "session migrate: {}", String::from_utf8_lossy(&o.stderr));
    let doc: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("session migrate --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
    let vm2 = doc["to_vm"].as_str().expect("the new VM").to_string();
    assert_ne!(vm2, vm1);
    assert_eq!((doc["session"].as_str(), doc["outcome"].as_str(), doc["how"].as_str(), doc["from_vm"].as_str(), doc["code"].as_i64()), (Some(sid.as_str()), Some("done"), Some("offline"), Some(vm1.as_str()), Some(0)), "{doc}");
    assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "one new VM, one Touch ID");
    let rows = first.audit_rows();
    let asked = index_of(&rows, "session_migrate_request", |d| d["session"] == sid.as_str() && d["how"] == "offline");
    assert!(rows[asked]["detail"].get("wrapper_pid").is_none(), "{}", rows[asked]);
    let fetched = index_after(&rows, asked, "codeout_fetch", |d| d["vm"] == vm1.as_str());
    let seed = index_after(&rows, asked, "seed", |d| d["vm"] == vm2.as_str());
    let pull = index_after(&rows, asked, "transcript_pull", |d| d["vm"] == vm2.as_str() && d["session"] == sid.as_str());
    let ended = index_of(&rows, "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
    assert!(fetched < seed && seed < ended && pull < ended, "session_migrate_request {asked}, codeout_fetch {fetched}, seed {seed}, transcript_pull {pull}, vm_terminate {ended}");
    assert!(rig.fake_calls().iter().any(|c| matches!(c, Call::Resume(id) if *id == vm1)), "the old VM resumed for its fetch");
    assert_eq!(text_of(&rig.vm_path_of(&vm2, &rig.work()), "agent.txt").as_deref(), Some(WIP_TEXT), "the old VM's WIP on the new one");
    let row = registry::read(&paths_of(rig), &sid).expect("the row").expect("the chat's row");
    assert_eq!((row.microvm_id.as_deref(), row.status.as_str(), row.migrating_pid), (Some(vm2.as_str()), "closed", None), "{row:?}");
    let last = row.vms.last().expect("the move's vms entry");
    assert_eq!((last.get("vm").and_then(toml::Value::as_str), last.get("why").and_then(toml::Value::as_str)), (Some(vm2.as_str()), Some("migrate:command")), "{:?}", row.vms);
    // The reopen takes the new VM: nothing to carry, no VM started.
    let resume = format!("--resume={sid}");
    let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &knobs(&[])));
    started(&mut second);
    let u = turn(&mut second, "after the move");
    closed(&mut second);
    assert_eq!(second.out_json().iter().filter(|v| is_result_for(v, &u)).count(), 1);
    assert_eq!(run_tokens(rig).len() - runs, 1, "the reopen starts no VM");
    let note = end_note_of(&first, second.pid());
    assert!(part_of(&note, "vm").as_deref() == Some(vm2.as_str()) && part_of(&note, "carried").is_none(), "{note}");
    assert!(first.env_log().iter().any(|l| l.starts_with("gen 2 resumed")), "the transcript was there before the CLI: {:?}", first.env_log());
    first.assert_vm_empty();
}

/// A claude its wrapper left parked on `vm` (§3.3), made here as a session
/// makes one: `cat` run by `agent::run_spawn_parked` on the rig's VM (its
/// row's target, through the routed endpoint), its park naming `owner`: one
/// line echoed, then idle until the shim parks it; the shim closes the
/// parked socket, and the host's EOF ends the session there
/// (`parked_close`: nothing dialed). The spawn stays on the VM, parked under
/// `owner`, as a chat closed parked with no socket, or a wrapper that died
/// parked, leaves it. Its id.
fn leave_parked(rig: &RemoteRig, vm: &str, owner: ParkOwner) -> SpawnId {
    use ai_env_cli::bridge::agent::{run_spawn_parked, spawn_channels, AgentEnv, AgentTarget, RunPolicy, SpawnEvent, SpawnInput, SpawnSpec, Start};
    use ai_env_cli::bridge::codeout::{CodeoutCtx, CodeoutTrigger};
    use ai_env_cli::bridge::config::{BridgeConfig, Keepalive, Rotation};
    use ai_env_cli::bridge::dataplane::{HttpsEndpoint, MintingTokens};
    use ai_env_cli::bridge::park::{ParkCtl, ParkPolicy, QuietState, Verdict};
    use ai_env_cli::bridge::workspace::{Head, WorkspaceRef, WsKind};
    use std::sync::{Arc, Mutex};
    let ms = Duration::from_millis;
    let paths = paths_of(rig);
    let row = ai_env_cli::bridge::vm::registry::read_row(&paths, vm).expect("the VM's row").unwrap_or_else(|| panic!("no row of {vm}"));
    let api = ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi::open(&rig.fake_path()).expect("the rig's fake API");
    let policy = RunPolicy {
        ping: Duration::from_secs(3600),
        ws_ping: Duration::from_secs(3600),
        dead_after: Duration::from_secs(5),
        ack_bytes: ai_env_cli::wire::frame::ACK_EVERY_BYTES,
        ack_every: ms(10),
        rotation: Rotation::Lazy,
        keepalive: Keepalive::Frames,
        keepalive_every: Duration::from_secs(3600),
        suspend_wait: ms(200),
        backoff_min: ms(10),
        backoff_max: ms(100),
        stable_after: Duration::from_secs(1),
        reconnect_budget: Duration::from_secs(10),
        not_run_budget: Duration::from_secs(2),
        token_minutes: 60,
        remint_below: Duration::from_secs(60),
        rotate_before: Duration::from_secs(120),
        idle_s: Some(90),
    };
    let env = AgentEnv { api: &api, ep: &api, paths: &paths, target: AgentTarget::from_row(&row).expect("the VM's target"), policy, dial: ai_env_cli::bridge::transport::AgentDial { local: Some(rig.endpoint.addr) } };
    let id = SpawnId::new_v7();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("a runtime");
    rt.block_on(async {
        async fn until(what: &str, f: impl Fn() -> bool) {
            let t = std::time::Instant::now();
            while !f() {
                assert!(t.elapsed() < T, "{what}");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        let (quiet, rx) = tokio::sync::watch::channel(QuietState { verdict: Verdict::Busy, since: tokio::time::Instant::now(), last_host: Some("user") });
        // Its fetch never runs: a trigger nobody asks is quiet.
        let unused = Arc::new(ai_env_cli::bridge::api::FakeMicrovmApi::new());
        let ws = WorkspaceRef {
            cwd: "/nonexistent/park".into(),
            root: "/nonexistent/park".into(),
            vm_cwd: "/nonexistent/park".into(),
            vm_root: "/nonexistent/park".into(),
            slug: "-nonexistent-park".into(),
            kind: WsKind::Git { git_dir: "/nonexistent/park/.git".into(), common_dir: "/nonexistent/park/.git".into(), object_format: ai_env_cli::wire::workspace::ObjectFormat::Sha1 },
            head: Head::Detached { sha: "a".repeat(40) },
            seed_branch: None,
        };
        let trigger = CodeoutTrigger::spawn(CodeoutCtx {
            api: unused.clone(),
            dp: Arc::new(HttpsEndpoint::new(&ai_env_cli::bridge::lab::VmKnobs::default()).expect("a data plane")),
            tokens: Arc::new(MintingTokens::new(unused, &paths, vm, false)),
            paths: paths.clone(),
            cfg: Arc::new(BridgeConfig::default()),
            target: AgentTarget { vm_id: vm.to_string(), endpoint: "x".into(), session_token: ai_env_cli::wire::redact::Secret::new("t".into()), vpc: false, shell: false },
            ws,
            capture_settings: false,
            transcript: None,
        });
        let terms = ParkPolicy { after: ms(200), grace_s: 600, min_quiet_s: 0, cpu_busy_ms: 500, hold_output: false, probe: ms(500), answer_wait: Duration::from_secs(2) };
        let ctl = ParkCtl { quiet: rx, trigger: trigger.watch(), policy: terms, owner };
        let (sio, mut cio) = spawn_channels(8);
        let input = cio.input.clone();
        let told = Mutex::new((Vec::<u8>::new(), Vec::<String>::new()));
        let spec = SpawnSpec { argv: vec!["cat".into()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(60), id: Some(id.clone()) };
        let consume = async {
            while let Some(ev) = cio.events.recv().await {
                match ev {
                    SpawnEvent::Stdout { seq, bytes } => {
                        told.lock().unwrap().0.extend(bytes);
                        cio.consumed.stdout_done(seq);
                    }
                    SpawnEvent::Stderr { seq, .. } => cio.consumed.stderr_done(seq),
                    SpawnEvent::Note(n) => told.lock().unwrap().1.push(n),
                    _ => {}
                }
            }
        };
        let driver = async {
            input.send(SpawnInput::Stdin(b"hello\n".to_vec())).await.expect("the line");
            until("the echo", || told.lock().unwrap().0 == b"hello\n").await;
            quiet.send_replace(QuietState { verdict: Verdict::Idle, since: tokio::time::Instant::now(), last_host: Some("user") });
            let shim = rig.shim_of(vm);
            until("parked on the shim under its owner", || shim.spawns.detail().iter().any(|d| d.status.spawn_id == id && d.parked == Some(owner))).await;
            shim.agents.close_all(ai_env_cli::wire::frame::CLOSE_GOING_AWAY, "test").await;
            until("parked with no socket", || told.lock().unwrap().1.iter().any(|n| n.contains("stays parked until the next input"))).await;
            input.send(SpawnInput::StdinEof).await.expect("the EOF");
        };
        let (out, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(spec), sio, None, ctl), consume, driver);
        assert!(out.expect("the parked session").parked_close, "closed parked, with no socket");
        drop(trigger);
    });
    id
}

/// D5 (M6, §2.7): a claude left parked on a VM by a wrapper that is gone
/// (the park's owner a pid no live `ai-env-claude` holds; no session row
/// names it: [`leave_parked`]) is ended by the next chat that starts there.
/// Before its spawn, P4 reads the VM's spawns once, finds the parked one
/// whose owner is no live wrapper (`orphan`), stops it (`agent::stop_spawn`:
/// resumed, then its TERM) and writes `session_reap` (`orphan`, `ended`, the
/// dead wrapper's pid); the chat then starts on that VM and runs its turn.
/// The shim keeps no such claude.
#[test]
fn the_reaper_ends_a_parked_orphan_by_its_owner() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let vm = rig.start_vm();
    let owner = ParkOwner { pid: dead_pid(), started: ai_env_cli::wire::time::unix_now() };
    let orphan = leave_parked(rig, &vm, owner);
    let parked: Vec<_> = rig.shim_of(&vm).spawns.detail().into_iter().filter(|d| d.status.spawn_id == orphan).collect();
    assert!(parked.len() == 1 && parked[0].status.alive && parked[0].parked == Some(owner), "the orphan, parked under its owner: {parked:?}");
    let mut h = p.spawn_on(Link::Remote, "", &[], &knobs(&[]));
    started(&mut h);
    let u = turn(&mut h, "one");
    closed(&mut h);
    let reaps = h.audit_events("session_reap");
    assert_eq!(reaps.len(), 1, "{reaps:#?}");
    let d = &reaps[0]["detail"];
    let spawn = orphan.to_string();
    assert_eq!((d["vm"].as_str(), d["spawn"].as_str(), d["why"].as_str(), d["outcome"].as_str()), (Some(vm.as_str()), Some(spawn.as_str()), Some("orphan"), Some("ended")), "{d}");
    assert_eq!(d["wrapper_pid"], owner.pid.to_string(), "{d}");
    let rows = h.audit_rows();
    let reaped = index_of(&rows, "session_reap", |_| true);
    let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm.as_str());
    assert!(reaped < start, "the reaper runs before the spawn: session_reap {reaped}, session_remote_start {start}");
    assert_eq!(vms_started(&h), [vm.as_str()], "the chat started on that VM");
    assert_eq!(h.out_json().iter().filter(|v| is_result_for(v, &u)).count(), 1);
    let left = h.rig().shim_of(&vm).spawns.detail();
    assert!(!left.iter().any(|d| d.status.spawn_id == orphan && d.status.alive), "the orphan is gone: {left:?}");
    h.assert_vm_empty();
}

// ---- S10 I2 (the lead): the joint cases of parking and moving ------------------------------------

/// S10's joint cases (plans/s10-plan.md Part A, Integration: I2): a chat
/// that parks on its own (the wrapper's `AI_ENV_BRIDGE_LAB_PARK_AFTER_MS`,
/// the shim's real `park_v1`) and then loses its VM, is moved by `ai-env
/// session migrate`, or is closed and reopened (on a new VM, or on its own,
/// which ends the claude it left parked there: one that does not stop fails
/// the reopen, and a new chat there only audits it); a migration refused at
/// `[vm].max_concurrent`; B0's park terms on the wire. A parked chat's VM is suspended by the test (the
/// platform's idle policy's stand-in: the fake suspends nothing on its own)
/// and reaches its wall by `bring_wall_near` (the fake's wall ends it, the
/// endpoint posts its `/terminate`).
mod joint {
    use super::*;
    use crate::common::fake_endpoint::Action;
    use crate::common::note_number;
    use crate::common::remote::{toml_table, BACKOFF_MS};
    use ai_env_cli::bridge::config::BridgeConfig;
    use ai_env_cli::bridge::lab::VmKnobs;
    use ai_env_cli::bridge::park::{ParkPolicy, CPU_BUSY_MS, HOLD_OUTPUT};
    use ai_env_cli::wire::workspace::APP_PORT;
    use std::time::Instant;

    /// The wrapper's park knob: the chat's quiet before the session asks to
    /// park, in place of `[vm].max_idle_s` (S10 §9). Under the rig's backoff
    /// knob the shim's busy window is 3 s (`ParkPolicy::from_cfg`), so a chat
    /// parks about 3 s after its turn's last stdio.
    const PARK: (&str, &str) = ("AI_ENV_BRIDGE_LAB_PARK_AFTER_MS", "300");

    /// Until the session parked on `vm` on its own (`session_park`, written
    /// at the shim's `parked`) and the VM's shim names this wrapper the
    /// park's owner (`SpawnDetail.parked`, the reaper's key).
    fn parks_on(h: &mut Harness, vm: &str) {
        wait_for_row(h, "the session parks on its own", "session_park", |d| d["vm"] == vm);
        let pid = h.pid();
        let shim = h.rig().shim_of(vm);
        let t = Instant::now();
        while !shim.spawns.detail().iter().any(|d| d.status.alive && d.parked.is_some_and(|o| o.pid == pid)) {
            assert!(t.elapsed() < T, "the shim names the wrapper {pid} the park's owner: {:?}", shim.spawns.detail());
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// The platform suspends `vm` under the parked chat (its idle policy's
    /// stand-in): the endpoint posts `/suspend`, whose `hook_suspend` closes
    /// the parked socket, and the session waits with no socket for the next
    /// input.
    fn suspended_under_the_park(h: &mut Harness, vm: &str) {
        h.rig().update_fake(|s| s.suspend(vm).expect("SuspendMicrovm of the running VM"));
        let said = format!("{vm} was suspended: spawn");
        h.wait_until("parked with no socket", T, |h| h.wrapper_log().contains(&said));
    }

    /// The `/agent` upgrades the endpoint took from the `from`-th attempt on: (the VM the check named, the status).
    fn dials_since(rig: &RemoteRig, from: usize) -> Vec<(Option<String>, u16)> {
        rig.endpoint.attempts().into_iter().skip(from).filter(|a| a.path == "/agent").map(|a| (a.vm, a.status)).collect()
    }

    /// The session's parks on `vm` (`session_park` rows).
    fn parks_of(h: &Harness, vm: &str) -> usize {
        h.audit_events("session_park").iter().filter(|r| r["detail"]["vm"] == vm).count()
    }

    /// I2 (a): a parked chat's VM hits its wall. The chat parks on its own
    /// after its turn (its WIP fetched), the platform suspends the VM under
    /// it (the session parked with no socket), and the VM's wall then ends
    /// it (the fake's wall, its `/terminate`): nothing reaches the parked
    /// session. The next line unparks into the ended VM: GetMicrovm finds it
    /// gone before any dial (no `session_unpark` naming it, no upgrade to
    /// it), and the chat re-addresses at once with that line (L3's
    /// `note_moving`: the interrupted message is sent again): `session_move`
    /// (`readdress`, `vm_gone`) after the park, one Touch ID (the setup
    /// token's) before the new VM's spawn and none for the park or the
    /// suspend (M1), the dead VM's WIP seeded from its fetch record (`seed`
    /// `box`), `session_move_end` `done`. The line reaches the new CLI
    /// verbatim, last, and is answered once; the end row counts the park
    /// (`park`, `parked_s`) and the move (`moves:readdress=1,…`, `cut:none`:
    /// the dead CLI never had the line).
    #[test]
    fn a_parked_vm_that_hits_its_wall_moves_at_the_next_line() {
        let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[WIP, PARK, ("FAKE_DEDUP_RESUMED", "1")]));
        started(&mut h);
        let u1 = turn(&mut h, "one");
        let sid = session_of(&mut h);
        synced(&mut h, &sid, 1);
        // M1: from here the park, the suspend and the move ask one Touch ID in all, the move's.
        let decrypts = h.rig().decrypts();
        let vm1 = vms_started(&h)[0].clone();
        parks_on(&mut h, &vm1);
        suspended_under_the_park(&mut h, &vm1);
        let rig = h.rig();
        // The moved CLI writes nothing of its own: the WIP on the new VM is the seed's.
        rig.set_vm_knobs(&knobs(&[]));
        let (runs, attempts) = (run_tokens(rig).len(), rig.endpoint.attempts().len());
        // Its wall passes while it sleeps: the platform ends it, its `/terminate` heard by no socket.
        rig.bring_wall_near(&vm1, 1);
        wait_for_state(rig, &vm1, "the VM's wall", VmState::is_terminal);
        let u2 = h.send_user("two");
        note_with(&mut h, &[&vm1, "it was terminated", "the interrupted message is sent again"]);
        h.expect_out(|v| is_result_for(v, &u2), T);
        closed(&mut h);
        let rig = h.rig();
        let vms = vms_started(&h);
        assert_eq!(vms.len(), 2, "{vms:?}");
        let vm2 = vms[1].clone();
        assert_ne!(vm2, vm1);
        assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "one RunMicrovm, one Touch ID: the move's (the park and the suspend ask none)");
        let dialed = dials_since(rig, attempts);
        assert!(!dialed.is_empty() && dialed.iter().all(|(vm, status)| vm.as_deref() == Some(vm2.as_str()) && *status == 101), "no dial into the ended VM: {dialed:?}");
        assert!(!h.audit_events("session_unpark").iter().any(|r| r["detail"]["vm"] == vm1.as_str()), "no unpark into the ended VM: {:?}", h.audit_events("session_unpark"));
        let rows = h.audit_rows();
        let parked = index_of(&rows, "session_park", |d| d["vm"] == vm1.as_str() && d["why"] == "idle");
        let moved = index_of(&rows, "session_move", |d| d["gen"] == "2" && d["kind"] == "readdress" && d["cause"] == "vm_gone" && d["from_vm"] == vm1.as_str() && d["session"] == sid.as_str());
        let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
        let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["kind"] == "readdress" && d["to_vm"] == vm2.as_str());
        assert!(parked < moved && moved < start && start < done, "session_park {parked}, session_move {moved}, session_remote_start {start}, session_move_end {done}");
        one_setup_token_unseal(&rows, moved, start);
        let d = &rows[done]["detail"];
        assert_eq!((d["touchid"].as_str(), d["seed"].as_str(), d["cut"].as_str(), d["gen"].as_str()), (Some("asked"), Some("box"), Some("none"), Some("2")), "{d}");
        let line = h.sent.last().cloned().expect("the line");
        assert!(resent_as(h.stdin_of(2).last(), &line), "the line again, its uuid fresh, last: {:?}", h.stdin_of(2).last());
        assert!(!h.stdin_of(1).contains(&line), "the ended VM's claude never had it");
        let out = h.out_json();
        for u in [&u1, &u2] {
            assert_eq!(out.iter().filter(|v| is_echo_of(v, u)).count(), 1, "one echo of {u}");
            assert_eq!(out.iter().filter(|v| is_result_for(v, u)).count(), 1, "one result for {u}");
        }
        let rig = h.rig();
        assert_eq!(text_of(&rig.vm_path_of(&vm2, &rig.work()), "agent.txt").as_deref(), Some(WIP_TEXT), "the dead VM's WIP, seeded from its fetch record");
        let note = h.end_note();
        assert!(note_has(&note, "moves:readdress=1,respawn=0,migrate=0") && note_has(&note, "cut:none") && part_of(&note, "move_ms").is_some(), "{note}");
        // The census sums every generation's parks and unparks: the new VM's own, before the host's EOF, may be in it.
        assert!(note_number(&note, "park").is_some_and(|n| n >= 1) && parks_of(&h, &vm1) == 1 && part_of(&note, "parked_s").is_some(), "parked once on the old VM: {note}");
        h.assert_vm_empty();
    }

    /// I2 (b): the VM of a parked chat is terminated (the platform's end, no
    /// sync from the Mac) while the session holds its parked socket open:
    /// the shim's `hook_terminate` tells the session at once, and the chat
    /// waits for its next line (L5: `note_move_at_next`), never unparking
    /// into the ended VM (no `session_unpark` naming it, no upgrade to it).
    /// That line moves the chat to a new VM (one RunMicrovm, one Touch ID:
    /// the move's, the park's none) and is answered there once: generation 2
    /// reads the host's state again, then that line verbatim and nothing
    /// more; nothing lost, nothing twice. The end row counts the park and
    /// the move.
    #[test]
    fn a_vm_terminated_while_parked_moves_with_the_next_line() {
        let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[PARK]));
        started(&mut h);
        let u1 = turn(&mut h, "one");
        let sid = session_of(&mut h);
        synced(&mut h, &sid, 1);
        // M1: from here the park and the move ask one Touch ID in all, the move's.
        let decrypts = h.rig().decrypts();
        let vm1 = vms_started(&h)[0].clone();
        parks_on(&mut h, &vm1);
        let rig = h.rig();
        let (runs, attempts) = (run_tokens(rig).len(), rig.endpoint.attempts().len());
        platform_ends(rig, &vm1);
        moves_with_the_next_message(&mut h, &vm1);
        let u2 = turn(&mut h, "two");
        closed(&mut h);
        let rig = h.rig();
        let vms = vms_started(&h);
        assert_eq!(vms.len(), 2, "{vms:?}");
        let vm2 = vms[1].clone();
        assert_ne!(vm2, vm1);
        assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "one RunMicrovm, one Touch ID: the move's (the park asks none)");
        let dialed = dials_since(rig, attempts);
        assert!(!dialed.is_empty() && dialed.iter().all(|(vm, status)| vm.as_deref() == Some(vm2.as_str()) && *status == 101), "no dial into the ended VM: {dialed:?}");
        assert!(!h.audit_events("session_unpark").iter().any(|r| r["detail"]["vm"] == vm1.as_str()), "no unpark into the ended VM: {:?}", h.audit_events("session_unpark"));
        let rows = h.audit_rows();
        let parked = index_of(&rows, "session_park", |d| d["vm"] == vm1.as_str());
        let moved = index_of(&rows, "session_move", |d| d["gen"] == "2" && d["kind"] == "readdress" && d["cause"] == "vm_gone" && d["from_vm"] == vm1.as_str() && d["session"] == sid.as_str());
        let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
        let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["to_vm"] == vm2.as_str());
        assert!(parked < moved && moved < start && start < done, "session_park {parked}, session_move {moved}, session_remote_start {start}, session_move_end {done}");
        one_setup_token_unseal(&rows, moved, start);
        let gen2 = replayed_state(&h, 2);
        assert_eq!(gen2[3..], [h.sent.last().cloned().expect("the line")], "then the line that moved it, verbatim, once");
        let out = h.out_json();
        for u in [&u1, &u2] {
            assert_eq!(out.iter().filter(|v| is_echo_of(v, u)).count(), 1, "one echo of {u}");
            assert_eq!(out.iter().filter(|v| is_result_for(v, u)).count(), 1, "one result for {u}");
        }
        assert_eq!(out.iter().filter(|v| is_init(v)).count(), 2, "one init per turn");
        let note = h.end_note();
        assert!(note_has(&note, "moves:readdress=1,respawn=0,migrate=0"), "{note}");
        // The census sums every generation's parks and unparks: the new VM's own, before the host's EOF, may be in it.
        assert!(note_number(&note, "park").is_some_and(|n| n >= 1) && parks_of(&h, &vm1) == 1, "parked once on the old VM: {note}");
        h.assert_vm_empty();
    }

    /// I2 (c): the reopen of a chat closed parked, its VM near its wall. The
    /// chat parks on its own after a turn (its WIP fetched), the platform
    /// suspends its VM, and the host closes it: at once (`end:eof`,
    /// `close_parked:1`), its claude left parked on the suspended VM under
    /// the wrapper that is gone. With 600 s of that VM's wall left, the
    /// chat's reopen (`--resume`) carries it off before its CLI starts
    /// (§2.7): `session_move` (`migrate`, `reopen`, generation 1), P2's
    /// resume of the old VM (its fetch and sync), a new VM seeded with the
    /// old one's WIP and the transcript restored, which the CLI resumes;
    /// `session_move_end` `done`; then the old VM is terminated by `migrate`
    /// (the parked claude, whose owner is gone, keeps nothing running). The
    /// reopen's end row says `carried:migrate` and counts the migration.
    #[test]
    fn a_chat_closed_parked_near_its_wall_migrates_at_its_reopen() {
        let mut first = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[WIP, PARK]));
        started(&mut first);
        turn(&mut first, "one");
        let sid = session_of(&mut first);
        synced(&mut first, &sid, 1);
        let vm1 = vms_started(&first)[0].clone();
        parks_on(&mut first, &vm1);
        suspended_under_the_park(&mut first, &vm1);
        closed(&mut first);
        let owner = first.pid();
        let note = end_note_of(&first, owner);
        assert!(note_has(&note, "end:eof") && note_has(&note, "close_parked:1"), "closed parked: {note}");
        let rig = first.rig();
        let left = rig.shim_of(&vm1).spawns.detail();
        assert!(left.iter().any(|d| d.status.alive && d.parked.is_some_and(|o| o.pid == owner)), "its claude stays parked on the old VM: {left:?}");
        // The reopen's CLI writes nothing of its own: the WIP on the new VM is the carry's.
        rig.set_vm_knobs(&knobs(&[]));
        rig.bring_wall_near(&vm1, 600);
        let (runs, decrypts) = (run_tokens(rig).len(), rig.decrypts());
        let resume = format!("--resume={sid}");
        let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &knobs(&[])));
        started(&mut second);
        wait_for_row(&mut first, "the old VM terminated", "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
        let vm2 = vms_started(&first).get(1).cloned().expect("the new VM's spawn");
        assert_ne!(vm2, vm1);
        let u = turn(&mut second, "after the move");
        closed(&mut second);
        let rig = first.rig();
        assert_eq!(vms_started(&first), [vm1.as_str(), vm2.as_str()]);
        assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "a new VM, and the reopen's one Touch ID");
        let rows = first.audit_rows();
        let moved = index_of(&rows, "session_move", |d| d["kind"] == "migrate" && d["trigger"] == "reopen" && d["gen"] == "1" && d["from_vm"] == vm1.as_str() && d["session"] == sid.as_str());
        let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
        let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["kind"] == "migrate" && d["to_vm"] == vm2.as_str());
        let ended = index_of(&rows, "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
        assert!(moved < start && start < done && start < ended, "session_move {moved}, session_remote_start {start}, session_move_end {done}, vm_terminate {ended}");
        assert_eq!((rows[start]["detail"]["gen"].as_str(), rows[start]["detail"]["why"].as_str()), (Some("1"), Some("migrate:reopen")), "{}", rows[start]);
        assert!(rig.fake_calls().iter().any(|c| matches!(c, Call::Resume(id) if *id == vm1)), "P2 resumed the old VM for its fetch");
        assert_eq!(text_of(&rig.vm_path_of(&vm2, &rig.work()), "agent.txt").as_deref(), Some(WIP_TEXT), "the old VM's WIP on the new one");
        assert_eq!(second.out_json().iter().filter(|v| is_result_for(v, &u)).count(), 1);
        let note = end_note_of(&first, second.pid());
        assert!(note_has(&note, "carried:migrate") && note_has(&note, "moves:readdress=0,respawn=0,migrate=1") && part_of(&note, "vm").as_deref() == Some(vm2.as_str()), "{note}");
        assert!(rig.fake().vms.get(&vm1).is_some_and(|v| v.state.is_terminal()), "the old VM ended, its parked claude with it");
        first.assert_vm_empty();
    }

    /// I2 (d): a wall migration due at `[vm].max_concurrent` (1 here: the
    /// chat's VM holds the slot). After a turn's result with 600 s of the
    /// VM's wall left, phase A starts (`note_migrating`; `session_move`
    /// `migrate`, `wall`, generation 1), and SELECT_VM refuses a second VM:
    /// phase A fails for good (`MoveFailed`, `again` false), so the chat
    /// stays on its VM (`note_stayed`: it moves when the VM reaches its wall;
    /// `session_move_end` `stayed`, step `select`, code 9), no RunMicrovm
    /// went out, and no later result starts another phase A. The wall is the
    /// backstop: once it ends the VM, the next line re-addresses the chat
    /// (the old VM gone, its slot free; one Touch ID), and every line is
    /// answered once. The census counts the re-address alone.
    #[test]
    fn a_migration_refused_at_max_concurrent_stays_until_the_wall() {
        let mut p = Harness::prepare();
        p.rig().config(|doc| {
            toml_table(doc, "vm").insert("max_concurrent".into(), toml::Value::Integer(1));
        });
        let mut h = p.spawn_on(Link::Remote, "", &[], &knobs(&[]));
        started(&mut h);
        let u1 = turn(&mut h, "one");
        let sid = session_of(&mut h);
        synced(&mut h, &sid, 1);
        let rig = h.rig();
        let vm1 = vms_started(&h)[0].clone();
        let runs = run_tokens(rig).len();
        rig.bring_wall_near(&vm1, 600);
        let u2 = turn(&mut h, "two");
        note_with(&mut h, &[&vm1, "its 8-hour wall", "the chat goes on meanwhile"]);
        note_with(&mut h, &[&format!("the chat stays on {vm1} (no VM can start: [vm].max_concurrent); it moves when the VM reaches its wall")]);
        wait_for_row(&mut h, "phase A's end", "session_move_end", |d| d["outcome"] == "stayed" && d["kind"] == "migrate");
        // No later result asks again: wall migrations are over for this process.
        let u3 = turn(&mut h, "three");
        synced(&mut h, &sid, 3);
        assert_eq!(h.audit_events("session_move").iter().filter(|r| r["detail"]["kind"] == "migrate").count(), 1, "one phase A in all: {:?}", h.audit_events("session_move"));
        assert_eq!(vms_started(&h), [vm1.as_str()], "the chat stays on its VM");
        assert_eq!(run_tokens(h.rig()).len(), runs, "SELECT_VM refused before any RunMicrovm");
        // The backstop: the VM's wall ends it, and the next line moves the chat.
        let decrypts = h.rig().decrypts();
        h.rig().bring_wall_near(&vm1, 1);
        moves_with_the_next_message(&mut h, &vm1);
        let u4 = turn(&mut h, "four");
        // The turn's code-out and sync done, the close suspends the chat's VM (D5's row, as L1's T10.2 reads it).
        synced(&mut h, &sid, 4);
        closed(&mut h);
        wait_for_row(&mut h, "the closing suspend's row", "vm_suspend", |d| d["by"] == "close");
        let rig = h.rig();
        let vms = vms_started(&h);
        assert_eq!(vms.len(), 2, "{vms:?}");
        let vm2 = vms[1].clone();
        assert_ne!(vm2, vm1);
        let suspends = h.audit_events("vm_suspend");
        assert!(suspends.iter().any(|r| r["detail"]["id"] == vm2.as_str() && r["detail"]["by"] == "close" && r["detail"]["outcome"] == "fired"), "{suspends:?}");
        assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "the re-address's RunMicrovm and Touch ID");
        let rows = h.audit_rows();
        let migrate = index_of(&rows, "session_move", |d| d["kind"] == "migrate" && d["trigger"] == "wall" && d["gen"] == "1" && d["from_vm"] == vm1.as_str() && d["session"] == sid.as_str());
        let stayed = index_of(&rows, "session_move_end", |d| d["outcome"] == "stayed" && d["kind"] == "migrate" && d["from_vm"] == vm1.as_str());
        let d = &rows[stayed]["detail"];
        assert_eq!((d["step"].as_str(), d["code"].as_str(), d["gen"].as_str(), d["session"].as_str()), (Some("select"), Some("9"), Some("1"), Some(sid.as_str())), "{d}");
        let moved = index_of(&rows, "session_move", |d| d["kind"] == "readdress" && d["cause"] == "vm_gone" && d["gen"] == "2" && d["from_vm"] == vm1.as_str());
        let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
        let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["kind"] == "readdress" && d["to_vm"] == vm2.as_str());
        assert!(migrate < stayed && stayed < moved && moved < start && start < done, "session_move (migrate) {migrate}, session_move_end (stayed) {stayed}, session_move (readdress) {moved}, session_remote_start {start}, session_move_end {done}");
        one_setup_token_unseal(&rows, moved, start);
        let out = h.out_json();
        for u in [&u1, &u2, &u3, &u4] {
            assert_eq!(out.iter().filter(|v| is_result_for(v, u)).count(), 1, "one result for {u}");
        }
        let note = h.end_note();
        assert!(note_has(&note, "moves:readdress=1,respawn=0,migrate=0") && part_of(&note, "vm").as_deref() == Some(vm2.as_str()), "{note}");
        h.assert_vm_empty();
    }

    /// I2 (e): B0's values reach the shim. A chat that parks on its own
    /// sends the VM's shim a `park` with `park::CPU_BUSY_MS` (B0, 20 Oct:
    /// 300 ms of CPU per 10 s sample), `park::HOLD_OUTPUT`, the busy window
    /// `ParkPolicy::from_cfg` gives under the rig's knobs
    /// (`park::MIN_QUIET_S`, scaled) and the park grace of the VM's wall
    /// left at the generation's start, owned by this wrapper; the shim
    /// answers `parked` for that spawn and names the wrapper the owner. Read
    /// off the wire as the session sent and got them
    /// (`AI_ENV_BRIDGE_TRACE=2`: `logs/frames-<pid>.jsonl`). The host's EOF
    /// on the open parked socket then unparks it (`session_unpark` `eof`)
    /// and ends the chat, exit 0: one Touch ID in all, the start's (M1: the
    /// park and the unpark ask none).
    #[test]
    fn b0s_park_terms_reach_the_shim() {
        assert_eq!(CPU_BUSY_MS, 300, "B0 (20 Oct): claude at rest used at most 70 ms of CPU in any 10 s sample");
        // Before the spawn: its generation takes its park policy at its start, after this.
        let t0 = ai_env_cli::wire::time::unix_now();
        let mut p = Harness::prepare();
        let touch = p.rig().decrypts();
        let mut h = p.spawn_on(Link::Remote, "", &[], &knobs(&[PARK, ("AI_ENV_BRIDGE_TRACE", "2")]));
        started(&mut h);
        turn(&mut h, "one");
        let vm1 = vms_started(&h)[0].clone();
        parks_on(&mut h, &vm1);
        closed(&mut h);
        let path = h.bridge().join("logs").join(format!("frames-{}.jsonl", h.pid()));
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let frames: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("a frame line ({e}): {l}"))).collect();
        let parked = frames.iter().find(|f| f["dir"] == "vm" && f["frame"]["t"] == "parked").map(|f| &f["frame"]).unwrap_or_else(|| panic!("the shim's parked: {text}"));
        let park = frames.iter().rev().filter(|f| f["dir"] == "mac" && f["frame"]["t"] == "park").map(|f| &f["frame"]).find(|p| p["spawn_id"] == parked["spawn_id"]).unwrap_or_else(|| panic!("the park the shim took: {text}"));
        let row = ai_env_cli::bridge::vm::registry::read_row(&paths_of(h.rig()), &vm1).expect("the VM's row").expect("a row of the VM");
        let knobs = VmKnobs { backoff_ms: Some(BACKOFF_MS), park_after: Some(Duration::from_millis(300)), ..VmKnobs::default() };
        let want = ParkPolicy::from_cfg(&BridgeConfig::default(), &row, &knobs, ai_env_cli::wire::time::unix_now());
        assert_eq!(
            (park["cpu_busy_ms"].as_u64(), park["min_quiet_s"].as_u64(), park["hold_output"].as_bool(), park["owner"]["pid"].as_u64()),
            (Some(u64::from(CPU_BUSY_MS)), Some(u64::from(want.min_quiet_s)), Some(HOLD_OUTPUT), Some(u64::from(h.pid()))),
            "{park}"
        );
        // The grace never grows with time: taken between `t0` and now, it lies between what those two give.
        let grace = park["grace_s"].as_u64().expect("the park grace");
        let hi = ParkPolicy::from_cfg(&BridgeConfig::default(), &row, &knobs, t0).grace_s;
        assert!((u64::from(want.grace_s)..=u64::from(hi)).contains(&grace), "the wall left plus an hour, capped, at the generation's start: {grace} (between {} now and {hi} before the spawn)", want.grace_s);
        assert!(
            h.audit_events("session_unpark").iter().any(|r| r["detail"]["vm"] == vm1.as_str() && r["detail"]["by"] == "eof" && r["detail"]["vm_state"] == "running"),
            "the EOF unparked it on its open socket: {:?}",
            h.audit_events("session_unpark")
        );
        assert_eq!(h.rig().decrypts() - touch, 1, "D1's one Touch ID: the park and the EOF's unpark ask none (M1)");
    }

    /// I2 (f): the host closes a chat parked with no socket (its VM
    /// suspended under the park): the session ends at once (`end:eof`,
    /// `close_parked:1`, exit 0) and nothing is dialed (no request reaches
    /// the endpoint, no GetMicrovm, no ResumeMicrovm); its closing suspend
    /// is skipped (`parked`). Its claude stays on the suspended VM, frozen,
    /// parked under the wrapper that is gone now. The next chat that starts
    /// on that VM (a new one: no row names its spawn there) reaps it by its
    /// owner before its own spawn (`session_reap`: `orphan`, `ended`, the
    /// dead wrapper's pid) and runs its turn there; the shim keeps no such
    /// claude.
    #[test]
    fn a_parked_close_dials_nothing_and_the_next_start_reaps_its_claude() {
        let mut first = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[PARK]));
        started(&mut first);
        turn(&mut first, "one");
        let sid = session_of(&mut first);
        synced(&mut first, &sid, 1);
        let vm1 = vms_started(&first)[0].clone();
        parks_on(&mut first, &vm1);
        suspended_under_the_park(&mut first, &vm1);
        let rig = first.rig();
        let (attempts, calls) = (rig.endpoint.attempts().len(), rig.fake_calls().len());
        closed(&mut first);
        let owner = first.pid();
        let rig = first.rig();
        let reached: Vec<String> = rig.endpoint.attempts().into_iter().skip(attempts).map(|a| format!("{} {} {}", a.status, a.port, a.path)).collect();
        assert_eq!(reached, Vec::<String>::new(), "nothing dialed at the close");
        let called: Vec<Call> = rig.fake_calls().into_iter().skip(calls).collect();
        assert!(!called.iter().any(|c| matches!(c, Call::Get(_) | Call::Resume(_))), "no GetMicrovm and no ResumeMicrovm at the close: {called:?}");
        let note = end_note_of(&first, owner);
        assert!(note_has(&note, "end:eof") && note_has(&note, "close_parked:1"), "{note}");
        let suspends = first.audit_events("vm_suspend");
        assert!(suspends.iter().any(|r| r["detail"]["id"] == vm1.as_str() && r["detail"]["by"] == "close" && r["detail"]["outcome"] == "skipped" && r["detail"]["why"] == "parked"), "{suspends:?}");
        let held = rig.shim_of(&vm1).spawns.detail();
        let orphan = held.iter().find(|d| d.status.alive && d.parked.is_some_and(|o| o.pid == owner)).cloned().unwrap_or_else(|| panic!("its claude stays parked under its wrapper: {held:?}"));
        assert!(orphan.frozen, "frozen with its suspended VM: {orphan:?}");
        // The next chat on that VM: a new one in the same workspace (no row names the parked spawn for it).
        let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[], &knobs(&[])));
        started(&mut second);
        let u = turn(&mut second, "two");
        closed(&mut second);
        let rig = first.rig();
        let reaps = first.audit_events("session_reap");
        assert_eq!(reaps.len(), 1, "{reaps:#?}");
        let d = &reaps[0]["detail"];
        let spawn = orphan.status.spawn_id.to_string();
        assert_eq!((d["vm"].as_str(), d["spawn"].as_str(), d["why"].as_str(), d["outcome"].as_str()), (Some(vm1.as_str()), Some(spawn.as_str()), Some("orphan"), Some("ended")), "{d}");
        assert_eq!(d["wrapper_pid"], owner.to_string(), "{d}");
        let rows = first.audit_rows();
        let reaped = index_of(&rows, "session_reap", |_| true);
        let starts: Vec<usize> = rows.iter().enumerate().filter(|(_, r)| r["event"] == "session_remote_start" && r["detail"]["id"] == vm1.as_str()).map(|(i, _)| i).collect();
        assert!(starts.len() == 2 && starts[0] < reaped && reaped < starts[1], "the second chat's start on that VM reaps first: session_reap {reaped}, session_remote_start {starts:?}");
        assert_eq!(second.out_json().iter().filter(|v| is_result_for(v, &u)).count(), 1);
        let left = rig.shim_of(&vm1).spawns.detail();
        assert!(!left.iter().any(|d| d.status.spawn_id == orphan.status.spawn_id && d.status.alive), "the orphan is gone: {left:?}");
    }

    /// The chat of (f), closed parked: after one turn (synced) it parks on
    /// its own on its VM, the VM is suspended under the park, and the host
    /// closes it with no socket (`close_parked:1`). Its claude stays on the
    /// VM, parked under the wrapper that is gone now, and the closed row
    /// names it (`spawn_id`). The harness (whose rig the next chat shares),
    /// the session id, the VM, that wrapper's pid and the claude's spawn.
    fn closed_parked() -> (Harness, String, String, u32, SpawnId) {
        let mut first = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[PARK]));
        started(&mut first);
        turn(&mut first, "one");
        let sid = session_of(&mut first);
        synced(&mut first, &sid, 1);
        let vm = vms_started(&first)[0].clone();
        parks_on(&mut first, &vm);
        suspended_under_the_park(&mut first, &vm);
        closed(&mut first);
        let owner = first.pid();
        let note = end_note_of(&first, owner);
        assert!(note_has(&note, "close_parked:1"), "closed parked: {note}");
        let rig = first.rig();
        let held = rig.shim_of(&vm).spawns.detail();
        let parked = held.iter().find(|d| d.status.alive && d.parked.is_some_and(|o| o.pid == owner)).map(|d| d.status.spawn_id.clone()).unwrap_or_else(|| panic!("its claude stays parked under its wrapper: {held:?}"));
        let row = ai_env_cli::bridge::registry::read(&paths_of(rig), &sid).expect("the row").expect("the chat's row");
        assert_eq!((row.status.as_str(), row.microvm_id.as_deref(), row.spawn_id.clone()), ("closed", Some(vm.as_str()), Some(parked.to_string())), "the closed row names that claude: {row:?}");
        (first, sid, vm, owner, parked)
    }

    /// From here on, the endpoint cuts every socket whose `hello_ok` resumes
    /// `spawn` before that frame reaches the Mac (`ForwardUntil` its text,
    /// for each request on the app port; one that never carries the text is
    /// forwarded as before, until either side ends it). So the reaper's
    /// `agent::stop_spawn` never attaches that claude, and never signals it:
    /// it does not stop, and lives on.
    fn unstoppable(rig: &RemoteRig, spawn: &SpawnId) {
        let resumed = format!(r#""resumed":[{{"spawn_id":"{spawn}""#);
        // More requests than a test makes on the app port from here on, the reaper's redials included.
        rig.endpoint.script_port(APP_PORT, vec![Action::ForwardUntil { text: resumed }; 4096]);
    }

    /// I2 (f), the same chat reopened: the chat closed parked with no socket
    /// ([`closed_parked`]) is reopened (`--resume`) on its VM, whose wall is
    /// far. The closed row still names its claude there (`spawn_id`), and
    /// that row's wrapper is gone: before the reopen's spawn, P4's reaper
    /// finds that claude a `leftover` (D5, M6: two claudes never share one
    /// transcript) and stops it (`session_reap`: the chat's session,
    /// `leftover`, `ended`, the closed wrapper's pid), before the reopen's
    /// `session_remote_start` there. No VM is started, and the reopen asks
    /// its start's one Touch ID (the reaper none); its CLI resumes the
    /// session (`--resume=<sid>`) and its turn is answered once; the shim
    /// keeps no such claude.
    #[test]
    fn a_chat_reopened_on_its_vm_reaps_the_claude_it_left_parked() {
        let (first, sid, vm1, owner, parked) = closed_parked();
        let rig = first.rig();
        let (runs, decrypts) = (run_tokens(rig).len(), rig.decrypts());
        let resume = format!("--resume={sid}");
        let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&resume], &knobs(&[])));
        started(&mut second);
        let u = turn(&mut second, "two");
        closed(&mut second);
        let rig = first.rig();
        assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (0, 1), "no VM started; the reopen's one Touch ID, the reaper's none");
        let reaps = first.audit_events("session_reap");
        assert_eq!(reaps.len(), 1, "{reaps:#?}");
        let d = &reaps[0]["detail"];
        let spawn = parked.to_string();
        assert_eq!(
            (d["session"].as_str(), d["vm"].as_str(), d["spawn"].as_str(), d["why"].as_str(), d["outcome"].as_str()),
            (Some(sid.as_str()), Some(vm1.as_str()), Some(spawn.as_str()), Some("leftover"), Some("ended")),
            "{d}"
        );
        assert_eq!(d["wrapper_pid"], owner.to_string(), "{d}");
        let rows = first.audit_rows();
        let reaped = index_of(&rows, "session_reap", |_| true);
        let starts: Vec<usize> = rows.iter().enumerate().filter(|(_, r)| r["event"] == "session_remote_start" && r["detail"]["id"] == vm1.as_str()).map(|(i, _)| i).collect();
        assert!(starts.len() == 2 && starts[0] < reaped && reaped < starts[1], "the reopen's start on that VM reaps first: session_reap {reaped}, session_remote_start {starts:?}");
        let argv = first.argv_log();
        assert!(argv.len() == 2 && argv[1].contains(&resume), "the reopen's CLI resumes the session: {argv:?}");
        assert_eq!(second.out_json().iter().filter(|v| is_result_for(v, &u)).count(), 1);
        let left = rig.shim_of(&vm1).spawns.detail();
        assert!(!left.iter().any(|d| d.status.spawn_id == parked && d.status.alive), "the leftover is gone: {left:?}");
    }

    /// I2 (f), the reaper's refusal: the chat closed parked
    /// ([`closed_parked`]) is reopened on its VM, as in
    /// [`a_chat_reopened_on_its_vm_reaps_the_claude_it_left_parked`], but
    /// its claude there does not stop ([`unstoppable`]). Two claudes never
    /// share one transcript (D5, M6): `session_reap` `leftover` `failed`
    /// (the chat's session, the closed wrapper's pid), then the reopen fails
    /// before its spawn: exit 8, its last line naming that claude and the VM,
    /// `session_remote_failed` at `spawn` with code 8. The reaper's attaches
    /// went to that VM alone; no VM is started, no claude spawned, and the
    /// leftover lives on.
    #[test]
    fn a_leftover_that_does_not_stop_fails_the_reopen() {
        let (first, sid, vm1, owner, parked) = closed_parked();
        let rig = first.rig();
        let (runs, spawns, attempts) = (run_tokens(rig).len(), first.spawn_count(), rig.endpoint.attempts().len());
        unstoppable(rig, &parked);
        let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[&format!("--resume={sid}")], &knobs(&[])));
        second.send_initialize();
        let (status, _) = second.wait(EXIT);
        assert_eq!(status.code(), Some(8), "{}", second.transcript());
        let err = second.err_text();
        let line = format!("ai-env-claude: this chat's claude from an earlier wrapper (spawn {parked}) did not stop on {vm1} (at spawn);");
        assert!(err.lines().last().is_some_and(|l| l.starts_with(&line)), "{err}");
        let reaps = first.audit_events("session_reap");
        assert_eq!(reaps.len(), 1, "{reaps:#?}");
        let d = &reaps[0]["detail"];
        let spawn = parked.to_string();
        assert_eq!(
            (d["session"].as_str(), d["vm"].as_str(), d["spawn"].as_str(), d["why"].as_str(), d["outcome"].as_str()),
            (Some(sid.as_str()), Some(vm1.as_str()), Some(spawn.as_str()), Some("leftover"), Some("failed")),
            "{d}"
        );
        assert_eq!(d["wrapper_pid"], owner.to_string(), "{d}");
        let rows = first.audit_rows();
        let reaped = index_of(&rows, "session_reap", |_| true);
        let failed = index_of(&rows, "session_remote_failed", |_| true);
        let f = &rows[failed]["detail"];
        assert_eq!((f["gen"].as_str(), f["step"].as_str(), f["code"].as_str(), f["id"].as_str()), (Some("1"), Some("spawn"), Some("8"), Some(vm1.as_str())), "{f}");
        assert!(reaped < failed, "the reaper's row, then the failure: session_reap {reaped}, session_remote_failed {failed}");
        let starts = rows.iter().filter(|r| r["event"] == "session_remote_start").count();
        assert_eq!(starts, 1, "the first chat's start alone");
        let dials = dials_since(rig, attempts);
        assert!(dials.iter().any(|(_, status)| *status == 101) && dials.iter().all(|(vm, _)| vm.as_deref() == Some(vm1.as_str())), "the reaper's attaches, to that VM alone: {dials:?}");
        assert_eq!((run_tokens(rig).len() - runs, first.spawn_count() - spawns), (0, 0), "no VM started, no claude spawned");
        let left = rig.shim_of(&vm1).spawns.detail();
        assert!(left.iter().any(|d| d.status.spawn_id == parked && d.status.alive), "the leftover lives on: {left:?}");
    }

    /// I2 (f), an orphan that does not stop: the claude the chat closed
    /// parked left on its VM ([`closed_parked`]) does not stop
    /// ([`unstoppable`]). The next chat on that VM, a new one (no row names
    /// that claude for it), finds it an `orphan` by its owner, as in (f), and
    /// only audits it (`session_reap`: no session, `orphan`, `failed`, the
    /// gone wrapper's pid); it starts there all the same, after that row,
    /// and its turn is answered once. The orphan lives on.
    #[test]
    fn an_orphan_that_does_not_stop_is_audited_and_the_chat_starts() {
        let (first, _, vm1, owner, orphan) = closed_parked();
        let rig = first.rig();
        unstoppable(rig, &orphan);
        let mut second = Harness::prepare().launch_wrapper(rig.wrapper(&[], &knobs(&[])));
        started(&mut second);
        let u = turn(&mut second, "two");
        closed(&mut second);
        let reaps = first.audit_events("session_reap");
        assert_eq!(reaps.len(), 1, "{reaps:#?}");
        let d = &reaps[0]["detail"];
        let spawn = orphan.to_string();
        assert_eq!(
            (d["session"].as_str(), d["vm"].as_str(), d["spawn"].as_str(), d["why"].as_str(), d["outcome"].as_str()),
            (Some("-"), Some(vm1.as_str()), Some(spawn.as_str()), Some("orphan"), Some("failed")),
            "{d}"
        );
        assert_eq!(d["wrapper_pid"], owner.to_string(), "{d}");
        let rows = first.audit_rows();
        let reaped = index_of(&rows, "session_reap", |_| true);
        let starts: Vec<usize> = rows.iter().enumerate().filter(|(_, r)| r["event"] == "session_remote_start" && r["detail"]["id"] == vm1.as_str()).map(|(i, _)| i).collect();
        assert!(starts.len() == 2 && starts[0] < reaped && reaped < starts[1], "the next chat starts on that VM after the reaper's row: session_reap {reaped}, session_remote_start {starts:?}");
        assert_eq!(second.out_json().iter().filter(|v| is_result_for(v, &u)).count(), 1);
        let left = rig.shim_of(&vm1).spawns.detail();
        assert!(left.iter().any(|d| d.status.spawn_id == orphan && d.status.alive), "the orphan lives on: {left:?}");
    }

    /// I2 (g), a move while parked: `ai-env session migrate <sid> --json` on
    /// a chat parked on its own, its socket closed by a suspend under the
    /// park (`suspend`) or open. The wrapper takes the request and prepares a
    /// new VM while the chat stays parked (`session_move` `migrate`,
    /// `command`, the request's nonce; phase A's one Touch ID). A parked
    /// session is no quiet point, so the pump sends the old CLI one
    /// `keep_alive` of its own (§14, wave 1c), which unparks it:
    /// `session_unpark` on the old VM, by the host's last frame's kind
    /// (§4.2: `user`), its VM `suspended` and resumed for it on one new
    /// socket (`unpark_resumed`), or `running` with no new socket (the open
    /// one carries the spawn again). The switch begins at the quiet point
    /// after that unpark: the old CLI's EOF, the old VM's work fetched, the
    /// new VM seeded (the turn's WIP) and the transcript restored; the CLI
    /// resumes the session there (`--resume=<sid>`, no cut) and reads the
    /// host's state again, then the next line, never the keep_alive.
    /// `session_move_end` `done` with the nonce, which the command reports
    /// (exit 0, `live`); the old VM is then terminated by `migrate`. One
    /// RunMicrovm, and one Touch ID from before the park: the park, the
    /// unpark and the switch ask none (M1). The old CLI read the host's
    /// lines once, then that one keep_alive; every line is answered once.
    fn session_migrate_moves_a_chat_parked(suspend: bool) {
        let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[WIP, PARK]));
        started(&mut h);
        let u1 = turn(&mut h, "one");
        let sid = session_of(&mut h);
        synced(&mut h, &sid, 1);
        // M1: from here the park, the unpark and the move ask one Touch ID in all, phase A's.
        let decrypts = h.rig().decrypts();
        let vm1 = vms_started(&h)[0].clone();
        parks_on(&mut h, &vm1);
        if suspend {
            suspended_under_the_park(&mut h, &vm1);
        }
        let rig = h.rig();
        // The moved CLI writes nothing of its own: the WIP on the new VM is the switch's seed.
        rig.set_vm_knobs(&knobs(&[]));
        let (runs, attempts, sent) = (run_tokens(rig).len(), rig.endpoint.attempts().len(), h.sent.clone());
        let o = rig.run(&["session", "migrate", &sid, "--json"], None);
        assert_eq!(o.status.code(), Some(0), "session migrate: {}\n{}", String::from_utf8_lossy(&o.stderr), h.wrapper_log());
        let doc: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("session migrate --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
        let vm2 = doc["to_vm"].as_str().expect("the new VM").to_string();
        assert_ne!(vm2, vm1);
        assert_eq!((doc["session"].as_str(), doc["outcome"].as_str(), doc["how"].as_str(), doc["from_vm"].as_str(), doc["code"].as_i64()), (Some(sid.as_str()), Some("done"), Some("live"), Some(vm1.as_str()), Some(0)), "{doc}");
        assert!(!paths_of(rig).session_migrate_request(&sid).exists(), "the wrapper took the request");
        wait_for_row(&mut h, "the old VM terminated", "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
        let u2 = turn(&mut h, "two");
        closed(&mut h);
        let rig = h.rig();
        assert_eq!(vms_started(&h), [vm1.clone(), vm2.clone()]);
        assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "one RunMicrovm; one Touch ID, phase A's: the park, the unpark and the switch ask none");
        // The unpark's socket: a new one to the resumed VM, or none (the open parked one carries the spawn again).
        let dialed: Vec<u16> = dials_since(rig, attempts).into_iter().filter(|(vm, _)| vm.as_deref() == Some(vm1.as_str())).map(|(_, status)| status).collect();
        assert_eq!(dialed, if suspend { vec![101] } else { vec![] }, "the old VM's upgrades since the request");
        let rows = h.audit_rows();
        let asked = index_of(&rows, "session_migrate_request", |d| d["session"] == sid.as_str() && d["how"] == "live");
        let nonce = rows[asked]["detail"]["nonce"].as_str().expect("the request's nonce").to_string();
        let parked = index_of(&rows, "session_park", |d| d["vm"] == vm1.as_str() && d["why"] == "idle");
        let moved = index_of(&rows, "session_move", |d| d["kind"] == "migrate" && d["trigger"] == "command" && d["request"] == nonce.as_str() && d["gen"] == "1" && d["from_vm"] == vm1.as_str() && d["session"] == sid.as_str());
        let unparked = index_of(&rows, "session_unpark", |d| d["vm"] == vm1.as_str());
        let fetched = index_after(&rows, unparked, "codeout_fetch", |d| d["vm"] == vm1.as_str());
        let seed = index_after(&rows, moved, "seed", |d| d["vm"] == vm2.as_str());
        let pull = index_after(&rows, moved, "transcript_pull", |d| d["vm"] == vm2.as_str() && d["session"] == sid.as_str());
        let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
        let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["kind"] == "migrate" && d["request"] == nonce.as_str() && d["to_vm"] == vm2.as_str());
        let ended = index_of(&rows, "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
        assert!(
            parked < moved && moved < unparked && unparked < fetched && fetched < seed && seed < start && pull < start && start < done && start < ended,
            "session_park {parked}, session_move {moved}, session_unpark {unparked}, codeout_fetch {fetched}, seed {seed}, transcript_pull {pull}, session_remote_start {start}, session_move_end {done}, vm_terminate {ended}"
        );
        // §4.2: an unpark by input names the host's last frame's kind (`QuietState.last_host`); the pump's keep_alive is no host frame.
        let d = &rows[unparked]["detail"];
        assert_eq!((d["by"].as_str(), d["vm_state"].as_str()), (Some("user"), Some(if suspend { "suspended" } else { "running" })), "{d}");
        let unparks = h.audit_events("session_unpark").iter().filter(|r| r["detail"]["vm"] == vm1.as_str()).count();
        assert_eq!((parks_of(&h, &vm1), unparks), (1, 1), "parked once on the old VM, and unparked once there, for the switch");
        one_setup_token_unseal(&rows, moved, start);
        assert_eq!(rows[moved..].iter().filter(|r| r["event"] == "credential_unseal").count(), 1, "the unpark and the switch never unseal");
        assert_eq!((rows[start]["detail"]["why"].as_str(), rows[done]["detail"]["touchid"].as_str()), (Some("migrate:command"), Some("asked")), "{} {}", rows[start], rows[done]);
        assert_eq!(h.audit_events("session_move_end").len(), 1, "the move's one end row");
        let keep_alive = r#"{"type":"keep_alive"}"#.to_string();
        assert_eq!(h.stdin_of(1), [sent, vec![keep_alive]].concat(), "the old CLI read the host's lines once, then the pump's one keep_alive: no host line again");
        let gen2 = replayed_state(&h, 2);
        assert_eq!(gen2[3..], [h.sent.last().cloned().expect("the last line")], "then the next line, never the keep_alive");
        let argv = h.argv_log();
        assert_eq!(argv.len(), 2, "{argv:?}");
        assert!(argv[1].contains(&format!("--resume={sid}")) && !argv[1].iter().any(|a| a.starts_with("--resume-session-at")), "{:?}", argv[1]);
        let out = h.out_json();
        for u in [&u1, &u2] {
            assert_eq!(out.iter().filter(|v| is_echo_of(v, u)).count(), 1, "one echo of {u}");
            assert_eq!(out.iter().filter(|v| is_result_for(v, u)).count(), 1, "one result for {u}");
        }
        let rig = h.rig();
        assert_eq!(text_of(&rig.vm_path_of(&vm2, &rig.work()), "agent.txt").as_deref(), Some(WIP_TEXT), "the turn's WIP, seeded at the switch");
        let note = h.end_note();
        assert!(note_has(&note, "moves:readdress=0,respawn=0,migrate=1") && part_of(&note, "vm").as_deref() == Some(vm2.as_str()), "{note}");
        // The census sums every generation's unparks: only the old VM's could find its VM suspended.
        assert_eq!(part_of(&note, "unpark_resumed").as_deref(), suspend.then_some("1"), "{note}");
        h.assert_vm_empty();
    }

    /// I2 (g): [`session_migrate_moves_a_chat_parked`], the chat parked with
    /// no socket, its VM suspended under the park: the keep_alive's unpark
    /// resumes it (GetMicrovm, the endpoint's auto-resume, a new socket).
    #[test]
    fn session_migrate_moves_a_parked_chat() {
        session_migrate_moves_a_chat_parked(true);
    }

    /// I2 (g), the twin: [`session_migrate_moves_a_chat_parked`], the chat
    /// parked on its open socket, its VM running: the keep_alive's unpark
    /// goes on that socket.
    #[test]
    fn session_migrate_moves_a_chat_parked_on_its_open_socket() {
        session_migrate_moves_a_chat_parked(false);
    }

    /// S10 §2.7, C-2 (phase 4b V-6): a chat whose VM stops answering it
    /// (every socket cut, every request on the app port the proxy's 502,
    /// until its reconnect budget is spent: `Unreachable`) while another live
    /// wrapper's chat runs on that VM (parked there: its socket cut too, it
    /// stays parked and dials nothing) moves with its next line, and M1 stops
    /// its own claude on that VM, which the shim answers: TERM to that spawn
    /// on a socket to the old VM, its `exit` (signal 15) read back, no
    /// `detach` (the trace, [`answered_stop`]), and the shim releases it,
    /// before the new VM's spawn. The VM is kept for the other chat: no
    /// TerminateMicrovm, still RUNNING, its row not terminated, the other
    /// chat's claude alive and parked under its wrapper. The move takes a new
    /// VM with its one Touch ID (`session_move` `readdress`, `unreachable`),
    /// and the line is answered there once; the other chat's next line then
    /// runs on the kept VM.
    #[test]
    fn an_answered_stop_keeps_the_vm_another_live_chat_runs_on() {
        let mut other = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs(&[PARK]));
        started(&mut other);
        turn(&mut other, "one");
        let other_sid = session_of(&mut other);
        synced(&mut other, &other_sid, 1);
        let vm1 = vms_started(&other)[0].clone();
        parks_on(&mut other, &vm1);
        // The chat that loses the VM: in the same workspace, so on that VM; its frames traced.
        let mut h = Harness::prepare().launch_wrapper(other.rig().wrapper(&[], &knobs(&[("AI_ENV_BRIDGE_TRACE", "2")])));
        started(&mut h);
        let u1 = turn(&mut h, "one");
        let sid = session_of(&mut h);
        synced(&mut other, &sid, 1);
        assert_eq!(vms_started(&other), [vm1.as_str(), vm1.as_str()], "both chats on one VM");
        let owner = other.pid();
        let rig = other.rig();
        let shim = rig.shim_of(&vm1);
        let mine: Vec<SpawnId> = shim.spawns.detail().into_iter().filter(|d| d.status.alive && d.parked.is_none()).map(|d| d.status.spawn_id).collect();
        assert_eq!(mine.len(), 1, "the moving chat's claude beside the parked one: {:?}", shim.spawns.detail());
        let mine = mine[0].clone();
        let (runs, decrypts) = (run_tokens(rig).len(), rig.decrypts());
        // Unreachable for the moving chat: its socket cut, every request on the app port a 502 until it gave up.
        rig.endpoint.script_port(APP_PORT, vec![Action::status(502, &[]); 400]);
        rig.endpoint.cut_all();
        moves_with_the_next_message(&mut h, &vm1);
        other.rig().endpoint.unscript_port(APP_PORT);
        let u2 = turn(&mut h, "two");
        let rig = other.rig();
        let vms = vms_started(&other);
        assert_eq!(vms.len(), 3, "{vms:?}");
        let vm2 = vms[2].clone();
        assert_ne!(vm2, vm1);
        assert_eq!((run_tokens(rig).len() - runs, rig.decrypts() - decrypts), (1, 1), "one RunMicrovm, one Touch ID: the move's");
        assert!(!rig.fake_calls().iter().any(|c| matches!(c, Call::Terminate(id) if *id == vm1)), "no TerminateMicrovm of the kept VM: {:?}", rig.fake_calls());
        assert_eq!(rig.fake().vms.get(&vm1).map(|v| v.state.clone()), Some(VmState::Running), "the kept VM runs");
        let row = ai_env_cli::bridge::vm::registry::read_row(&paths_of(rig), &vm1).expect("the VM's row").expect("a row of the kept VM");
        assert_eq!((row.status.as_str(), row.terminated_by.as_deref()), ("running", None), "{row:?}");
        let held = shim.spawns.detail();
        assert!(held.iter().any(|d| d.status.alive && d.parked.is_some_and(|o| o.pid == owner)), "the other chat's claude lives on, parked under its wrapper: {held:?}");
        assert!(!held.iter().any(|d| d.status.spawn_id == mine), "the moving chat's claude was stopped and released: {held:?}");
        let rows = other.audit_rows();
        let moved = index_of(&rows, "session_move", |d| d["gen"] == "2" && d["kind"] == "readdress" && d["cause"] == "unreachable" && d["from_vm"] == vm1.as_str() && d["session"] == sid.as_str());
        let start = index_of(&rows, "session_remote_start", |d| d["id"] == vm2.as_str());
        let done = index_of(&rows, "session_move_end", |d| d["outcome"] == "done" && d["kind"] == "readdress" && d["to_vm"] == vm2.as_str());
        assert!(moved < start && start < done, "session_move {moved}, session_remote_start {start}, session_move_end {done}");
        let frames = traced(&other.bridge(), h.pid());
        let (term, exit) = answered_stop(&frames, &vm1, &mine.0);
        assert_eq!(frames[exit]["frame"]["signal"], 15, "the moving chat's claude died of the TERM: {}", frames[exit]);
        let on2 = sockets_on(&frames, &vm2);
        let spawn2 = frames
            .iter()
            .position(|f| f["dir"] == "mac" && f["frame"]["t"] == "spawn" && f["socket"].as_u64().is_some_and(|n| on2.contains(&n)))
            .unwrap_or_else(|| panic!("generation 2's spawn on {vm2}: {:#?}", frame_summary(&frames)));
        assert!(exit < spawn2, "the stop ended before the new VM's spawn: TERM {term}, exit {exit}, spawn {spawn2}: {:#?}", frame_summary(&frames));
        let out = h.out_json();
        for u in [&u1, &u2] {
            assert_eq!(out.iter().filter(|v| is_result_for(v, u)).count(), 1, "one result for {u}");
        }
        // The other chat goes on on the kept VM: its next line unparks it there.
        let u3 = turn(&mut other, "two");
        assert_eq!(other.out_json().iter().filter(|v| is_result_for(v, &u3)).count(), 1);
        assert!(other.audit_events("session_unpark").iter().any(|r| r["detail"]["vm"] == vm1.as_str()), "{:?}", other.audit_events("session_unpark"));
        closed(&mut h);
        closed(&mut other);
        other.assert_vm_empty();
    }
}
