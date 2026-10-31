//! The multi-VM rig's and the fakes' self-tests (S10, plans/s10-contracts.md
//! §8.5; S10 wave 1a, R). The rig (`common::remote`) gives each fake VM a
//! shim and a disk of its own at its first request through the endpoint
//! (`FakeEndpoint::start_per_vm`): each VM's `/run` answered by its own shim,
//! a request routed by its VM and its port, a VM's `/health/detail` its own
//! shim's, every shim stopped with the rig. The fake API ends a VM at its
//! wall only when asked (`FakeState::enforce_wall`, which the rig sets), the
//! endpoint's tick posting that VM's `/terminate`. The fake claude's S10
//! knobs (`tests/fakes/claude-v2.sh`): the held permission prompt, the
//! subagents and the subtree's log, the long tool run and its mark, the cut
//! and the session id, and the uuid each assistant frame shares with its
//! transcript entry. Declared in S10 phase 0. Phase 4b: the platform's end
//! waits for the VM's shim (`FakeState::terminate_after_hook`), a call the
//! wall ended leaves no record, `Harness::assert_vm_empty` reads every VM's
//! shim, and the fake continues a resumed chain and forks one.

use super::common::remote::{toml_table, RemoteRig, Req, LIMIT};
use super::common::{self, env_log_field, is_init, is_permission_request, is_response_to, is_result_for, permission_answer, Harness};
use ai_env_cli::bridge::api::{Call, FakeState, IdleSpec, RunSpec, VmState, APP_PORT, FAKE_IMAGE_ARN, FAKE_WALL_REASON};
use ai_env_cli::bridge::config::Paths;
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use ai_env_cli::bridge::vm::registry::read_row;
use ai_env_cli::wire::claude::{classify_child, is_cut_miss, is_resume_miss, ChildFrame};
use ai_env_cli::wire::time::unix_now;
use serde_json::value::RawValue;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Every wait's bound.
const T: Duration = Duration::from_secs(60);
const INIT: &str = r#"{"request_id":"i1","type":"control_request","request":{"subtype":"initialize"}}"#;

/// Poll `done` every 25 ms until it holds; past `within` panic naming `what`.
fn wait_for(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let t = Instant::now();
    while !done() {
        assert!(t.elapsed() < within, "{what}: not within {within:?}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The entry names of `dir`, sorted (none when it is missing).
fn names_in(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir).map(|rd| rd.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    out.sort();
    out
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Every line of `text`, as JSON (a line that is not panics).
fn json_lines(text: &str) -> Vec<Value> {
    text.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}"))).collect()
}

// ---- the rig: a shim and a disk per VM -------------------------------------------------------

/// `vm exec <vm> -- claude --verbose` on the rig, run to its end:
/// `initialize`, the user line `uuid`, then EOF; the CLI's frames, once
/// the exec exited 0 with the turn's result.
fn exec_turn(rig: &RemoteRig, vm: &str, uuid: &str) -> Vec<Value> {
    let stdin = format!("{INIT}\n{}\n", Harness::user_line(uuid, "a turn"));
    let o = rig.run(&["vm", "exec", vm, "--", "claude", "--verbose"], Some(stdin.as_bytes()));
    assert_eq!(o.status.code(), Some(0), "vm exec {vm}: {}", String::from_utf8_lossy(&o.stderr));
    let frames = json_lines(&String::from_utf8_lossy(&o.stdout));
    assert!(frames.iter().any(|f| is_result_for(f, uuid)), "the turn's result on {vm}: {frames:?}");
    frames
}

/// A `vm exec <vm> -- claude` left running, its stdin open and its stdout
/// dropped, once its CLI lives on that VM.
fn exec_open(rig: &RemoteRig, vm: &str) -> std::process::Child {
    let mut cmd = rig.ai_env(&["vm", "exec", vm, "--", "claude"]);
    cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped());
    let child = cmd.spawn().expect("spawn vm exec");
    wait_for(&format!("a CLI alive on {vm}"), T, || rig.vm_ids().iter().any(|v| v == vm) && rig.vm_spawns_of(vm).iter().any(|s| s.alive));
    child
}

/// The value of `key` in the fake's env-log line that generation `gen` of it
/// wrote at its start (`gen <g> CLAUDE_CONFIG_DIR=… pid=…`, under `root`).
fn started_with(root: &Path, gen: u32, key: &str) -> Option<String> {
    let prefix = format!("gen {gen} CLAUDE_CONFIG_DIR=");
    let log = std::fs::read_to_string(root.join("env.log")).unwrap_or_default();
    log.lines().find(|l| l.starts_with(&prefix)).and_then(|l| env_log_field(l, key)).map(str::to_string)
}

/// The hooks the endpoint posted as the platform, as (VM, hook, status).
fn hooks_of(rig: &RemoteRig) -> Vec<(String, &'static str, u16)> {
    rig.endpoint.hooks().into_iter().map(|h| (h.vm, h.name, h.status)).collect()
}

/// Two VMs of the workspace (the second by `vm run --new`), a turn on each
/// through `vm exec`: each VM's first request runs it on a shim of its own
/// (`/run` answered 200 by both, where one shim would answer the second
/// 409), in the order of their first requests. The first VM keeps the shim
/// and the disk made with the rig (`rig.shim`, `<tmp>/vm`); the second has
/// `<tmp>/vm-2`, its home the Mac's `HOME` under it. Each CLI started with
/// its own VM's config dir, and its transcript is on that VM's disk alone.
#[test]
fn rig_two_vms_each_get_run_and_keep_their_own_transcripts() {
    let mut p = Harness::prepare();
    let slug = p.slug();
    let rig = p.rig();
    rig.set_vm_knobs(&[("FAKE_WRITE_TRANSCRIPT", "1")]);
    let one = rig.start_vm();
    let two = rig.start_new_vm();
    assert_ne!(one, two, "vm run --new: a second VM");
    let (first, second) = (common::uuid(0x1001), common::uuid(0x1002));
    exec_turn(rig, &one, &first);
    exec_turn(rig, &two, &second);
    assert_eq!(hooks_of(rig), [(one.clone(), "run", 200), (two.clone(), "run", 200)], "each VM run on a shim of its own");
    assert_eq!((rig.vm_ids(), rig.newest_vm()), (vec![one.clone(), two.clone()], Some(two.clone())));
    assert!(Arc::ptr_eq(&rig.shim_of(&one), &rig.shim), "the first VM keeps the rig's first shim");
    for vm in [&one, &two] {
        assert_eq!(rig.shim_of(vm).run.view().microvm_id.as_deref(), Some(vm.as_str()), "{vm}'s shim ran {vm}");
    }
    assert_eq!((rig.vm_root_of(&one), rig.vm_projects_of(&one)), (rig.vm_root(), rig.vm_projects()), "the first VM's disk is the rig's first");
    let disk = rig.root().join("vm-2");
    assert_eq!(rig.vm_root_of(&two), disk);
    assert_eq!(rig.vm_home_of(&two), rig.vm_path_of(&two, rig.root()), "its home: the Mac's HOME under its fs_root");
    assert_eq!(rig.vm_path_of(&two, &rig.work()), disk.join(rig.work().strip_prefix("/").unwrap()));
    for (gen, vm) in [(1, &one), (2, &two)] {
        let config = rig.vm_home_of(vm).join(".claude").display().to_string();
        assert_eq!(started_with(rig.root(), gen, "CLAUDE_CONFIG_DIR"), Some(config), "generation {gen} ran on {vm}");
    }
    let file = |gen: u64| format!("{}.jsonl", common::fake_gen_sid(gen));
    assert_eq!(names_in(&rig.vm_projects_of(&one).join(&slug)), [file(1)]);
    assert_eq!(names_in(&rig.vm_projects_of(&two).join(&slug)), [file(2)]);
    let (on_one, on_two) = (read(&rig.vm_projects_of(&one).join(&slug).join(file(1))), read(&rig.vm_projects_of(&two).join(&slug).join(file(2))));
    assert!(on_one.contains(&first) && !on_one.contains(&second), "{on_one}");
    assert!(on_two.contains(&second) && !on_two.contains(&first), "{on_two}");
}

/// Nothing for a second VM reaches the first VM's shim: its `/health` and
/// its code listener's 401 are its own shim's, through listeners the
/// endpoint built for it, each attempt naming the VM the check found, and
/// its CLI runs on its own disk; the first shim's run, spawns and disk stay
/// the first VM's alone.
#[test]
fn rig_nothing_for_vm_2_reaches_shim_1() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let one = rig.start_vm();
    let app1 = rig.mint(&one, APP_PORT);
    assert_eq!(rig.send(&one, &Req::get("/health", APP_PORT, &app1)).json()["microvm_id"].as_str(), Some(one.as_str()), "the first VM's shim");
    let two = rig.start_new_vm();
    let (app2, code2) = (rig.mint(&two, APP_PORT), rig.mint(&two, 9418));
    let health = rig.send(&two, &Req::get("/health", APP_PORT, &app2));
    assert_eq!((health.status, health.json()["microvm_id"].as_str()), (200, Some(two.as_str())), "the second VM's own shim answers");
    assert_eq!(rig.send(&two, &Req::get("/health", 9418, &code2)).status, 401, "its code listener: behind its bearer");
    exec_turn(rig, &two, &common::uuid(0x1003));
    let (r1, r2) = (rig.endpoint.routes_of(&one).expect("the first VM's listeners"), rig.endpoint.routes_of(&two).expect("the second VM's listeners"));
    assert_eq!((r1.hooks, r1.app, r1.code), (rig.hooks, rig.app, rig.code), "the first VM's: the rig's first shim's");
    assert!([r2.hooks, r2.app, r2.code].iter().all(|a| ![rig.hooks, rig.app, rig.code].contains(a)), "the second VM's are its own: {r2:?}");
    let named: Vec<Option<String>> = rig.endpoint.attempts().into_iter().map(|a| a.vm).collect();
    assert_eq!(named.first(), Some(&Some(one.clone())), "{named:?}");
    assert!(named.len() > 3 && named[1..].iter().all(|vm| vm.as_deref() == Some(two.as_str())), "every later request was the second VM's: {named:?}");
    assert_eq!(hooks_of(rig), [(one.clone(), "run", 200), (two.clone(), "run", 200)]);
    assert_eq!(rig.shim.run.view().microvm_id.as_deref(), Some(one.as_str()), "the first shim ran the first VM alone");
    assert!(rig.shim.spawns.detail().is_empty(), "no spawn ever on the first shim: {:?}", rig.shim.spawns.detail());
    assert_eq!(started_with(rig.root(), 1, "CLAUDE_CONFIG_DIR"), Some(rig.vm_home_of(&two).join(".claude").display().to_string()), "the CLI ran on the second VM's disk");
    assert!(files_under(&rig.vm_projects()).is_empty(), "nothing on the first VM's disk: {:?}", files_under(&rig.vm_projects()));
}

/// Every file under `dir`, relative to it (none when it is missing).
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().filter_map(Result::ok) {
        let path = e.path();
        if path.is_dir() {
            out.extend(files_under(&path).into_iter().map(|p| PathBuf::from(e.file_name()).join(p)));
        } else {
            out.push(PathBuf::from(e.file_name()));
        }
    }
    out
}

/// A VM terminated (`vm terminate`): its shim is told so and drains, and a
/// VM started after it serves on a shim of its own (`/run` answered 200,
/// which the draining shim could no longer give), a turn there runs.
#[test]
fn rig_vm_2_serves_after_vm_1_is_terminated() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let one = rig.start_vm();
    exec_turn(rig, &one, &common::uuid(0x1004));
    let o = rig.run(&["vm", "terminate", &one, "--yes"], None);
    assert!(o.status.success(), "vm terminate: {}", String::from_utf8_lossy(&o.stderr));
    wait_for("the first VM's shim told of its terminate", T, || hooks_of(rig).iter().any(|(vm, hook, status)| *vm == one && *hook == "terminate" && *status == 200));
    assert!(rig.shim.is_draining(), "the first VM's shim drains");
    let two = rig.start_vm();
    assert_ne!(two, one, "the workspace's VM is gone: a new one");
    exec_turn(rig, &two, &common::uuid(0x1005));
    assert_eq!(hooks_of(rig), [(one.clone(), "run", 200), (one.clone(), "terminate", 200), (two.clone(), "run", 200)]);
    assert!(!rig.shim_of(&two).is_draining(), "the second VM's shim serves");
    assert_eq!(rig.vm_ids(), [one, two]);
}

/// `vm health --detail` of each of two VMs reaches that VM's own shim (the
/// endpoint, the VM's session bearer): each detail names its VM, as its
/// shim's `/run` did, and a CLI left running on one VM is in that VM's
/// detail alone. The shims went to the VMs in the order of their first
/// requests: the VM a CLI started on first has the rig's first shim.
#[test]
fn rig_health_detail_reaches_the_right_shim() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let one = rig.start_vm();
    let two = rig.start_new_vm();
    let mut exec = exec_open(rig, &two);
    let detail = |vm: &str| -> Value {
        let o = rig.run(&["vm", "health", vm, "--detail", "--json"], None);
        assert!(o.status.success(), "vm health {vm} --detail: {}", String::from_utf8_lossy(&o.stderr));
        let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("vm health --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
        v["detail"].clone()
    };
    let (d1, d2) = (detail(&one), detail(&two));
    assert_eq!((d1["microvm_id"].as_str(), d2["microvm_id"].as_str()), (Some(one.as_str()), Some(two.as_str())), "each VM's own shim");
    let spawns = |d: &Value| d["spawns"].as_array().map_or(0, Vec::len);
    assert_eq!((spawns(&d1), spawns(&d2)), (0, 1), "the CLI on the second VM alone: {d1} {d2}");
    assert_eq!(rig.vm_ids(), [two.clone(), one.clone()], "in the order of their first requests");
    assert!(Arc::ptr_eq(&rig.shim_of(&two), &rig.shim), "the first VM a request reached has the rig's first shim");
    assert_eq!(rig.vm_root_of(&one), rig.root().join("vm-2"));
    drop(exec.stdin.take());
    let o = common::bounded::finish_within(exec, LIMIT, "vm exec");
    assert_eq!(o.status.code(), Some(0), "vm exec: {}", String::from_utf8_lossy(&o.stderr));
}

/// Whether process group `pgid` still has a member (killpg(2) with signal
/// 0; a member this process may not signal counts).
fn group_alive(pgid: u32) -> bool {
    let Ok(pgid) = i32::try_from(pgid) else { return false };
    // SAFETY: killpg(2) with signal 0 only checks for the group's members and permission.
    let rc = unsafe { libc::killpg(pgid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// The rig's drop stops every VM's shim: a CLI left running on each of two
/// VMs (each `vm exec`'s stdin kept open), each in a long tool run
/// (FAKE_TURN_MS) whose `sleep` is in its process group (the spawn's
/// setsid: the group is the CLI's pid), is gone with its whole group once
/// the rig is, each CLI TERMed first (FAKE_TERM_LOG): a shim's stop, its
/// TERM to every group, then KILL. A shim left unstopped at most KILLs (the
/// spawn's kill_on_drop: the CLI alone, its `sleep` left), and no TERM is
/// logged. The VMs' shims share the fake's generation counter, so the
/// second CLI starts once the first has its generation. The fake marks its
/// tool before it forks the tool's `sleep`, and a group TERM before that
/// fork has exec'd `sleep` runs the fake's TERM trap in the fork too (two
/// TERM lines from one CLI), so the rig drops once each group's `sleep` runs.
#[test]
fn rig_no_spawn_left_after_drop() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = std::fs::canonicalize(tmp.path()).expect("canonicalize the tempdir");
    let rig = RemoteRig::new(&root);
    let (mark, term) = (root.join("mark"), root.join("term.log"));
    rig.set_vm_knobs(&[("FAKE_TURN_MS", "60000"), ("FAKE_TURN_MARK", mark.to_str().unwrap()), ("FAKE_TERM_LOG", term.to_str().unwrap())]);
    let vms = [rig.start_vm(), rig.start_new_vm()];
    let pid_of = |gen: u32| started_with(&root, gen, "pid").and_then(|p| p.parse::<u32>().ok());
    let first = exec_open(&rig, &vms[0]);
    wait_for("the first CLI's pid logged", T, || pid_of(1).is_some());
    let mut execs = vec![first, exec_open(&rig, &vms[1])];
    wait_for("both CLIs' pids logged", T, || pid_of(2).is_some());
    for (exec, n) in execs.iter_mut().zip([0x1011, 0x1012]) {
        let stdin = format!("{INIT}\n{}\n", Harness::user_line(&common::uuid(n), "a long tool"));
        exec.stdin.as_mut().expect("the exec's stdin").write_all(stdin.as_bytes()).expect("write the exec's stdin");
    }
    wait_for("each CLI in its long tool", T, || {
        let marked = std::fs::read_to_string(&mark).unwrap_or_default();
        ["gen 1 turn 1", "gen 2 turn 1"].iter().all(|m| marked.lines().any(|l| l == *m))
    });
    let pids: Vec<u32> = (1..=2).filter_map(pid_of).collect();
    let sleeping = |pgid: u32| Command::new("/usr/bin/pgrep").args(["-g", &pgid.to_string(), "-x", "sleep"]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    wait_for("each CLI's tool sleep running in its group", T, || pids.iter().all(|pid| sleeping(*pid)));
    assert!(pids.iter().all(|pid| common::pid_alive(*pid) && group_alive(*pid)), "both CLIs and their groups run: {pids:?}");
    assert_eq!(vms.iter().map(|vm| rig.vm_spawns_of(vm).len()).collect::<Vec<_>>(), [1, 1], "one spawn on each VM's shim");
    drop(rig);
    let deadline = Instant::now() + common::VM_END;
    while pids.iter().any(|pid| group_alive(*pid)) {
        assert!(Instant::now() < deadline, "a CLI's group outlived the rig: {:?}", pids.iter().filter(|pid| group_alive(**pid)).collect::<Vec<_>>());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(std::fs::read_to_string(&term).unwrap_or_default(), "TERM\nTERM\n", "each CLI TERMed by its shim's stop");
    for mut exec in execs {
        let _ = exec.kill();
        let _ = exec.wait();
    }
}

/// `rig.config` edits bridge.toml as TOML: two edits of one table leave one
/// `[vm]` table holding both keys (appended text would add a second, which
/// TOML refuses), the green world's tables kept, and `vm run` reads the
/// result (its VM's maximum duration).
#[test]
fn rig_config_edits_bridge_toml_as_toml() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    rig.config(|doc| {
        toml_table(doc, "vm").insert("max_duration_s".into(), toml::Value::Integer(1800));
    });
    rig.config(|doc| {
        toml_table(doc, "vm").insert("max_readdress".into(), toml::Value::Integer(2));
    });
    let text = read(&rig.bridge().join("bridge.toml"));
    let doc: toml::Table = toml::from_str(&text).unwrap_or_else(|e| panic!("bridge.toml: {e}\n{text}"));
    assert_eq!((doc["vm"]["max_duration_s"].as_integer(), doc["vm"]["max_readdress"].as_integer()), (Some(1800), Some(2)), "{text}");
    assert_eq!(text.matches("[vm]").count(), 1, "{text}");
    assert_eq!(doc["aws"]["image_arn"].as_str(), Some(FAKE_IMAGE_ARN), "{text}");
    assert_eq!(doc["workspaces"]["roots"].as_array().map(Vec::len), Some(1), "{text}");
    let vm = rig.start_vm();
    assert_eq!(rig.fake().vms[&vm].max_duration_s, 1800, "vm run read the edited [vm]");
}

/// The platform's end waits for the VM's shim, as the platform's VM ends
/// once its terminate hook returned (`FakeState::terminate_after_hook`,
/// which the rig sets): a VM the endpoint ran on its shim (`hook_ran`, the
/// rig's factory's record) and the platform ended (TERMINATING, no
/// TerminateMicrovm) stays TERMINATING, whoever looks, while its shim has
/// not answered `/terminate` (the tick held off: nothing posts it). Once
/// the tick posted it and the shim answered (`terminate_answered`, which
/// the rig's hooks listener records before the endpoint has the answer),
/// the next look finds it TERMINATED. A VM no request reached (no shim ran
/// it) ends at the next look.
#[test]
fn rig_a_vm_ends_once_its_shim_answered_terminate() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    assert!(rig.fake().terminate_after_hook, "the rig asks for it");
    let vm = rig.start_vm();
    let app = rig.mint(&vm, APP_PORT);
    assert_eq!(rig.send(&vm, &Req::get("/health", APP_PORT, &app)).status, 200, "the endpoint ran it on its shim");
    assert!(rig.fake().hook_ran.contains(&vm), "the factory's record");
    let api = FileFakeMicrovmApi::open(&rig.fake_path()).expect("the fake");
    let look = |id: &str| api.with(|s| s.get(id)).expect("GetMicrovm").state;
    rig.endpoint.ticking(false);
    rig.update_fake(|s| s.vms.get_mut(&vm).expect("the VM").state = VmState::Terminating);
    for _ in 0..3 {
        assert_eq!(look(&vm), VmState::Terminating, "its shim has not answered /terminate");
    }
    assert!(!hooks_of(rig).iter().any(|(id, hook, _)| *id == vm && *hook == "terminate"), "nothing posted it yet");
    rig.endpoint.ticking(true);
    wait_for("its shim answered /terminate", T, || hooks_of(rig).iter().any(|(id, hook, status)| *id == vm && *hook == "terminate" && *status == 200));
    assert!(rig.fake().terminate_answered.contains(&vm), "recorded before the endpoint had the answer");
    assert!(rig.shim_of(&vm).is_draining(), "its shim drains");
    assert_eq!(look(&vm), VmState::Terminated, "the look after the answer");
    let quiet = rig.start_new_vm();
    rig.update_fake(|s| s.vms.get_mut(&quiet).expect("the VM").state = VmState::Terminating);
    assert_eq!(look(&quiet), VmState::Terminated, "no shim ran it: TERMINATED at the next look");
    assert!(!rig.fake().hook_ran.contains(&quiet));
}

/// `Harness::assert_vm_empty` reads every VM's shim, not the rig's first
/// one alone: a CLI left running on a second VM (a shim of its own; its
/// pid logged elsewhere, so only that shim's table shows it) fails the
/// check; once the platform ends that VM, its shim, told `/terminate`,
/// stops the spawn, and the check passes within `VM_END` (the stopped
/// shim keeps the exit nobody collected: no live spawn is what counts).
#[test]
fn rig_assert_vm_empty_reads_every_vms_shim() {
    let mut p = Harness::prepare();
    let (one, two, cmd) = {
        let rig = p.rig();
        let one = rig.start_vm();
        exec_turn(rig, &one, &common::uuid(0x1701));
        let two = rig.start_new_vm();
        let elsewhere = rig.root().join("env-two.log").display().to_string();
        rig.set_vm_knobs(&[("FAKE_ENV_LOG", elsewhere.as_str())]);
        let cmd = rig.ai_env(&["vm", "exec", &two, "--", "claude"]);
        (one, two, cmd)
    };
    let h = p.launch_wrapper(cmd);
    let rig = h.rig();
    wait_for("a CLI alive on the second VM", T, || rig.vm_ids().contains(&two) && rig.vm_spawns_of(&two).iter().any(|s| s.alive));
    assert!(Arc::ptr_eq(&rig.shim_of(&one), &rig.shim) && !Arc::ptr_eq(&rig.shim_of(&two), &rig.shim), "the first VM has the rig's first shim, the second one of its own");
    // The first VM's CLI ended, left its shim and was reaped (a zombie counts as alive); the second's
    // logged its pid elsewhere: only the second VM's shim shows a CLI.
    wait_for("the first VM's CLI gone", T, || rig.vm_spawns_of(&one).is_empty() && h.fake_pid(1).is_some_and(|pid| !common::pid_alive(pid)));
    wait_for("the second VM's CLI logged elsewhere", T, || std::fs::read_to_string(rig.root().join("env-two.log")).unwrap_or_default().starts_with("gen 2 "));
    assert_eq!(h.fake_pid(2), None, "no pid of it in the env log");
    let held = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.assert_vm_empty_within(Duration::from_millis(300))));
    assert!(held.is_err(), "the second VM's spawn fails the check");
    rig.update_fake(|s| s.vms.get_mut(&two).expect("the VM").state = VmState::Terminating);
    h.assert_vm_empty();
    assert!(rig.shim_of(&two).is_draining() && rig.vm_spawns_of(&two).iter().all(|s| !s.alive), "{:?}", rig.vm_spawns_of(&two));
}

// ---- the fake API's wall ----------------------------------------------------------------------

/// The fake image's run of a VM whose wall is 900 s after its start.
fn run_spec(token: &str) -> RunSpec {
    RunSpec {
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        execution_role_arn: None,
        ingress_connectors: vec![],
        egress_connectors: vec![],
        idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
        max_duration_s: 900,
        run_hook_payload: "{}".into(),
        client_token: token.into(),
    }
}

/// A RUNNING VM of [`run_spec`] in `s`, its start `aged` seconds ago.
fn running(s: &mut FakeState, token: &str, aged: u64) -> String {
    let id = s.run(&run_spec(token)).expect("RunMicrovm").id;
    s.advance_all();
    s.age(&id, aged);
    id
}

/// The fake API's wall (S10, `FakeState::enforce_wall`). Off by default, a
/// VM past `started_at_unix + max_duration_s` runs on, whoever looks; asked
/// for, the next look ends it (TERMINATING, `FAKE_WALL_REASON`; TERMINATED
/// at the look after), suspended time counted, and a suspend, a resume or a
/// token of it refused. On the rig, which asks for it: with the switch off,
/// a VM brought to its wall (`bring_wall_near`, which moves the Mac's row
/// with the fake's start) stays RUNNING through a look (a request through
/// the endpoint, which runs the tick's look first) and its shim hears
/// nothing; with it on, the endpoint's tick ends the VM and posts
/// `/terminate` to its shim (no TerminateMicrovm: the platform's end), which
/// drains; a VM brought near its wall runs on through a look, as much left
/// on both sides. A SuspendMicrovm that is the first look past a VM's wall
/// (the tick held off) is refused and leaves no call for the endpoint to
/// replay: that VM's shim hears its `/run`, then its `/terminate`, nothing
/// between.
#[test]
fn the_fake_api_ends_a_vm_at_its_wall_only_when_asked() {
    let mut s = FakeState::new();
    assert!(!s.enforce_wall, "off by default");
    let old = running(&mut s, "t1", 900);
    assert_eq!((s.get(&old).unwrap().state, s.list(None).unwrap()[0].state.clone()), (VmState::Running, VmState::Running), "no wall without the switch");
    s.enforce_wall = true;
    let ended = s.get(&old).unwrap();
    assert_eq!((&ended.state, ended.state_reason.as_deref()), (&VmState::Terminating, Some(FAKE_WALL_REASON)));
    assert_eq!(s.get(&old).unwrap().state, VmState::Terminated, "TERMINATED at the look after");
    let young = running(&mut s, "t2", 800);
    assert_eq!(s.get(&young).unwrap().state, VmState::Running, "100 s short of its wall");
    let resting = running(&mut s, "t3", 0);
    s.suspend(&resting).unwrap();
    s.age(&resting, 900);
    assert!(matches!(s.resume(&resting), Err(BridgeError::Conflict(_))), "suspended time counts; the resume looks first");
    let busy = running(&mut s, "t4", 900);
    assert!(matches!(s.suspend(&busy), Err(BridgeError::Conflict(_))), "the suspend looks first");
    let tokened = running(&mut s, "t5", 900);
    assert!(matches!(s.create_auth_token(&tokened, 5, APP_PORT), Err(BridgeError::Conflict(_))), "a token's call looks first");

    let mut p = Harness::prepare();
    let rig = p.rig();
    assert!(rig.fake().enforce_wall, "the rig asks for the wall");
    let vm = rig.start_vm();
    let app = rig.mint(&vm, APP_PORT);
    assert_eq!(rig.send(&vm, &Req::get("/health", APP_PORT, &app)).status, 200, "the VM runs on its shim");
    rig.update_fake(|s| s.enforce_wall = false);
    rig.bring_wall_near(&vm, 0);
    let paths = Paths::from_root_and_env(rig.bridge(), None);
    let left = |vm: &str| read_row(&paths, vm).expect("the rows").expect("the VM's row").wall_left(unix_now()).expect("its wall");
    assert!((-10..=0).contains(&left(&vm)), "the Mac's row at the wall too: {} s left", left(&vm));
    assert_eq!(rig.send(&vm, &Req::get("/health", APP_PORT, &app)).status, 200, "off: a look through the endpoint (the bridge's tick, then the check) ends nothing");
    assert_eq!(rig.fake().vms[&vm].state, VmState::Running, "off: nothing ends it");
    assert_eq!(hooks_of(rig), [(vm.clone(), "run", 200)], "nothing told its shim");
    rig.update_fake(|s| s.enforce_wall = true);
    wait_for("the tick ended the VM and posted its /terminate", T, || hooks_of(rig).iter().any(|(id, hook, status)| *id == vm && *hook == "terminate" && *status == 200));
    let ended = rig.fake().vms[&vm].clone();
    assert!(ended.state.is_terminal() && ended.state_reason.as_deref() == Some(FAKE_WALL_REASON), "{ended:?}");
    assert!(rig.shim_of(&vm).is_draining(), "its shim drains");
    assert!(!rig.fake_calls().iter().any(|c| matches!(c, Call::Terminate(_))), "the platform's end: no TerminateMicrovm");
    let near = rig.start_new_vm();
    rig.bring_wall_near(&near, 600);
    assert!((590..=600).contains(&left(&near)), "{} s left", left(&near));
    let app = rig.mint(&near, APP_PORT);
    assert_eq!(rig.send(&near, &Req::get("/health", APP_PORT, &app)).status, 200, "near its wall: a look ends nothing");
    let fresh = rig.fake().vms[&near].clone();
    let row = read_row(&paths, &near).expect("the rows").expect("its row");
    let wall = fresh.started_at_unix.map(|t| t + i64::from(fresh.max_duration_s));
    assert_eq!((&fresh.state, wall), (&VmState::Running, row.wall_deadline.map(|d| i64::try_from(d).unwrap())), "the fake's wall where the row's is");
    let last = rig.start_new_vm();
    let app = rig.mint(&last, APP_PORT);
    assert_eq!(rig.send(&last, &Req::get("/health", APP_PORT, &app)).status, 200, "the VM runs on its shim");
    rig.endpoint.ticking(false);
    rig.bring_wall_near(&last, 0);
    let refused = FileFakeMicrovmApi::open(&rig.fake_path()).and_then(|api| api.with(|s| Ok(s.suspend(&last)))).expect("the fake");
    rig.endpoint.ticking(true);
    assert!(matches!(refused, Err(BridgeError::Conflict(_))), "its own look ended it: {refused:?}");
    wait_for("the tick told its shim of its end", T, || hooks_of(rig).iter().any(|(id, hook, status)| *id == last && *hook == "terminate" && *status == 200));
    let told: Vec<&str> = hooks_of(rig).into_iter().filter(|(id, _, _)| *id == last).map(|(_, hook, _)| hook).collect();
    assert_eq!(told, ["run", "terminate"], "no /suspend: the refused call moved nothing");
}

// ---- the fake claude, run as the shim runs it --------------------------------------------------

/// A tempdir with the fake claude linked as `claude` (`Harness::prepare`'s):
/// its cwd `work/`, its config dir `home/.claude`, its env log `env.log`.
struct Fake {
    _p: common::Prepared,
    root: PathBuf,
}

impl Fake {
    fn new() -> Fake {
        let p = Harness::prepare();
        let root = p.root.clone();
        Fake { _p: p, root }
    }

    /// The fake in `work/` with `args`, its environment cleared but `HOME`,
    /// `PATH`, its config dir, its env log, and `knobs`.
    fn command(&self, args: &[&str], knobs: &[(&str, &str)]) -> Command {
        let mut cmd = Command::new(self.root.join("claude"));
        cmd.args(args).current_dir(self.root.join("work")).env_clear().env("HOME", self.root.join("home")).env("PATH", "/usr/bin:/bin").env("CLAUDE_CONFIG_DIR", self.config()).env("FAKE_ENV_LOG", self.at("env.log"));
        for (k, v) in knobs {
            cmd.env(k, v);
        }
        cmd
    }

    /// [`Fake::command`] run with `stdin`, then EOF, within [`T`]: its exit
    /// code, its stdout lines and its stderr.
    fn run(&self, args: &[&str], knobs: &[(&str, &str)], stdin: &str) -> (Option<i32>, Vec<String>, String) {
        let o = common::bounded::run_within(self.command(args, knobs), Some(stdin.as_bytes()), T, "the fake claude");
        (o.status.code(), String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect(), String::from_utf8_lossy(&o.stderr).into_owned())
    }

    fn at(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn config(&self) -> PathBuf {
        self.root.join("home").join(".claude")
    }

    fn slug(&self) -> String {
        ai_env_cli::wire::slug::project_dir_name(&self.root.join("work")).expect("the work dir's slug")
    }

    /// Session `sid`'s transcript.
    fn transcript(&self, sid: &str) -> PathBuf {
        self.config().join("projects").join(self.slug()).join(format!("{sid}.jsonl"))
    }

    /// The env log's lines holding `part`.
    fn logged(&self, part: &str) -> Vec<String> {
        std::fs::read_to_string(self.at("env.log")).unwrap_or_default().lines().filter(|l| l.contains(part)).map(str::to_string).collect()
    }
}

/// One stdout frame, told for a turn's shape: `answer:<id>`, `init`,
/// `echo:<uuid>`, `tool_use:<name>`, `tool_result:<text>` (`error:<text>`
/// when it is one), `reply`, `<subtype>:<id>` for a request, `cancel:<id>`,
/// `result:<uuid>` (`error_result:<uuid>`).
fn shape(v: &Value) -> String {
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    match v["type"].as_str().unwrap_or_default() {
        "control_response" => format!("answer:{}", text(&v["response"]["request_id"])),
        "system" if is_init(v) => "init".to_string(),
        "user" if v["isReplay"] == true => format!("echo:{}", text(&v["uuid"])),
        "user" => {
            let block = &v["message"]["content"][0];
            format!("{}:{}", if block["is_error"] == true { "error" } else { "tool_result" }, text(&block["content"]))
        }
        "assistant" => match v["message"]["content"][0]["type"].as_str() {
            Some("tool_use") => format!("tool_use:{}", text(&v["message"]["content"][0]["name"])),
            _ => "reply".to_string(),
        },
        "control_request" => format!("{}:{}", text(&v["request"]["subtype"]), text(&v["request_id"])),
        "control_cancel_request" => format!("cancel:{}", text(&v["request_id"])),
        "result" if v["is_error"] == true => format!("error_result:{}", text(&v["user_message_uuid"])),
        "result" => format!("result:{}", text(&v["user_message_uuid"])),
        other => other.to_string(),
    }
}

fn shapes(lines: &[String]) -> Vec<String> {
    lines.iter().map(|l| shape(&serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))).collect()
}

/// FAKE_ASK: the asking turn's echo and its tool_use (the tool, its command,
/// its id), then the CLI's `can_use_tool` request `perm-<gen>-<turn>`, as the
/// pump reads one. The turn is held meanwhile: a user line is queued, a
/// control request answered. Allowed, the tool's result (FAKE_ASK_RESULT),
/// the reply, its effect (FAKE_EDIT) and the result, then the queued line's
/// turn, which asks nothing. Denied, or answered with an error (in
/// FAKE_ASK_TURN's turn), an error tool_result, no effect, the reply and the
/// result. An interrupt withdraws the request and ends the turn with an
/// error result; stdin's end while held ends the CLI (exit 0) with no result
/// and no queued turn. Every line is logged, every answer too
/// (FAKE_PERMISSION_LOG).
#[test]
fn the_fake_claude_asks_holds_and_logs_the_permission() {
    let f = Fake::new();
    let (perms, stdin_log) = (f.at("permission.log"), f.at("stdin.log"));
    let knobs = [
        ("FAKE_ASK", r#"Bash:ls -la "x""#),
        ("FAKE_ASK_RESULT", "two \"files\""),
        ("FAKE_EDIT", "note.txt:edited"),
        ("FAKE_PERMISSION_LOG", perms.to_str().unwrap()),
        ("FAKE_STDIN_LOG", stdin_log.to_str().unwrap()),
    ];
    let (u1, u2) = (common::uuid(0x1101), common::uuid(0x1102));
    let mode = r#"{"request_id":"m1","type":"control_request","request":{"subtype":"set_permission_mode","mode":"default"}}"#;
    let lines = [INIT.to_string(), Harness::user_line(&u1, "ask"), Harness::user_line(&u2, "queued"), mode.to_string(), permission_answer("perm-1-1", true)];
    let (code, out, err) = f.run(&[], &knobs, &format!("{}\n", lines.join("\n")));
    assert_eq!(code, Some(0), "{err}");
    let want = ["answer:i1", "init", &format!("echo:{u1}"), "tool_use:Bash", "can_use_tool:perm-1-1", "answer:m1", "tool_result:two \"files\"", "reply", &format!("result:{u1}"), &format!("echo:{u2}"), "reply", &format!("result:{u2}")];
    assert_eq!(shapes(&out), want, "{out:#?}");
    let ask = out.iter().find(|l| l.contains("can_use_tool")).unwrap();
    assert_eq!(classify_child(ask.as_bytes()), ChildFrame::ControlRequest { request_id: Some("perm-1-1".into()), subtype: Some("can_use_tool".into()) });
    let (asked, used): (Value, Value) = (serde_json::from_str(ask).unwrap(), serde_json::from_str(&out[3]).unwrap());
    assert!(is_permission_request(&asked), "{asked}");
    let r = &asked["request"];
    assert_eq!((r["tool_name"].as_str(), r["input"]["command"].as_str(), &r["permission_suggestions"]), (Some("Bash"), Some(r#"ls -la "x""#), &serde_json::json!([])), "{asked}");
    let block = &used["message"]["content"][0];
    assert_eq!((&r["tool_use_id"], &block["input"]), (&block["id"], &r["input"]), "the request names the tool_use's id and input");
    assert_eq!(read(&f.at("work").join("note.txt")), "edited\n", "allowed: the tool's effect");
    assert_eq!(read(&perms), "gen 1 turn 1 perm-1-1 allow\n");
    assert_eq!(read(&stdin_log).lines().count(), lines.len(), "every line logged, held or not");

    // Denied: an error result for the tool, none of its effects.
    let f = Fake::new();
    let perms = f.at("permission.log");
    let knobs = [("FAKE_ASK", "Bash"), ("FAKE_EDIT", "note.txt:edited"), ("FAKE_PERMISSION_LOG", perms.to_str().unwrap())];
    let (code, out, err) = f.run(&[], &knobs, &format!("{INIT}\n{}\n{}\n", Harness::user_line(&u1, "ask"), permission_answer("perm-1-1", false)));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u1}"), "tool_use:Bash", "can_use_tool:perm-1-1", "error:not allowed: deny", "reply", &format!("result:{u1}")]);
    assert_eq!(serde_json::from_str::<Value>(&out[4]).unwrap()["request"]["input"], serde_json::json!({}), "no command: no input");
    assert!(!f.at("work").join("note.txt").exists(), "denied: the tool never ran");
    assert_eq!(read(&perms), "gen 1 turn 1 perm-1-1 deny\n");

    // An error answer, in FAKE_ASK_TURN's turn: the turn before it asks nothing.
    let f = Fake::new();
    let perms = f.at("permission.log");
    let knobs = [("FAKE_ASK", "Read"), ("FAKE_ASK_TURN", "2"), ("FAKE_PERMISSION_LOG", perms.to_str().unwrap())];
    let error = r#"{"type":"control_response","response":{"subtype":"error","request_id":"perm-1-2","error":"no answer"}}"#;
    let (code, out, err) = f.run(&[], &knobs, &format!("{INIT}\n{}\n{}\n{error}\n", Harness::user_line(&u1, "first"), Harness::user_line(&u2, "ask")));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u1}"), "reply", &format!("result:{u1}"), &format!("echo:{u2}"), "tool_use:Read", "can_use_tool:perm-1-2", "error:not allowed: error", "reply", &format!("result:{u2}")]);
    assert_eq!(read(&perms), "gen 1 turn 2 perm-1-2 error\n");

    // An interrupt: the request withdrawn, the turn ended in error, no answer logged.
    let f = Fake::new();
    let perms = f.at("permission.log");
    let interrupt = r#"{"request_id":"x1","type":"control_request","request":{"subtype":"interrupt"}}"#;
    let (code, out, err) = f.run(&[], &[("FAKE_ASK", "Bash"), ("FAKE_PERMISSION_LOG", perms.to_str().unwrap())], &format!("{INIT}\n{}\n{interrupt}\n", Harness::user_line(&u1, "ask")));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u1}"), "tool_use:Bash", "can_use_tool:perm-1-1", "answer:x1", "cancel:perm-1-1", &format!("error_result:{u1}")]);
    assert_eq!(classify_child(out[6].as_bytes()), ChildFrame::ControlCancel { request_id: Some("perm-1-1".into()) });
    assert!(!perms.exists(), "no answer to log");

    // Stdin's end while held: the CLI ends, no result, the queued line never runs.
    let f = Fake::new();
    let (code, out, err) = f.run(&[], &[("FAKE_ASK", "Bash")], &format!("{INIT}\n{}\n{}\n", Harness::user_line(&u1, "ask"), Harness::user_line(&u2, "queued")));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u1}"), "tool_use:Bash", "can_use_tool:perm-1-1"]);
}

/// FAKE_SUBAGENTS and FAKE_SUBTREE_LOG: each turn writes its n subagent
/// transcripts in the session's subtree
/// (`<sid>/subagents/agent-<g>-<t>-<k>.jsonl`, two sidechain lines each,
/// naming the agent, the second chained to the first), and each turn's start
/// logs how many files that directory holds then: one planted before (what a
/// restore puts there), then the first turn's added.
#[test]
fn the_fake_claude_writes_subagents_and_logs_the_subtree() {
    let f = Fake::new();
    let sid = common::fake_fixed_sid();
    let sub = f.config().join("projects").join(f.slug()).join(&sid).join("subagents");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("agent-restored.jsonl"), "{\"isSidechain\":true}\n").unwrap();
    let (u1, u2) = (common::uuid(0x1201), common::uuid(0x1202));
    let stdin = format!("{INIT}\n{}\n{}\n", Harness::user_line(&u1, "one"), Harness::user_line(&u2, "two"));
    let (code, out, err) = f.run(&[], &[("FAKE_SUBAGENTS", "2"), ("FAKE_SUBTREE_LOG", "1")], &stdin);
    assert_eq!(code, Some(0), "{err}");
    assert!(shapes(&out).contains(&format!("result:{u2}")), "{out:?}");
    let written = ["agent-1-1-1.jsonl", "agent-1-1-2.jsonl", "agent-1-2-1.jsonl", "agent-1-2-2.jsonl"];
    assert_eq!(names_in(&sub), written.iter().map(|n| (*n).to_string()).chain(["agent-restored.jsonl".to_string()]).collect::<Vec<_>>());
    for name in written {
        let agent = name.trim_start_matches("agent-").trim_end_matches(".jsonl");
        let lines = json_lines(&read(&sub.join(name)));
        assert_eq!(lines.len(), 2, "{name}");
        for l in &lines {
            assert_eq!((&l["isSidechain"], l["agentId"].as_str(), l["sessionId"].as_str()), (&Value::Bool(true), Some(agent), Some(sid.as_str())), "{name}: {l}");
        }
        assert_eq!((lines[0]["type"].as_str(), lines[1]["type"].as_str(), &lines[1]["parentUuid"]), (Some("user"), Some("assistant"), &lines[0]["uuid"]), "{name}");
    }
    assert_eq!(f.logged("subagents="), ["gen 1 turn 1 subagents=1", "gen 1 turn 2 subagents=3"]);
}

/// FAKE_TURN_MS and FAKE_TURN_MARK: each turn runs a long tool: its echo,
/// an assistant tool_use (Bash), the mark (`gen <g> turn <t>`) as the wait
/// starts, the wait, the tool's result, the reply and the result. A TERM
/// ends the wait at once (FAKE_TERM_LOG's trap): the CLI exits 143 long
/// before the wait's end, its mark made, the turn's result never sent.
#[test]
fn the_fake_claude_runs_a_long_tool_and_marks_it() {
    let f = Fake::new();
    let mark = f.at("mark");
    let u = common::uuid(0x1301);
    let t0 = Instant::now();
    let (code, out, err) = f.run(&[], &[("FAKE_TURN_MS", "400"), ("FAKE_TURN_MARK", mark.to_str().unwrap())], &format!("{INIT}\n{}\n", Harness::user_line(&u, "long")));
    assert!(t0.elapsed() >= Duration::from_millis(400), "the tool's wait: {:?}", t0.elapsed());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u}"), "tool_use:Bash", "tool_result:ok", "reply", &format!("result:{u}")]);
    assert_eq!(read(&mark), "gen 1 turn 1\n");

    let g = Fake::new();
    let (mark, term) = (g.at("mark"), g.at("term.log"));
    let knobs = [("FAKE_TURN_MS", "60000"), ("FAKE_TURN_MARK", mark.to_str().unwrap()), ("FAKE_TERM_LOG", term.to_str().unwrap())];
    let mut cmd = g.command(&[], &knobs);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn the fake claude");
    let mut stdin = child.stdin.take().expect("its stdin");
    stdin.write_all(format!("{INIT}\n{}\n", Harness::user_line(&u, "long")).as_bytes()).expect("write its stdin");
    wait_for("the long tool's mark", T, || mark.exists());
    // Then its `sleep` exec'd: a TERM between the mark and that exec runs the fake's trap in the fork too (bash 3.2 as sh), two TERM lines.
    let pid = child.id().to_string();
    wait_for("the long tool's sleep", T, || Command::new("/usr/bin/pgrep").args(["-P", pid.as_str(), "-x", "sleep"]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()));
    let at = Instant::now();
    // SAFETY: kill(2) on the pid of our own not-yet-reaped child.
    assert_eq!(unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGTERM) }, 0, "kill(SIGTERM)");
    let o = common::bounded::finish_within(child, T, "the fake claude");
    drop(stdin);
    assert!(at.elapsed() < Duration::from_secs(10), "the TERM ended the wait: {:?}", at.elapsed());
    assert_eq!(o.status.code(), Some(143), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(read(&term), "TERM\n");
    let out: Vec<String> = String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect();
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u}"), "tool_use:Bash"], "no result");
}

/// `--resume-session-at` and `--session-id`, in either form. A cut at a
/// message of the `--resume` transcript is found (logged), and this
/// process's entries chain from it; at a message the transcript lacks, with
/// FAKE_RESUME_NEEDS_FILE, the CLI's cut miss before stdin is read (after
/// `initialize`'s answer with FAKE_RESUME_FAIL_AFTER_ACK), which the pump's
/// reader takes for a cut miss, not a resume miss; without it, only logged.
/// `--session-id` names the session (logged) and is refused, the CLI's
/// error lines on stderr: once that session's transcript exists, and beside
/// `--resume` (`-r`) or `--continue` (`-c`) unless `--fork-session` is given,
/// before a resume or a cut that would miss (nothing on stdout).
#[test]
fn the_fake_claude_cuts_at_a_message_or_misses() {
    let f = Fake::new();
    let sid = common::uuid(0x1401);
    let (earlier, leaf, gone) = (common::uuid(0x1402), common::uuid(0x1403), common::uuid(0x1404));
    let file = f.transcript(&sid);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let planted = format!(
        "{{\"parentUuid\":null,\"type\":\"user\",\"uuid\":\"{earlier}\",\"sessionId\":\"{sid}\",\"message\":{{\"role\":\"user\",\"content\":\"earlier\"}}}}\n{{\"parentUuid\":\"{earlier}\",\"type\":\"assistant\",\"uuid\":\"{leaf}\",\"sessionId\":\"{sid}\",\"message\":{{\"role\":\"assistant\",\"content\":[]}}}}\n"
    );
    std::fs::write(&file, &planted).unwrap();
    let resume = format!("--resume={sid}");
    let needs = [("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_WRITE_TRANSCRIPT", "1")];
    let u = common::uuid(0x1405);
    let (code, out, err) = f.run(&[&resume, &format!("--resume-session-at={leaf}")], &needs, &format!("{INIT}\n{}\n", Harness::user_line(&u, "after the cut")));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u}"), "reply", &format!("result:{u}")]);
    let entries = json_lines(&read(&file));
    let entry = entries.iter().find(|e| e["uuid"] == u.as_str()).unwrap_or_else(|| panic!("the turn's entry: {entries:?}"));
    assert_eq!(entry["parentUuid"].as_str(), Some(leaf.as_str()), "the turn chains from the cut");

    let marker = format!("No message found with message.uuid of: {gone}");
    let (code, out, err) = f.run(&[&resume, "--resume-session-at", &gone], &needs, &format!("{INIT}\n"));
    assert_eq!(code, Some(1), "{err}");
    assert!(err.lines().any(|l| l == marker), "{err}");
    assert_eq!(out.len(), 1, "its result alone, before stdin: {out:?}");
    let missed = classify_child(out[0].as_bytes());
    assert!(is_cut_miss(&missed) && !is_resume_miss(&missed), "{}", out[0]);
    let (code, out, err) = f.run(&[&resume, &format!("--resume-session-at={gone}")], &[("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_RESUME_FAIL_AFTER_ACK", "1")], &format!("{INIT}\n"));
    assert_eq!(code, Some(1), "{err}");
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(is_response_to(&serde_json::from_str(&out[0]).unwrap(), "i1") && is_cut_miss(&classify_child(out[1].as_bytes())), "after the answer: {out:?}");
    let (code, out, err) = f.run(&[&resume, "--resume-session-at", &gone], &[], &format!("{INIT}\n"));
    assert_eq!(code, Some(0), "without FAKE_RESUME_NEEDS_FILE no miss: {err}");
    assert_eq!(shapes(&out), ["answer:i1", "init"]);
    let at = |uuid: &str, found: &str| format!("gen 1 cut at={uuid} {found}");
    assert_eq!(f.logged(" cut at="), [at(&leaf, "found"), at(&gone, "missing"), at(&gone, "missing"), at(&gone, "missing")]);

    let fresh = common::uuid(0x1406);
    let (code, out, err) = f.run(&["--session-id", &fresh], &[("FAKE_WRITE_TRANSCRIPT", "1")], &format!("{INIT}\n{}\n", Harness::user_line(&u, "fresh")));
    assert_eq!(code, Some(0), "{err}");
    let init: Value = serde_json::from_str(&out[1]).unwrap();
    assert_eq!(init["session_id"].as_str(), Some(fresh.as_str()), "{init}");
    assert!(f.transcript(&fresh).is_file(), "its transcript under its id");
    let (code, out, err) = f.run(&[&format!("--session-id={fresh}")], &[], &format!("{INIT}\n"));
    assert_eq!((code, out.len()), (Some(1), 0), "{out:?}");
    assert!(err.lines().any(|l| l == format!("Error: Session ID {fresh} is already in use.")), "{err}");
    assert_eq!(f.logged("session-id="), [format!("gen 1 session-id={fresh}"), format!("gen 1 session-id={fresh}")]);

    let refusal = "Error: --session-id can only be used with --continue or --resume if --fork-session is also specified.";
    let forked = common::uuid(0x1407);
    for before in [&[resume.as_str()][..], &["-r", sid.as_str()], &["--continue"], &["-c"]] {
        let args: Vec<&str> = before.iter().copied().chain(["--session-id", forked.as_str()]).collect();
        let (code, out, err) = f.run(&args, &[], &format!("{INIT}\n"));
        assert_eq!((code, out.len()), (Some(1), 0), "{args:?}: {out:?}");
        assert!(err.lines().any(|l| l == refusal), "{args:?}: {err}");
    }
    let (code, out, err) = f.run(&[&resume, "--fork-session", &format!("--session-id={forked}")], &[], &format!("{INIT}\n"));
    assert_eq!(code, Some(0), "with --fork-session: {err}");
    let init: Value = serde_json::from_str(&out[1]).unwrap();
    assert_eq!(init["session_id"].as_str(), Some(forked.as_str()), "{init}");

    // The refusal comes first: a resume, or a cut, that would miss never answers.
    let missing = format!("--resume={}", common::uuid(0x1408));
    let session = format!("--session-id={forked}");
    for args in [vec![missing.as_str(), session.as_str()], vec![resume.as_str(), "--resume-session-at", gone.as_str(), session.as_str()]] {
        let (code, out, err) = f.run(&args, &[("FAKE_RESUME_NEEDS_FILE", "1")], &format!("{INIT}\n"));
        assert_eq!((code, out.len()), (Some(1), 0), "{args:?}: nothing on stdout: {out:?}");
        assert!(err.lines().any(|l| l == refusal) && !err.contains("No conversation found") && !err.contains("No message found"), "{args:?}: {err}");
    }
}

/// The entries the `transcript_mirror` frames of `out` carry, each as sent
/// (raw), one per line.
fn mirror_entries(out: &[String]) -> String {
    let mut text = String::new();
    for line in out.iter().filter(|l| l.contains(r#""type":"transcript_mirror""#)) {
        let frame: BTreeMap<String, Box<RawValue>> = serde_json::from_str(line).unwrap_or_else(|e| panic!("not a mirror frame ({e}): {line}"));
        let entries: Vec<Box<RawValue>> = serde_json::from_str(frame["entries"].get()).unwrap_or_else(|e| panic!("its entries ({e}): {line}"));
        text.extend(entries.iter().map(|e| format!("{}\n", e.get())));
    }
    text
}

/// The (uuid, parent) of each user and assistant entry of a transcript that
/// is no sidechain's, in file order (a null parent as "").
fn chain_of(path: &Path) -> Vec<(String, String)> {
    json_lines(&read(path))
        .iter()
        .filter(|e| matches!(e["type"].as_str(), Some("user" | "assistant")) && e["isSidechain"] != true)
        .map(|e| (e["uuid"].as_str().unwrap_or_default().to_string(), e["parentUuid"].as_str().unwrap_or_default().to_string()))
        .collect()
}

/// A resumed session's entries continue its chain, as the CLI's do (a
/// second resume then keeps the history): a plain `--resume` of [u0, a0]
/// (then a sidechain entry and a summary, which it skips) writes its turn's
/// user entry with a0 its parent; a transcript with no user or assistant
/// entry gives a null one. `--fork-session` beside `--resume X` is a session
/// of its own: the generation's fork id (no `--session-id`), its init
/// naming it, logged (`gen <n> forked from=<X>`); its transcript starts
/// with X's user and assistant lines (the fake's model of the CLI's copy;
/// with `--session-mirror` one mirror frame of them, so the frames still
/// carry the file but its api-request lines), then its own turn chained to
/// X's leaf; X's file is left as it was. A second process of generation 1
/// (no FAKE_SPAWN_COUNT, as another rig's) writing into X, which holds that
/// generation's reply already, gives its reply the next free uuid
/// (`…-a000-0001<gen>`), frame and entry alike, so the chain keeps a leaf.
#[test]
fn the_fake_claude_continues_a_resumed_chain_or_forks_it() {
    let f = Fake::new();
    let sid = common::uuid(0x1601);
    let (u0, a0, side) = (common::uuid(0x1602), common::uuid(0x1603), common::uuid(0x1604));
    let file = f.transcript(&sid);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let planted = format!(
        "{{\"parentUuid\":null,\"isSidechain\":false,\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"earlier\"}},\"uuid\":\"{u0}\",\"sessionId\":\"{sid}\"}}\n\
         {{\"parentUuid\":\"{u0}\",\"isSidechain\":false,\"type\":\"assistant\",\"message\":{{\"role\":\"assistant\",\"content\":[]}},\"uuid\":\"{a0}\",\"sessionId\":\"{sid}\"}}\n\
         {{\"parentUuid\":null,\"isSidechain\":true,\"type\":\"assistant\",\"message\":{{\"role\":\"assistant\",\"content\":[]}},\"uuid\":\"{side}\",\"sessionId\":\"{sid}\"}}\n\
         {{\"type\":\"summary\",\"summary\":\"earlier\",\"leafUuid\":\"{a0}\"}}\n"
    );
    std::fs::write(&file, &planted).unwrap();
    let count = f.at("spawn.count");
    let knobs = [("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_SPAWN_COUNT", count.to_str().unwrap())];
    let resume = format!("--resume={sid}");
    let u1 = common::uuid(0x1605);
    let (code, out, err) = f.run(&[&resume], &knobs, &format!("{INIT}\n{}\n", Harness::user_line(&u1, "after a plain resume")));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u1}"), "reply", &format!("result:{u1}")]);
    let a1 = common::fake_reply_uuid(1, 1);
    let x = [(u0.clone(), String::new()), (a0.clone(), u0.clone()), (u1.clone(), a0.clone()), (a1.clone(), u1.clone())];
    assert_eq!(chain_of(&file), x, "the resumed chain goes on from a0");

    let bare = common::uuid(0x1606);
    std::fs::write(f.transcript(&bare), "{\"type\":\"summary\",\"summary\":\"nothing to continue\"}\n").unwrap();
    let u2 = common::uuid(0x1607);
    let (code, _, err) = f.run(&[&format!("--resume={bare}")], &knobs, &format!("{INIT}\n{}\n", Harness::user_line(&u2, "nothing before")));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(chain_of(&f.transcript(&bare)), [(u2.clone(), String::new()), (common::fake_reply_uuid(1, 2), u2.clone())], "no entry to continue: null");

    let before = read(&file);
    let fork = common::fake_fork_sid(3);
    let shown = f.at("mac").join(".claude");
    let mut with = knobs.to_vec();
    with.push(("FAKE_CONFIG_DIR", shown.to_str().unwrap()));
    let u3 = common::uuid(0x1608);
    let (code, out, err) = f.run(&[&resume, "--fork-session", "--session-mirror"], &with, &format!("{INIT}\n{}\n", Harness::user_line(&u3, "in the fork")));
    assert_eq!(code, Some(0), "{err}");
    let init: Value = serde_json::from_str(&out[1]).unwrap();
    assert_eq!(init["session_id"].as_str(), Some(fork.as_str()), "{init}");
    assert!(out.iter().any(|l| is_result_for(&serde_json::from_str(l).unwrap(), &u3)), "{out:?}");
    assert_eq!(f.logged("forked from="), [format!("gen 3 forked from={sid}")]);
    assert_eq!(read(&file), before, "X's file is left as it was");
    let forked = f.transcript(&fork);
    let a3 = common::fake_reply_uuid(1, 3);
    let mut want = x.to_vec();
    want.extend([(u3.clone(), a1.clone()), (a3, u3.clone())]);
    assert_eq!(chain_of(&forked), want, "X's history, then the fork's turn chained to X's leaf");
    assert_eq!(mirror_entries(&out), String::from_utf8(common::mirrored(read(&forked).as_bytes())).unwrap(), "the frames carry the fork's file but its api-request lines");

    let u4 = common::uuid(0x1609);
    let (code, out, err) = f.run(&[&resume], &knobs[..2], &format!("{INIT}\n{}\n", Harness::user_line(&u4, "generation 1 again")));
    assert_eq!(code, Some(0), "{err}");
    let again = format!("{:08x}-0000-4000-a000-{:04x}{:08x}", 1, 1, 1);
    assert!(out.iter().any(|l| l.contains(r#""type":"assistant""#) && l.contains(&format!(r#""uuid":"{again}""#))), "the frame's uuid is the entry's: {out:?}");
    let mut want = x.to_vec();
    want.extend([(u4.clone(), a1.clone()), (again.clone(), u4.clone())]);
    assert_eq!(chain_of(&file), want, "one uuid per entry: the chain still has its leaf");
}

/// Every assistant frame carries `"parent_tool_use_id":null` and the uuid
/// its transcript entry gets, whether a transcript is written or not, so the
/// pump's reader takes each for a top-level message with that uuid: a plain
/// turn's reply (`a000`), and in a tool turn the tool_use (`b000`) and the
/// reply, its tool_result a user entry (`c000`) between them, the entries
/// chained in that order.
#[test]
fn the_fake_claudes_assistant_frames_carry_the_transcripts_uuid() {
    let (u1, u2) = (common::uuid(0x1501), common::uuid(0x1502));
    let stdin = format!("{INIT}\n{}\n{}\n{}\n", Harness::user_line(&u1, "plain"), Harness::user_line(&u2, "a tool"), permission_answer("perm-1-2", true));
    let knobs = [("FAKE_ASK", "Bash:true"), ("FAKE_ASK_TURN", "2")];
    let (reply1, tool2, result2, reply2) = (common::fake_reply_uuid(1, 1), common::fake_tool_use_uuid(2, 1), common::fake_tool_result_uuid(2, 1), common::fake_reply_uuid(2, 1));
    let want = vec![reply1.clone(), tool2.clone(), reply2.clone()];
    let assistants = |out: &[String]| -> Vec<String> {
        out.iter()
            .filter(|l| l.contains(r#""type":"assistant""#))
            .map(|l| {
                let v: Value = serde_json::from_str(l).unwrap();
                assert!(v.as_object().unwrap().get("parent_tool_use_id") == Some(&Value::Null), "{l}");
                match classify_child(l.as_bytes()) {
                    ChildFrame::Assistant { uuid: Some(uuid), top_level: true } => uuid.into_owned(),
                    other => panic!("not a top-level assistant frame with a uuid: {other:?}: {l}"),
                }
            })
            .collect()
    };
    let bare = Fake::new();
    let (code, out, err) = bare.run(&[], &knobs, &stdin);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(assistants(&out), want, "no transcript written");
    assert!(out.iter().any(|l| l.contains(&format!(r#""uuid":"{result2}""#)) && l.contains("tool_result")), "the tool_result's frame: {out:?}");

    let f = Fake::new();
    let mut with = knobs.to_vec();
    with.push(("FAKE_WRITE_TRANSCRIPT", "1"));
    let (code, out, err) = f.run(&[], &with, &stdin);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(assistants(&out), want, "the same uuids with a transcript");
    let entries = json_lines(&read(&f.transcript(&common::fake_fixed_sid())));
    let typed: Vec<(String, String, String)> = entries
        .iter()
        .filter(|e| matches!(e["type"].as_str(), Some("user" | "assistant")))
        .map(|e| [&e["type"], &e["uuid"], &e["parentUuid"]].map(|v| v.as_str().unwrap_or_default().to_string()).into())
        .collect();
    let t = |kind: &str, uuid: &str, parent: &str| (kind.to_string(), uuid.to_string(), parent.to_string());
    assert_eq!(typed, [t("user", &u1, ""), t("assistant", &reply1, &u1), t("user", &u2, &reply1), t("assistant", &tool2, &u2), t("user", &result2, &tool2), t("assistant", &reply2, &result2)], "{entries:#?}");
}

// ---- S11 (C3): the fake claude's compaction and part A's start-up knobs -----------------------

/// (type, uuid, parentUuid) of each entry of the transcript at `path` that
/// has a uuid, in file order (a null parent as "").
fn typed_entries(path: &Path) -> Vec<(String, String, String)> {
    json_lines(&read(path)).iter().filter(|e| e["uuid"].is_string()).map(|e| [&e["type"], &e["uuid"], &e["parentUuid"]].map(|v| v.as_str().unwrap_or_default().to_string()).into()).collect()
}

/// S11 (C-4, plans/s11-contracts-C.md §C.2.5): FAKE_COMPACT_BEFORE_TURN=2
/// with FAKE_WRITE_TRANSCRIPT=1: at the start of the process's turn 2, after
/// its echo and before its user entry, two entries as claude 2.1.302 writes
/// a compaction: the boundary (a chain root, `logicalParentUuid` the reply
/// turn 1 wrote; uuid kind 7000) and its summary (`isCompactSummary`,
/// chained to the boundary; kind 6000), with `--session-mirror` in one
/// mirror frame of their own (the frames carry the file but its
/// api-request lines) and nothing else on stdout; the turn's user entry then
/// chains to the summary, and the env log names it. Before a tool turn
/// (turn 1, nothing written yet: `logicalParentUuid` null) the user entry
/// and the tool_use follow the summary as the tool starts. Without
/// FAKE_WRITE_TRANSCRIPT=1 nothing compacts.
#[test]
fn the_fake_claude_compacts_before_its_turn() {
    let f = Fake::new();
    let shown = f.at("mac").join(".claude");
    let knobs = [("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_COMPACT_BEFORE_TURN", "2"), ("FAKE_CONFIG_DIR", shown.to_str().unwrap())];
    let (u1, u2) = (common::uuid(0x1701), common::uuid(0x1702));
    let stdin = format!("{INIT}\n{}\n{}\n", Harness::user_line(&u1, "before"), Harness::user_line(&u2, "after the compaction"));
    let (code, out, err) = f.run(&["--session-mirror"], &knobs, &stdin);
    assert_eq!(code, Some(0), "{err}");
    let mirror = "transcript_mirror";
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u1}"), "reply", mirror, &format!("result:{u1}"), &format!("echo:{u2}"), mirror, "reply", mirror, &format!("result:{u2}")], "{out:#?}");
    let sid = common::fake_fixed_sid();
    let file = f.transcript(&sid);
    let (boundary, summary) = (common::fake_compact_boundary_uuid(2, 1), common::fake_compact_summary_uuid(2, 1));
    let (a1, a2) = (common::fake_reply_uuid(1, 1), common::fake_reply_uuid(2, 1));
    let t = |kind: &str, uuid: &str, parent: &str| (kind.to_string(), uuid.to_string(), parent.to_string());
    assert_eq!(typed_entries(&file), [t("user", &u1, ""), t("assistant", &a1, &u1), t("system", &boundary, ""), t("user", &summary, &boundary), t("user", &u2, &summary), t("assistant", &a2, &u2)]);
    let lines: Vec<String> = read(&file).lines().map(str::to_string).collect();
    let at = lines.iter().position(|l| l.contains(&format!(r#""uuid":"{boundary}""#))).expect("the boundary's line");
    let (b, s): (Value, Value) = (serde_json::from_str(&lines[at]).unwrap(), serde_json::from_str(&lines[at + 1]).unwrap());
    let init: Value = serde_json::from_str(&out[1]).unwrap();
    assert_eq!(
        (b["type"].as_str(), b["subtype"].as_str(), b["content"].as_str(), &b["isMeta"], &b["isSidechain"], &b["parentUuid"], b["logicalParentUuid"].as_str(), &b["compactMetadata"]),
        (Some("system"), Some("compact_boundary"), Some("Conversation compacted"), &Value::Bool(false), &Value::Bool(false), &Value::Null, Some(a1.as_str()), &serde_json::json!({"trigger": "manual", "preTokens": 1000})),
        "{b}"
    );
    assert_eq!((b["sessionId"].as_str(), &b["cwd"]), (Some(sid.as_str()), &init["cwd"]), "{b}");
    let said = serde_json::json!({"role": "user", "content": "This session is being continued from a previous conversation."});
    assert_eq!((&s["isCompactSummary"], &s["isVisibleInTranscriptOnly"], &s["isSidechain"], &s["message"], s["sessionId"].as_str(), &s["cwd"]), (&Value::Bool(true), &Value::Bool(true), &Value::Bool(false), &said, Some(sid.as_str()), &init["cwd"]), "{s}");
    let frames: Vec<String> = out.iter().filter(|l| l.contains(r#""type":"transcript_mirror""#)).cloned().collect();
    assert_eq!(mirror_entries(&frames[1..2]), format!("{}\n{}\n", lines[at], lines[at + 1]), "one frame of the two, byte for byte");
    let named = serde_json::from_str::<Value>(&frames[1]).unwrap()["filePath"].as_str().map(PathBuf::from);
    assert_eq!(named, Some(shown.join("projects").join(f.slug()).join(format!("{sid}.jsonl"))));
    assert_eq!(mirror_entries(&out), String::from_utf8(common::mirrored(read(&file).as_bytes())).unwrap(), "the frames carry the file but its api-request lines");
    assert_eq!(f.logged("compacted"), [format!("gen 1 turn 2 compacted summary={summary}")]);

    // Before a tool turn, nothing written yet.
    let g = Fake::new();
    let u = common::uuid(0x1703);
    let (code, out, err) = g.run(&[], &[("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_COMPACT_BEFORE_TURN", "1"), ("FAKE_TURN_MS", "1")], &format!("{INIT}\n{}\n", Harness::user_line(&u, "a tool")));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u}"), "tool_use:Bash", "tool_result:ok", "reply", &format!("result:{u}")], "nothing of the compaction on stdout");
    let (boundary, summary) = (common::fake_compact_boundary_uuid(1, 1), common::fake_compact_summary_uuid(1, 1));
    let (tool, result, reply) = (common::fake_tool_use_uuid(1, 1), common::fake_tool_result_uuid(1, 1), common::fake_reply_uuid(1, 1));
    let file = g.transcript(&sid);
    assert_eq!(typed_entries(&file), [t("system", &boundary, ""), t("user", &summary, &boundary), t("user", &u, &summary), t("assistant", &tool, &u), t("user", &result, &tool), t("assistant", &reply, &result)]);
    assert_eq!(json_lines(&read(&file))[0]["logicalParentUuid"], Value::Null, "nothing written before it");
    assert_eq!(g.logged("compacted"), [format!("gen 1 turn 1 compacted summary={summary}")]);

    // Without FAKE_WRITE_TRANSCRIPT=1 the knob does nothing.
    let n = Fake::new();
    let (code, out, err) = n.run(&["--session-mirror"], &[("FAKE_COMPACT_BEFORE_TURN", "1")], &format!("{INIT}\n{}\n", Harness::user_line(&u, "no transcript")));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u}"), "reply", &format!("result:{u}")]);
    assert!(n.logged("compacted").is_empty() && !n.transcript(&sid).exists(), "{:?}", n.logged("compacted"));
}

/// S11 (part A, plans/s11-contracts-A.md §9.1): FAKE_REJECT_OPTION and
/// FAKE_DIE_BEFORE_INIT end the CLI once its argv is logged and its
/// generation counted, before its start-up log line and before stdin is
/// read, exit 1 with nothing on stdout: the first argument in argv order
/// that is a listed flag (`--x` or `--x=…`) gets the CLI's `error: unknown
/// option '<flag>'`, the other `fake claude: died before init`, each with its
/// env-log line; an argv with no listed flag runs as ever. `--version`
/// prints FAKE_VERSION_PINNED over FAKE_VERSION (default 2.1.305), and
/// FAKE_KNOBS_FILE is sourced in place of `<this path>.knobs`.
#[test]
fn the_fake_claude_rejects_an_option_or_dies_before_init_and_pins_its_version() {
    let f = Fake::new();
    let (count, argv) = (f.at("spawn.count").display().to_string(), f.at("argv.log").display().to_string());
    let rejecting = [("FAKE_SPAWN_COUNT", count.as_str()), ("ARGV_LOG", argv.as_str()), ("FAKE_REJECT_OPTION", "--x-new --resume-session-at")];
    let (code, out, err) = f.run(&["--verbose", "--resume-session-at=abc", "--x-new"], &rejecting, &format!("{INIT}\n"));
    assert_eq!((code, out.len()), (Some(1), 0), "{out:?}");
    assert_eq!(err.lines().collect::<Vec<_>>(), ["error: unknown option '--resume-session-at'"]);
    assert_eq!(read(&f.at("argv.log")), "--- gen 1\n--verbose\n--resume-session-at=abc\n--x-new\n", "the argv logged first");
    assert_eq!(f.logged("rejected="), ["gen 1 rejected=--resume-session-at"]);
    let u = common::uuid(0x1801);
    let (code, out, err) = f.run(&["--verbose"], &[("FAKE_SPAWN_COUNT", count.as_str()), ("FAKE_REJECT_OPTION", "--x-new")], &format!("{INIT}\n{}\n", Harness::user_line(&u, "runs")));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(shapes(&out), ["answer:i1", "init", &format!("echo:{u}"), "reply", &format!("result:{u}")]);
    let (code, out, err) = f.run(&[], &[("FAKE_SPAWN_COUNT", count.as_str()), ("FAKE_DIE_BEFORE_INIT", "1")], &format!("{INIT}\n"));
    assert_eq!((code, out.len()), (Some(1), 0), "{out:?}");
    assert_eq!(err.lines().collect::<Vec<_>>(), ["fake claude: died before init"]);
    assert_eq!(f.logged("died_before_init"), ["gen 3 died_before_init"]);
    assert_eq!(f.logged("CLAUDE_CONFIG_DIR=").len(), 1, "only generation 2 got past its start: {:?}", f.logged("gen "));

    let g = Fake::new();
    let version = |knobs: &[(&str, &str)]| {
        let (code, out, err) = g.run(&["--version"], knobs, "");
        assert_eq!(code, Some(0), "{err}");
        out.join("\n")
    };
    assert_eq!(version(&[]), "2.1.305 (Claude Code)");
    assert_eq!(version(&[("FAKE_VERSION", "2.1.399")]), "2.1.399 (Claude Code)");
    assert_eq!(version(&[("FAKE_VERSION", "2.1.399"), ("FAKE_VERSION_PINNED", "2.1.400")]), "2.1.400 (Claude Code)");
    // claude.knobs pins a version staged.knobs leaves unset: sourcing both
    // would print the pinned 2.1.401, so 2.1.402 proves "in place of".
    std::fs::write(g.at("claude.knobs"), "export FAKE_VERSION_PINNED='2.1.401'\n").unwrap();
    std::fs::write(g.at("staged.knobs"), "export FAKE_VERSION='2.1.402'\n").unwrap();
    assert_eq!(version(&[]), "2.1.401 (Claude Code)", "<this path>.knobs");
    let staged = g.at("staged.knobs").display().to_string();
    assert_eq!(version(&[("FAKE_KNOBS_FILE", staged.as_str())]), "2.1.402 (Claude Code)", "FAKE_KNOBS_FILE in its place, not as well");
}

/// S14 (T2, plans/s14-plan.md Phase P): the fake claude's Remote Control,
/// Track B's fixture, in claude 2.1.314's shapes. FAKE_RC=ok: an enable
/// (`remote_control` with `enabled` true) gets the session's two URLs, its
/// environment, the bridge's epoch and its session (the request's
/// `reattach_session_id` when it names one), then the `bridge_state` frame
/// `connected`; a disable gets `{}`. FAKE_RC=refused: an enable gets the
/// CLI's error and no frame, a disable still `{}`. FAKE_RC_PHONE=1 (with ok
/// only): after the frame, the phone's turn (its echo, the reply, the
/// result), then a `can_use_tool` request the CLI withdraws
/// (`control_cancel_request`): the phone answered first.
/// FAKE_ANALYTICS_DISABLED=1 adds `analytics_disabled` to the initialize
/// answer. Without the knobs a `remote_control` request gets the `{}` every
/// request gets, and the initialize answer is the pid alone. Cursor's own
/// initialize (tests/fixtures/away/initialize-cursor-hooks.json, one line:
/// its SDK hooks and its in-process MCP server) is answered as any.
#[test]
fn the_fake_claude_answers_remote_control_and_relays_a_phone_turn() {
    fn parse(l: &str) -> Value {
        serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}"))
    }
    // Each frame's shape, a system frame's by its subtype.
    fn kinds(out: &[String]) -> Vec<String> {
        out.iter().map(String::as_str).map(parse).map(|v| if v["type"] == "system" && !is_init(&v) { format!("system:{}", v["subtype"].as_str().unwrap_or_default()) } else { shape(&v) }).collect()
    }
    let fixture = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/away/initialize-cursor-hooks.json"));
    assert_eq!(fixture.lines().count(), 1, "one stream-json line");
    let cursor = parse(&fixture);
    let r = &cursor["request"];
    let pre = serde_json::json!([{"matcher": "Edit|Write|MultiEdit", "hookCallbackIds": ["hook_0"]}, {"matcher": "Edit|Write|Read", "hookCallbackIds": ["hook_1"]}]);
    let post = serde_json::json!([{"matcher": "Edit|Write|MultiEdit", "hookCallbackIds": ["hook_2"]}]);
    assert_eq!((r["subtype"].as_str(), &r["hooks"]["PreToolUse"], &r["hooks"]["PostToolUse"]), (Some("initialize"), &pre, &post), "{r}");
    let tool = &r["sdkMcpServerManifests"]["claude-vscode"]["toolsListResult"]["tools"][0];
    assert_eq!((&r["sdkMcpServers"], tool["name"].as_str()), (&serde_json::json!(["claude-vscode"]), Some("getDiagnostics")), "{r}");
    let cursor_answer = format!("answer:{}", cursor["request_id"].as_str().expect("its request_id"));

    let rc = |id: &str, body: &str| format!(r#"{{"request_id":"{id}","type":"control_request","request":{{"subtype":"remote_control",{body}}}}}"#);
    let (enable, disable) = (rc("rc1", r#""enabled":true,"name":"away""#), rc("rc2", r#""enabled":false"#));
    let empty = |id: &str| format!(r#"{{"type":"control_response","response":{{"subtype":"success","request_id":"{id}","response":{{}}}}}}"#);
    let connected = |id: &str, bridge: &str| format!(r#"{{"type":"control_response","response":{{"subtype":"success","request_id":"{id}","response":{{"session_url":"https://example.invalid/code/session_0199a1b2","connect_url":"https://example.invalid/code?environment=env_0199a1b2","environment_id":"env_0199a1b2","bridge_epoch":1,"bridge_session_id":"{bridge}"}}}}}}"#);
    let bridge_state = r#"{"type":"system","subtype":"bridge_state","state":"connected","bridge_epoch":1}"#;

    // No knob: today's answers, the {} every request gets and the pid alone.
    let f = Fake::new();
    let (code, out, err) = f.run(&[], &[], &format!("{INIT}\n{enable}\n{disable}\n"));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(kinds(&out), ["answer:i1", "init", "answer:rc1", "answer:rc2"], "{out:#?}");
    assert_eq!((out[2].as_str(), out[3].as_str()), (empty("rc1").as_str(), empty("rc2").as_str()));
    let answered = parse(&out[0])["response"]["response"].clone();
    assert!(answered.as_object().is_some_and(|o| o.len() == 1 && o["pid"].is_u64()), "the pid alone: {answered}");

    // ok, under Cursor's initialize, analytics off: each enable connected (the default bridge session, then the
    // reattached one), a disable {}.
    let f = Fake::new();
    let reattach = "cse_0199a1b2-0000-7000-8000-0000000000a2";
    let again = rc("rc3", &format!(r#""enabled":true,"reattach_session_id":"{reattach}""#));
    let (code, out, err) = f.run(&[], &[("FAKE_RC", "ok"), ("FAKE_ANALYTICS_DISABLED", "1")], &format!("{fixture}{enable}\n{again}\n{disable}\n"));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(kinds(&out), [cursor_answer.as_str(), "init", "answer:rc1", "system:bridge_state", "answer:rc3", "system:bridge_state", "answer:rc2"], "{out:#?}");
    let init = parse(&out[0]);
    assert_eq!((init["response"]["subtype"].as_str(), &init["response"]["response"]["analytics_disabled"]), (Some("success"), &Value::Bool(true)), "{init}");
    assert!(init["response"]["response"]["pid"].is_u64(), "{init}");
    assert_eq!(out[2], connected("rc1", "cse_0199a1b2-0000-7000-8000-000000000001"));
    assert_eq!((out[3].as_str(), out[5].as_str()), (bridge_state, bridge_state));
    assert_eq!(out[4], connected("rc3", reattach), "the reattached bridge session");
    assert_eq!(out[6], empty("rc2"));

    // refused: the CLI's error, no frame and no phone; a disable still {}.
    let f = Fake::new();
    let (code, out, err) = f.run(&[], &[("FAKE_RC", "refused"), ("FAKE_RC_PHONE", "1")], &format!("{INIT}\n{enable}\n{disable}\n"));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(kinds(&out), ["answer:i1", "init", "answer:rc1", "answer:rc2"], "{out:#?}");
    assert_eq!(out[2], r#"{"type":"control_response","response":{"subtype":"error","request_id":"rc1","error":"Remote Control initialization failed"}}"#);
    assert_eq!(out[3], empty("rc2"));

    // ok with the phone: after the frame, the phone's turn, then its prompt asked of the host and withdrawn.
    let f = Fake::new();
    let (code, out, err) = f.run(&[], &[("FAKE_RC", "ok"), ("FAKE_RC_PHONE", "1")], &format!("{INIT}\n{enable}\n"));
    assert_eq!(code, Some(0), "{err}");
    let phone = "00000001-0000-4000-1000-000000000001";
    assert_eq!(kinds(&out), ["answer:i1", "init", "answer:rc1", "system:bridge_state", &format!("echo:{phone}"), "reply", &format!("result:{phone}"), "can_use_tool:phone-perm-1-1", "cancel:phone-perm-1-1"], "{out:#?}");
    let (echo, reply) = (parse(&out[4]), parse(&out[5]));
    assert_eq!((echo["message"]["content"].as_str(), reply["message"]["content"][0]["text"].as_str()), (Some("phone turn"), Some("phone reply")), "{echo} {reply}");
    let asked = parse(&out[7]);
    assert!(is_permission_request(&asked), "{asked}");
    assert_eq!((asked["request"]["tool_name"].as_str(), &asked["request"]["input"]), (Some("Bash"), &serde_json::json!({"command": "ls"})), "{asked}");
    assert_eq!(classify_child(out[7].as_bytes()), ChildFrame::ControlRequest { request_id: Some("phone-perm-1-1".into()), subtype: Some("can_use_tool".into()) });
    assert_eq!(classify_child(out[8].as_bytes()), ChildFrame::ControlCancel { request_id: Some("phone-perm-1-1".into()) });
}
