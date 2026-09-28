//! T2.3 — the pump's host-state recorder/replayer, registry and resume seeder,
//! end to end: `ai-env-claude` pipes a session to `tests/fakes/claude-v2.sh`
//! (`AI_ENV_BRIDGE_MODE=local-child|local-scratch`) and these tests read what
//! reached the host's stdout, what each child generation read on its stdin
//! (the fake's log), the census, `audit.jsonl` and `state/sessions/`.
//! Compiled only with `bridge`; nothing here touches the developer's
//! `~/.config/ai-env` or runs the real `claude`.
mod common;

use ai_env_cli::bridge::registry::{self, SCRATCH_OWNER_FILE};
use common::{
    env_log_field, fake_clear_sid, fake_fixed_sid, is_echo_of, is_init, is_response_to, is_result_for, note_has, pid_alive, resume_miss_frame, uuid, Harness, SESSION_ARGV,
};
use serde_json::value::RawValue;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Upper bound for a frame the fake answers at once. Generous: these tests
/// assert what happens, not how fast (`race.rs` owns the timing contract), and
/// a loaded Mac can start a child process seconds late.
const T: Duration = Duration::from_secs(30);
/// Upper bound for the wrapper's exit (the contract, 1.5 s after EOF, is `race.rs`'s).
const EXIT: Duration = Duration::from_secs(30);

/// A transcript of three lines for session `sid` (the resume source).
fn transcript_lines(sid: &str) -> Vec<String> {
    vec![
        format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, uuid(0x1001)),
        format!(r#"{{"type":"assistant","uuid":"{}","parentUuid":"{}","sessionId":"{sid}","message":{{"content":[{{"type":"text","text":"reply \"quoted\" 1e21"}}]}}}}"#, uuid(0x1002), uuid(0x1001)),
        format!(r#"{{"type":"summary","summary":"a planted session","leafUuid":"{}"}}"#, uuid(0x1002)),
    ]
}

/// Plant the resume source: `<uuid>.jsonl` (3 lines) and `<uuid>/subagents/agent-a1.jsonl`.
fn plant_source(p: &common::Prepared, sid: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let lines = transcript_lines(sid);
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let main = p.plant_transcript(sid, &refs);
    let sub = p.plant_project_file(&format!("{sid}/subagents/agent-a1.jsonl"), "{\"type\":\"user\",\"isSidechain\":true,\"message\":{\"role\":\"user\",\"content\":\"sub\"}}\n");
    (main, sub)
}

/// The top-level members of a JSON object line, as raw slices.
fn members(line: &str) -> BTreeMap<String, Box<RawValue>> {
    serde_json::from_str(line).unwrap_or_else(|e| panic!("not a JSON object line ({e}): {line}"))
}

/// `request_id` and the raw `request` object of a control_request line.
fn request_parts(line: &str) -> (String, String) {
    let m = members(line);
    let id: String = serde_json::from_str(m.get("request_id").unwrap_or_else(|| panic!("no request_id: {line}")).get()).expect("string id");
    let request = m.get("request").unwrap_or_else(|| panic!("no request: {line}")).get().to_string();
    (id, request)
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

fn toml_str<'a>(row: &'a toml::Value, key: &str) -> &'a str {
    row.get(key).and_then(toml::Value::as_str).unwrap_or_else(|| panic!("registry row has no string {key}: {row:#?}"))
}

fn toml_int(row: &toml::Value, key: &str) -> i64 {
    row.get(key).and_then(toml::Value::as_integer).unwrap_or_else(|| panic!("registry row has no integer {key}: {row:#?}"))
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())).permissions().mode() & 0o777
}

/// Every audit row whose event starts with `resume_seed_`.
fn seed_rows(h: &Harness) -> Vec<Value> {
    h.audit_rows().into_iter().filter(|r| r["event"].as_str().is_some_and(|e| e.starts_with("resume_seed_"))).collect()
}

/// Generation 1's scratch config dir, from the fake's env log (`CLAUDE_CONFIG_DIR=…`):
/// (its path, its name under `state/scratch`).
fn gen1_scratch(h: &Harness) -> (PathBuf, String) {
    let env = h.env_log();
    let line = env.iter().find(|l| l.starts_with("gen 1 ")).unwrap_or_else(|| panic!("the fake logged no environment: {env:#?}"));
    let dir = PathBuf::from(env_log_field(line, "CLAUDE_CONFIG_DIR").unwrap_or_else(|| panic!("{line}")));
    let root = h.bridge().join("state").join("scratch");
    let name = dir.strip_prefix(&root).unwrap_or_else(|_| panic!("the child's CLAUDE_CONFIG_DIR is not under {}: {line}", root.display()));
    let name = name.to_str().expect("utf-8 name").to_string();
    assert!(!name.contains('/'), "one level below state/scratch: {line}");
    (dir, name)
}

/// `mkdir -p` with 0700 for every level created.
fn mkdir_0700(dir: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
}

#[test]
fn t2_3_resume_miss_respawns_with_replay() {
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0001);
    let (planted, planted_sub) = plant_source(&p, &sid);
    let slug = p.slug();
    let marker = p.root.join("resume.marker");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn("local-scratch", &[&resume], &[("FAKE_RESUME_FAIL_ONCE", path_str(&marker))]);

    let init_id = h.send_initialize();
    let perm_id = h.send_control("set_permission_mode", r#"{"mode":"acceptEdits"}"#);
    let flags_id = h.send_control("apply_flag_settings", r#"{"settings":{"model":"claude-x"}}"#);
    let u = h.send_user("resume me");
    h.expect_out(|v| is_result_for(v, &u), T);
    h.expect_out(|v| is_response_to(v, &init_id), T);
    h.expect_out(|v| is_response_to(v, &perm_id), T);
    h.expect_out(|v| is_response_to(v, &flags_id), T);
    h.close_stdin();
    let (status, took) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "exit after EOF took {took:?}\n{transcript}");

    // What the host saw.
    let host_ids = [init_id.as_str(), perm_id.as_str(), flags_id.as_str()];
    for id in host_ids {
        let n = h.out_matching(|v| is_response_to(v, id)).len();
        assert_eq!(n, 1, "exactly one control_response for {id}\n{transcript}");
    }
    for r in h.out_matching(|v| v["type"] == "control_response") {
        let id = r["response"]["request_id"].as_str().unwrap_or_default().to_string();
        assert!(host_ids.contains(&id.as_str()), "a control_response for an id the host never sent (a fresh replay id leaked): {r}\n{transcript}");
        assert_eq!(r["response"]["subtype"], "success", "{r}");
    }
    assert_eq!(h.out_matching(is_init).len(), 1, "exactly one system/init\n{transcript}");
    let errors = h.out_matching(|v| v["type"] == "result" && v["is_error"] == true);
    assert!(errors.is_empty(), "the held resume-miss result reached the host: {errors:?}\n{transcript}");
    assert!(!h.out_lines().iter().any(|l| l.contains("No conversation found")), "{transcript}");
    assert_eq!(h.out_matching(|v| is_echo_of(v, &u)).len(), 1, "exactly one isReplay echo (gen 1 never echoed)\n{transcript}");
    assert_eq!(h.out_matching(|v| is_result_for(v, &u)).len(), 1, "exactly one result\n{transcript}");

    // What each generation read.
    assert_eq!(h.spawn_count(), 2, "{transcript}");
    let sent = h.sent.clone();
    let gen1 = h.stdin_of(1);
    assert!(gen1.is_empty() || gen1 == [sent[0].clone()], "gen 1 fails before (or right after) reading the initialize: {gen1:#?}");
    let gen2 = h.stdin_of(2);
    assert_eq!(gen2.len(), 4, "gen 2 reads initialize, the two state requests, the user line: {gen2:#?}");
    let mut fresh: Vec<String> = Vec::new();
    for (i, (sub, host_line)) in [("initialize", &sent[0]), ("set_permission_mode", &sent[1]), ("apply_flag_settings", &sent[2])].into_iter().enumerate() {
        let (id, request) = request_parts(&gen2[i]);
        let (host_id, host_request) = request_parts(host_line);
        assert_ne!(id, host_id, "gen 2's {sub} must carry a FRESH request id: {}", gen2[i]);
        assert_eq!(request, host_request, "gen 2's {sub} request object must be the host's, byte for byte");
        let v: Value = serde_json::from_str(&gen2[i]).unwrap();
        assert_eq!((v["type"].as_str(), v["request"]["subtype"].as_str()), (Some("control_request"), Some(sub)), "{}", gen2[i]);
        fresh.push(id);
    }
    fresh.sort();
    fresh.dedup();
    assert_eq!(fresh.len(), 3, "the fresh ids are distinct: {fresh:?}");
    assert!(fresh.iter().all(|f| !host_ids.contains(&f.as_str())));
    assert_eq!(gen2[3], sent[3], "the outstanding user line is re-sent verbatim");
    assert!(h.stdin_log().iter().all(|(g, _)| *g <= 2), "no third generation");

    // Both generations got the host's argv, --resume included, plus one --session-mirror.
    let mut want: Vec<String> = SESSION_ARGV.iter().map(|s| (*s).to_string()).collect();
    want.push(resume.clone());
    want.push("--session-mirror".to_string());
    let argv = h.argv_log();
    assert_eq!(argv.len(), 2, "{argv:#?}");
    for (g, a) in argv.iter().enumerate() {
        assert_eq!(a, &want, "generation {} argv", g + 1);
    }

    // The seed retry was audited and the scratch copy is exact.
    let retries = h.audit_events("resume_seed_retry");
    assert_eq!(retries.len(), 1, "{:#?}", h.audit_rows());
    let d = &retries[0]["detail"];
    assert_eq!(d["session_id"], sid.as_str(), "{d}");
    assert_eq!(d["source"], path_str(&h.prepared.mac_projects().join(&slug)), "{d}");
    assert_eq!(d["files"], "2", "the transcript + one subagent file: {d}");
    let total = std::fs::metadata(&planted).unwrap().len() + std::fs::metadata(&planted_sub).unwrap().len();
    assert_eq!(d["bytes"], total.to_string().as_str(), "{d}");
    assert!(h.audit_events("resume_seed_miss").is_empty());
    let scratch = h.scratch_dir(&sid).join("projects").join(&slug);
    assert_eq!(std::fs::read(scratch.join(format!("{sid}.jsonl"))).expect("seeded transcript"), std::fs::read(&planted).unwrap(), "byte-equal seed");
    assert_eq!(
        std::fs::read(scratch.join(&sid).join("subagents").join("agent-a1.jsonl")).expect("seeded subagent transcript"),
        std::fs::read(&planted_sub).unwrap()
    );

    // The registry row: closed, one respawn, the state summary, no request body.
    let files = h.registry_files();
    assert_eq!(files.len(), 1, "{files:#?}");
    assert_eq!(files[0].0, format!("{sid}.toml"));
    let text = &files[0].1;
    for body in ["jsonSchema", "hooks", "\"settings\"", "{\"", "resume me"] {
        assert!(!text.contains(body), "the registry row holds request/message bytes ({body}):\n{text}");
    }
    let row = &h.registry_rows()[0];
    assert_eq!(toml_int(row, "respawns"), 1, "{text}");
    assert_eq!(toml_str(row, "status"), "closed", "{text}");
    assert_eq!(toml_int(row, "exit"), 0, "{text}");
    assert_eq!(toml_str(row, "mode"), "local-scratch", "{text}");
    let hs = row.get("host_state").unwrap_or_else(|| panic!("no host_state:\n{text}"));
    assert_eq!(toml_str(hs, "model"), "claude-x", "{text}");
    assert_eq!(toml_str(hs, "permission_mode"), "acceptEdits", "{text}");

    // The census end row counts the respawn.
    let end = h.end_row();
    let note = end["note"].as_str().unwrap_or_default();
    assert!(note_has(note, "respawns:1"), "{note}");
    assert_eq!(end["exit"], 0, "{end}");
}

#[test]
fn replay_response_swallowed_when_original_answered() {
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0002);
    plant_source(&p, &sid);
    let marker = p.root.join("resume.marker");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn("local-scratch", &[&resume], &[("FAKE_RESUME_FAIL_ONCE", path_str(&marker)), ("FAKE_RESUME_FAIL_AFTER_ACK", "1")]);
    let init_id = h.send_initialize();
    let u = h.send_user("after the ack");
    h.expect_out(|v| is_result_for(v, &u), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    assert_eq!(h.spawn_count(), 2, "{transcript}");

    let responses = h.out_matching(|v| v["type"] == "control_response");
    assert_eq!(responses.len(), 1, "only generation 1's answer reaches the host: {responses:#?}\n{transcript}");
    assert!(is_response_to(&responses[0], &init_id), "{}", responses[0]);
    // Generation 2 was asked under a fresh id (and the fake answers every request).
    let gen2 = h.stdin_of(2);
    let (fresh, _) = request_parts(gen2.first().unwrap_or_else(|| panic!("gen 2 read nothing\n{transcript}")));
    assert_ne!(fresh, init_id);
    assert!(!h.out_lines().iter().any(|l| l.contains(&fresh)), "gen 2's answer to {fresh} reached the host\n{transcript}");
    assert_eq!(h.out_matching(is_init).len(), 1, "{transcript}");
    assert!(h.out_matching(|v| v["type"] == "result" && v["is_error"] == true).is_empty(), "{transcript}");
    assert_eq!(h.out_matching(|v| is_echo_of(v, &u)).len(), 1, "{transcript}");
    assert_eq!(h.audit_events("resume_seed_retry").len(), 1, "{:#?}", h.audit_rows());
}

/// D16: a respawn re-sends EVERY un-result'ed user line, in send order, after
/// the replayed initialize and state requests (a queued follow-up is never lost).
#[test]
fn every_outstanding_user_line_is_replayed_in_send_order() {
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0008);
    plant_source(&p, &sid);
    let marker = p.root.join("resume.marker");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn("local-scratch", &[&resume], &[("FAKE_RESUME_FAIL_ONCE", path_str(&marker))]);
    // All written before generation 1 dies (it fails before reading its stdin).
    let init_id = h.send_initialize();
    let perm_id = h.send_control("set_permission_mode", r#"{"mode":"plan"}"#);
    let u1 = h.send_user("first");
    let u2 = h.send_user("second, queued behind the first");
    h.expect_out(|v| is_result_for(v, &u1), T);
    h.expect_out(|v| is_result_for(v, &u2), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    assert_eq!(h.spawn_count(), 2, "{transcript}");
    assert_eq!(h.audit_events("resume_seed_retry").len(), 1, "{:#?}", h.audit_rows());

    let sent = h.sent.clone();
    let gen1 = h.stdin_of(1);
    assert!(sent.starts_with(&gen1), "gen 1 read at most a prefix of the host's lines: {gen1:#?}");
    let gen2 = h.stdin_of(2);
    assert_eq!(gen2.len(), 4, "gen 2 reads initialize, the state request, both user lines: {gen2:#?}\n{transcript}");
    for (i, (sub, host_line)) in [("initialize", &sent[0]), ("set_permission_mode", &sent[1])].into_iter().enumerate() {
        let (id, request) = request_parts(&gen2[i]);
        let (host_id, host_request) = request_parts(host_line);
        assert_ne!(id, host_id, "gen 2's {sub} carries a fresh request id: {}", gen2[i]);
        assert_eq!(request, host_request, "gen 2's {sub} request object is the host's, byte for byte");
    }
    assert_eq!(gen2[2], sent[2], "user line 1 re-sent verbatim, first");
    assert_eq!(gen2[3], sent[3], "user line 2 re-sent verbatim, second");

    for u in [&u1, &u2] {
        assert_eq!(h.out_matching(|v| is_result_for(v, u)).len(), 1, "one result for {u}\n{transcript}");
        assert_eq!(h.out_matching(|v| is_echo_of(v, u)).len(), 1, "exactly one echo for {u}\n{transcript}");
    }
    for id in [&init_id, &perm_id] {
        assert_eq!(h.out_matching(|v| is_response_to(v, id)).len(), 1, "one control_response for {id}\n{transcript}");
    }
    assert_eq!(h.out_matching(is_init).len(), 1, "{transcript}");
    assert!(h.out_matching(|v| v["type"] == "result" && v["is_error"] == true).is_empty(), "{transcript}");
}

/// The child reports the resume miss AFTER its init reached the host: the
/// result is forwarded at once (nothing is held once an init was forwarded)
/// and the child's exit is final.
#[test]
fn exit_after_init_is_not_retried() {
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0003);
    // A seed source exists: a (wrong) retry would find something to seed from.
    plant_source(&p, &sid);
    let resume = format!("--resume={sid}");
    let mut h = p.spawn("local-scratch", &[&resume], &[("FAKE_MISS_AFTER_INIT", "1")]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(1), "{transcript}");
    let out = h.out_lines();
    let frame = resume_miss_frame(&sid);
    let at_frame = out.iter().position(|l| *l == frame).unwrap_or_else(|| panic!("the miss result was not forwarded (held after an init?)\n{transcript}"));
    assert_eq!(out.iter().filter(|l| **l == frame).count(), 1, "{transcript}");
    let at_init = out.iter().position(|l| serde_json::from_str::<Value>(l).is_ok_and(|v| is_init(&v))).unwrap_or_else(|| panic!("no init\n{transcript}"));
    assert!(at_init < at_frame, "the init reached the host first\n{transcript}");
    assert_eq!(h.out_matching(is_init).len(), 1, "{transcript}");
    let line = format!("No conversation found with session ID: {sid}");
    assert!(h.err_text().lines().any(|l| l == line), "stderr carries the child's line\n{transcript}");
    assert_eq!(h.spawn_count(), 1, "an exit after init is never retried\n{transcript}");
    assert_eq!(h.argv_log().len(), 1);
    assert!(seed_rows(&h).is_empty(), "no resume_seed_* row: {:#?}", h.audit_rows());
    let note = h.end_note();
    assert!(note_has(&note, "end:child_exit"), "{note}");
    assert!(note_has(&note, "respawns:0"), "{note}");
}

#[test]
fn resume_miss_without_source_propagates() {
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0004);
    let marker = p.root.join("resume.marker");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn("local-scratch", &[&resume], &[("FAKE_RESUME_FAIL_ONCE", path_str(&marker))]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(1), "{transcript}");
    let frame = resume_miss_frame(&sid);
    assert_eq!(h.out_lines().iter().filter(|l| **l == frame).count(), 1, "the held error result is forwarded verbatim\n{transcript}");
    let misses = h.audit_events("resume_seed_miss");
    assert_eq!(misses.len(), 1, "{:#?}", h.audit_rows());
    assert_eq!(misses[0]["detail"]["session_id"], sid.as_str(), "{}", misses[0]);
    assert_eq!(misses[0]["detail"]["reason"], "no local transcript", "{}", misses[0]);
    assert!(h.audit_events("resume_seed_retry").is_empty());
    assert_eq!(h.spawn_count(), 1, "{transcript}");
    let line = format!("No conversation found with session ID: {sid}");
    assert!(h.err_text().lines().any(|l| l == line), "{transcript}");
    let note = h.end_note();
    assert!(note_has(&note, "respawns:0"), "a retry that found nothing to seed from is no respawn: {note}");
}

/// A SIGTERM that lands while generation 1 drains after its exit (its stderr
/// is still held open by a background sleep, so the pump sits in its 200 ms
/// drain window) cancels the seed retry: the held miss is forwarded and the
/// child's code is the wrapper's.
#[test]
fn sigterm_while_gen1_drains_cancels_the_retry() {
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0009);
    plant_source(&p, &sid);
    let marker = p.root.join("resume.marker");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn("local-scratch", &[&resume], &[("FAKE_RESUME_FAIL_ONCE", path_str(&marker)), ("FAKE_HOLD_STDERR_MS", "3000")]);
    h.send_initialize();
    let line = format!("No conversation found with session ID: {sid}");
    h.wait_until("generation 1 reports the miss on stderr", T, |h| h.seen_err.contains(&line));
    // Then wait for the pump to reap it (the drain window opens at the exit), and SIGTERM at once.
    let pid = h.fake_pid(1).unwrap_or_else(|| panic!("the fake logged no pid: {:?}", h.env_log()));
    let deadline = Instant::now() + Duration::from_millis(150);
    while pid_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_micros(200));
    }
    let reaped = !pid_alive(pid);
    h.sigterm();
    let (status, took) = h.wait(EXIT);
    let transcript = h.transcript();
    eprintln!("sigterm_while_gen1_drains_cancels_the_retry: gen 1 reaped before the SIGTERM: {reaped}; SIGTERM -> exit {} ms", took.as_millis());
    assert_eq!(status.code(), Some(1), "the child's own code\n{transcript}");
    assert!(took < Duration::from_millis(1000), "SIGTERM -> exit took {took:?}\n{transcript}");
    assert_eq!(h.spawn_count(), 1, "no respawn after the SIGTERM\n{transcript}");
    let frame = resume_miss_frame(&sid);
    assert_eq!(h.out_lines().iter().filter(|l| **l == frame).count(), 1, "the held miss result is forwarded\n{transcript}");
    assert!(h.audit_events("resume_seed_retry").is_empty(), "{:#?}", h.audit_rows());
    assert!(note_has(&h.end_note(), "respawns:0"), "{}", h.end_note());
}

#[test]
fn resume_miss_in_local_child_propagates_verbatim() {
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0005);
    plant_source(&p, &sid);
    let marker = p.root.join("resume.marker");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn("local-child", &[&resume], &[("FAKE_RESUME_FAIL_ONCE", path_str(&marker))]);
    h.send_initialize();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(1), "{transcript}");
    let frame = resume_miss_frame(&sid);
    assert_eq!(h.out_lines(), vec![frame], "the frame is the only stdout line, byte for byte\n{transcript}");
    let line = format!("No conversation found with session ID: {sid}");
    assert!(h.err_text().lines().any(|l| l == line), "{transcript}");
    assert_eq!(h.spawn_count(), 1, "local-child never retries\n{transcript}");
    assert!(h.audit_rows().is_empty(), "{:#?}", h.audit_rows());
    assert!(!h.bridge().join("state").join("scratch").exists(), "local-child has no scratch dir");
}

#[test]
fn stdin_lines_before_spawn_are_buffered_in_order() {
    let mut h = Harness::spawn("local-child", &[], &[]);
    // Written before anything was read back: the wrapper may not even have spawned the child yet.
    h.send_initialize();
    let u1 = h.send_user("one");
    let u2 = h.send_user("two");
    h.send(r#"{"type":"keep_alive"}"#);
    h.expect_out(|v| is_result_for(v, &u1), T);
    h.expect_out(|v| is_result_for(v, &u2), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert_eq!(h.stdin_of(1), h.sent, "the child read every host line, in order, verbatim");
    assert_eq!(h.spawn_count(), 1);
}

#[test]
fn keep_alive_and_non_json_pass_verbatim() {
    let p = Harness::prepare();
    let lines = [
        r#"{"type":"keep_alive"}"#.to_string(),
        "plain text".to_string(),
        "{\"type\":\"stream_event\",\"event\":{\"type\":\"message_start\"}}\r".to_string(),
        r#"{"type":"command_lifecycle","state":"started","command_uuid":"c"}"#.to_string(),
    ];
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    let file = p.write_file("stdout.ndjson", &text);
    let mut h = p.spawn("local-child", &[], &[("FAKE_STDOUT_FILE", path_str(&file))]);
    h.send_initialize();
    h.expect_out(|v| v["type"] == "command_lifecycle", T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    let out = h.out_lines();
    let at = out.iter().position(|l| serde_json::from_str::<Value>(l).is_ok_and(|v| is_init(&v))).unwrap_or_else(|| panic!("no init\n{}", h.transcript()));
    assert!(out.len() >= at + 5, "{out:#?}");
    assert_eq!(&out[at + 1..at + 5], &lines[..], "forwarded byte for byte, \\r included, right after the init");
}

#[test]
fn oauth_token_refresh_is_answered_locally() {
    let mut h = Harness::spawn("local-child", &[], &[("FAKE_OAUTH_REFRESH", "1")]);
    h.send_initialize();
    h.expect_out(is_init, T);
    let u = h.send_user("after the refresh");
    h.expect_out(|v| is_result_for(v, &u), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    assert!(!h.out_lines().iter().any(|l| l.contains("oauth_token_refresh")), "the refresh request reached the host\n{transcript}");
    let answer = r#"{"type":"control_response","response":{"subtype":"success","request_id":"o1","response":{"accessToken":null}}}"#;
    let log = h.stdin_of(1);
    assert!(log.iter().any(|l| l == answer), "the child never got the local answer: {log:#?}");
    assert!(log.iter().any(|l| l.contains(r#""request_id":"o1""#) && l.contains(r#""accessToken":null"#)));
    let note = h.end_note();
    assert!(note_has(&note, "oauth_refresh_answered:1"), "{note}");
    let rows = h.audit_events("oauth_refresh_answered");
    assert_eq!(rows.len(), 1, "{:#?}", h.audit_rows());
}

#[test]
fn registry_row_is_written_and_closed() {
    let mut h = Harness::spawn("local-child", &[], &[]);
    let sid = fake_fixed_sid();
    let slug = h.slug();
    h.send_initialize();
    h.expect_out(is_init, T);
    let u = h.send_user("register me");
    h.expect_out(|v| is_result_for(v, &u), T);

    // While the session is open.
    let files = h.registry_files();
    assert_eq!(files.len(), 1, "{files:#?}\n{}", h.transcript());
    assert_eq!(files[0].0, format!("{sid}.toml"));
    let open = &h.registry_rows()[0];
    assert_eq!(toml_str(open, "status"), "active", "{}", files[0].1);
    assert!(open.get("exit").is_none(), "no exit while active: {}", files[0].1);

    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    let (name, text) = h.registry_files().into_iter().next().expect("the row is still there");
    assert_eq!(name, format!("{sid}.toml"));
    let row = &h.registry_rows()[0];
    assert_eq!(toml_str(row, "session_id"), sid, "{text}");
    assert_eq!(toml_str(row, "status"), "closed", "{text}");
    assert_eq!(toml_int(row, "exit"), 0, "{text}");
    assert_eq!(toml_str(row, "mode"), "local-child", "{text}");
    assert_eq!(toml_str(row, "route"), "local:unconfigured", "{text}");
    assert_eq!(toml_str(row, "slug"), slug, "{text}");
    assert_eq!(toml_str(row, "transcript_rel"), format!("{slug}/{sid}.jsonl"), "{text}");
    assert_eq!(toml_str(row, "cwd"), path_str(&h.prepared.work()), "{text}");
    assert_eq!(toml_int(row, "respawns"), 0, "{text}");
    assert_eq!(toml_int(row, "pid"), i64::from(h.pid()), "the wrapper's pid: {text}");
    let hash = toml_str(row, "argv_hash");
    assert!(hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "argv_hash is 64 lowercase hex: {hash}");
    assert!(!text.contains("register me") && !text.contains("jsonSchema"), "{text}");
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = h.bridge().join("state").join("sessions");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700, "sessions dir");
        assert_eq!(mode(&dir.join(&name)), 0o600, "registry row");
    }
}

#[test]
fn probe_without_user_line_gets_no_registry_row() {
    let mut h = Harness::spawn("local-child", &[], &[]);
    let id = h.send_initialize();
    h.expect_out(|v| is_response_to(v, &id), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(h.registry_files().is_empty(), "{:#?}", h.registry_files());
    let rows = h.census();
    assert_eq!(rows.len(), 2, "a start row and an end row: {rows:#?}");
    assert!(rows[0].get("end").is_none() && rows[1].get("end").is_some(), "{rows:#?}");
    assert_eq!((rows[0]["pid"].clone(), rows[0]["start"].clone()), (rows[1]["pid"].clone(), rows[1]["start"].clone()), "paired on (pid, start)");
}

#[test]
fn no_session_persistence_gets_no_registry_row() {
    let mut h = Harness::spawn("local-child", &["--no-session-persistence"], &[]);
    h.send_initialize();
    h.expect_out(is_init, T);
    let u = h.send_user("ephemeral");
    h.expect_out(|v| is_result_for(v, &u), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(h.registry_files().is_empty(), "{:#?}", h.registry_files());
    let argv = h.argv_log();
    assert_eq!(argv.len(), 1);
    assert!(argv[0].iter().any(|a| a == "--no-session-persistence"), "{argv:#?}");
    assert_eq!(argv[0].last().map(String::as_str), Some("--session-mirror"), "{argv:#?}");
}

/// D21 with the lab knob `AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS=500`: the
/// respawned child never answers the replay, so after the deadline the host's
/// initialize gets an error answer, the timeout is audited, and host input
/// keeps flowing to generation 2.
#[cfg(debug_assertions)]
#[test]
fn replay_timeout_releases_buffered_lines() {
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0006);
    plant_source(&p, &sid);
    let marker = p.root.join("resume.marker");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn(
        "local-scratch",
        &[&resume],
        &[("FAKE_RESUME_FAIL_ONCE", path_str(&marker)), ("FAKE_IGNORE_CONTROL_GEN", "2"), ("AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS", "500")],
    );
    let t = Instant::now();
    let init_id = h.send_initialize();
    // Far below the 15 s default: a pump that ignores the knob fails here.
    let failed = h.expect_out(|v| is_response_to(v, &init_id), Duration::from_secs(10));
    eprintln!("replay_timeout_releases_buffered_lines: initialize -> error answer {} ms (deadline 500 ms after the respawn)", t.elapsed().as_millis());
    assert_eq!(failed["response"]["subtype"], "error", "{failed}");
    let err = failed["response"]["error"].as_str().unwrap_or_default();
    assert!(err.contains("respawned child did not answer"), "{failed}");
    let timeouts = h.audit_events("replay_timeout");
    assert_eq!(timeouts.len(), 1, "{:#?}", h.audit_rows());
    // Host input flows: a user line sent now reaches generation 2 and is answered.
    let u = h.send_user("released");
    h.expect_out(|v| is_result_for(v, &u), T);
    let line = h.sent.last().unwrap().clone();
    assert!(h.stdin_of(2).contains(&line), "{:#?}", h.stdin_log());
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert_eq!(h.out_matching(|v| is_response_to(v, &init_id)).len(), 1, "one (error) answer only\n{}", h.transcript());
    assert_eq!(h.spawn_count(), 2, "{}", h.transcript());
}

/// A scratch child never sees the Mac's secure-storage override, its config
/// dir is a fresh name under `state/scratch` marked with the wrapper's pid
/// while the session runs, and an invocation that never registered a session
/// (no user line) leaves no scratch dir behind.
#[test]
fn scratch_child_env_is_confined() {
    let mut h = Harness::spawn("local-scratch", &[], &[("CLAUDE_SECURESTORAGE_CONFIG_DIR", "/x")]);
    h.send_initialize();
    h.expect_out(is_init, T);
    let env = h.env_log();
    assert_eq!(env.len(), 1, "{env:#?}");
    assert_eq!(env_log_field(&env[0], "SECURESTORAGE"), Some("absent"), "CLAUDE_SECURESTORAGE_CONFIG_DIR must be removed from the child's env: {}", env[0]);
    let (dir, name) = gen1_scratch(&h);
    assert!(registry::is_uuid(&name), "a fresh uuid names the scratch dir: {name}");
    // While the session runs.
    assert_eq!(SCRATCH_OWNER_FILE, ".ai-env-owner");
    let owner = std::fs::read_to_string(dir.join(SCRATCH_OWNER_FILE)).unwrap_or_else(|e| panic!("no owner file in {} while the session runs: {e}", dir.display()));
    assert_eq!(owner.trim(), h.pid().to_string(), "the owner file holds the wrapper's pid");
    assert_eq!(registry::scratch_owner(&dir), Some(h.pid()));
    assert_eq!(mode_of(&dir), 0o700, "{}", dir.display());
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    assert!(!dir.exists(), "the fresh scratch dir of an unregistered invocation is removed: {}", dir.display());
    assert!(h.scratch_names().is_empty(), "nothing left under state/scratch: {:?}", h.scratch_names());
    assert!(h.registry_files().is_empty(), "{:#?}", h.registry_files());
    assert!(h.err_text().contains("local-scratch without CLAUDE_CODE_OAUTH_TOKEN"), "{transcript}");
}

/// A registered session's fresh-named scratch dir is renamed to the session
/// id at the end (so `session forget` and a later `--resume` find it) and
/// loses its owner mark.
#[test]
fn scratch_dir_is_renamed_to_the_session_id() {
    let mut h = Harness::spawn("local-scratch", &[], &[]);
    h.send_initialize();
    h.expect_out(is_init, T);
    let u = h.send_user("name my scratch dir");
    h.expect_out(|v| is_result_for(v, &u), T);
    let (fresh, name) = gen1_scratch(&h);
    assert!(registry::is_uuid(&name), "{name}");
    assert_eq!(registry::scratch_owner(&fresh), Some(h.pid()), "the owner file holds the wrapper's pid while the session runs");
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    let sid = fake_fixed_sid();
    assert_ne!(name, sid);
    assert_eq!(h.scratch_names(), vec![sid.clone()], "exactly <scratch>/<session id>\n{transcript}");
    let dir = h.scratch_dir(&sid);
    assert!(!fresh.exists(), "the fresh name is gone: {}", fresh.display());
    assert_eq!(mode_of(&dir), 0o700, "{}", dir.display());
    assert!(std::fs::symlink_metadata(dir.join(SCRATCH_OWNER_FILE)).is_err(), "no owner file after the session");
    let row = &h.registry_rows()[0];
    assert_eq!(toml_str(row, "session_id"), sid);
    assert_eq!(toml_str(row, "scratch_dir"), path_str(&dir), "the row records the final scratch dir");
    assert_eq!(toml_str(row, "status"), "closed");
}

/// The pre-spawn seed never overwrites a scratch transcript at least as long
/// as the Mac's copy (it may hold entries the Mac copy lacks).
#[test]
fn prespawn_seed_never_shrinks_the_scratch_copy() {
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0007);
    let (planted, _) = plant_source(&p, &sid);
    let mac_before = std::fs::read(&planted).unwrap();
    let scratch_dir = p.root.join("bridge").join("state").join("scratch").join(&sid);
    let project = scratch_dir.join("projects").join(p.slug());
    mkdir_0700(&project);
    let mut longer = mac_before.clone();
    longer.extend_from_slice(format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"only in scratch"}}}}"#, uuid(0x1003)).as_bytes());
    longer.push(b'\n');
    let scratch_file = project.join(format!("{sid}.jsonl"));
    std::fs::write(&scratch_file, &longer).unwrap();
    let resume = format!("--resume={sid}");
    let mut h = p.spawn("local-scratch", &[&resume], &[]);
    h.send_initialize();
    h.expect_out(is_init, T);
    let u = h.send_user("resume from scratch");
    h.expect_out(|v| is_result_for(v, &u), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    assert_eq!(std::fs::read(&scratch_file).unwrap(), longer, "the longer scratch copy is unchanged");
    assert_eq!(std::fs::read(&planted).unwrap(), mac_before, "the Mac copy is unchanged");
    assert_eq!(h.spawn_count(), 1, "{transcript}");
    assert!(seed_rows(&h).is_empty(), "{:#?}", h.audit_rows());
    assert_eq!(h.scratch_names(), vec![sid.clone()]);
    assert!(std::fs::symlink_metadata(scratch_dir.join(SCRATCH_OWNER_FILE)).is_err(), "no owner file after the session");
}

/// `/clear`: a later init with a DIFFERENT session id in the same process
/// closes the current registry row and opens one for the new id.
#[test]
fn clear_starts_a_new_registry_row() {
    let mut h = Harness::spawn("local-child", &[], &[("FAKE_NEW_SESSION_AFTER", "1")]);
    let (first, second) = (fake_fixed_sid(), fake_clear_sid());
    h.send_initialize();
    h.expect_out(is_init, T);
    let u1 = h.send_user("before /clear");
    h.expect_out(|v| is_result_for(v, &u1), T);
    let u2 = h.send_user("after /clear");
    h.expect_out(|v| is_result_for(v, &u2), T);
    let names: Vec<String> = h.registry_files().into_iter().map(|(n, _)| n).collect();
    assert_eq!(names.len(), 2, "one row per session id while the second one runs: {names:?}\n{}", h.transcript());
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    let inits: Vec<String> = h.out_matching(is_init).iter().map(|v| v["session_id"].as_str().unwrap_or_default().to_string()).collect();
    assert_eq!(inits, vec![first.clone(), second.clone()], "{transcript}");
    let files = h.registry_files();
    let mut want = vec![format!("{first}.toml"), format!("{second}.toml")];
    want.sort();
    assert_eq!(files.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(), want, "{files:#?}");
    for ((name, text), row) in files.iter().zip(h.registry_rows()) {
        let id = toml_str(&row, "session_id");
        assert_eq!(format!("{id}.toml"), *name, "{text}");
        assert_eq!(toml_str(&row, "status"), "closed", "{text}");
        assert_eq!(toml_str(&row, "transcript_rel"), format!("{}/{id}.jsonl", h.slug()), "{text}");
    }
    let last = h.registry_rows().into_iter().find(|r| toml_str(r, "session_id") == second).expect("the second row");
    assert_eq!(toml_int(&last, "exit"), 0, "the row open at the end gets the exit code");
}

/// Every file under a directory, recursively.
fn all_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => out.extend(all_files(&p)),
                Ok(t) if t.is_file() => out.push(p),
                _ => {}
            }
        }
    }
    out
}

/// Invariant (1) of the plan (§2.8) for everything S2 writes: the OAuth
/// token in the child's environment and an API key inside the host's MCP and
/// flag-settings requests never reach wrapper.log (even at trace level), the
/// census, audit.jsonl or the registry — the only secret-bearing inputs S2
/// sees. The values are built at runtime (no credential-looking literals).
#[test]
fn secrets_never_reach_the_log_census_audit_or_registry() {
    let token = format!("sk-ant-oat01-{}", "Q".repeat(40));
    let api_key = format!("proj-{}", "Z".repeat(32));
    let mut h = Harness::spawn(
        "local-child",
        &[],
        &[("CLAUDE_CODE_OAUTH_TOKEN", token.as_str()), ("RUST_LOG", "ai_env_cli=trace"), ("FAKE_OAUTH_REFRESH", "1")],
    );
    h.send_initialize();
    h.send_control("mcp_set_servers", &format!(r#"{{"servers":{{"x":{{"type":"stdio","command":"c","env":{{"OPENAI_API_KEY":"{api_key}"}}}}}}}}"#));
    h.send_control("apply_flag_settings", &format!(r#"{{"settings":{{"env":{{"SOME_KEY":"{api_key}"}},"model":"claude-x"}}}}"#));
    let u = h.send_user(&format!("the key is {api_key} and the token {token}"));
    h.expect_out(|v| is_result_for(v, &u), T);
    h.close_stdin();
    let (status, _) = h.wait(EXIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    let files = all_files(&h.bridge());
    let names: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
    for want in ["wrapper.log", "census.jsonl", "audit.jsonl"] {
        assert!(names.iter().any(|n| n.ends_with(want)), "{want} was written: {names:#?}");
    }
    assert!(names.iter().any(|n| n.ends_with(".toml") && n.contains("sessions")), "a registry row was written: {names:#?}");
    for f in &files {
        let text = String::from_utf8_lossy(&std::fs::read(f).unwrap()).into_owned();
        assert!(!text.contains(&token), "the OAuth token reached {}", f.display());
        assert!(!text.contains(&api_key), "the API key reached {}", f.display());
    }
    assert!(h.wrapper_log().contains("TRACE") || h.wrapper_log().contains("DEBUG"), "the log ran at a verbose level");
}
