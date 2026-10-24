//! S11 part B (wave 1, B1): the panel's `session-migrate` is `ai-env session
//! migrate` (B §B5.8, §B6.4), on the S10 rig (`common::remote`, one in-process
//! shim per fake VM) with the real `ai-env-claude` in remote mode: the live
//! path (a wrapper serves the chat: the panel signals it, and the wrapper's
//! `session_move_end` carries the panel's nonce as its `request`) and the
//! offline one (no wrapper: the panel moves the chat itself, one Touch ID).
//! The helpers are the continuity tests' (tests/continuity.rs), copied: that
//! file is C3's in S11.
use super::{Panel, T};
use crate::common::remote::{toml_table, RemoteRig};
use crate::common::{is_init, is_response_to, is_result_for, Harness, Link};
use ai_env_cli::bridge::api::VmState;
use serde_json::Value;
use std::time::Duration;

/// The fake claude as the real CLI is: an init with each turn, its transcript written, a resume needing it.
const CLI: [(&str, &str); 3] = [("FAKE_INIT_AT_TURN", "1"), ("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_RESUME_NEEDS_FILE", "1")];
const EXIT: Duration = Duration::from_secs(30);

/// The host's start: `initialize`, `set_permission_mode` and `apply_flag_settings{model}`, each answered.
fn started(h: &mut Harness) {
    let ids = [h.send_initialize(), h.send_control("set_permission_mode", r#"{"mode":"acceptEdits"}"#), h.send_control("apply_flag_settings", r#"{"settings":{"model":"claude-x"}}"#)];
    for id in &ids {
        h.expect_out(|v| is_response_to(v, id), T);
    }
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

/// Until `views` views of session `sid`'s transcript were written.
fn synced(h: &mut Harness, sid: &str, views: usize) {
    h.wait_until("the turn's transcript synced to S3 and its view written", T, |h| {
        h.audit_events("transcript_view").iter().filter(|r| r["detail"]["session"] == sid && r["detail"]["outcome"] == "written").count() >= views
    });
}

/// The VM of each generation that started, in order.
fn vms_started(h: &Harness) -> Vec<String> {
    h.audit_events("session_remote_start").iter().map(|r| r["detail"]["id"].as_str().expect("the VM").to_string()).collect()
}

/// Until the fake says `vm` is in a state `f` takes.
fn wait_for_state(rig: &RemoteRig, vm: &str, what: &str, f: impl Fn(&VmState) -> bool) {
    let t = std::time::Instant::now();
    while !rig.fake().vms.get(vm).is_some_and(|v| f(&v.state)) {
        assert!(t.elapsed() < T, "{what}: {vm} is {:?}", rig.fake().vms.get(vm).map(|v| v.state.clone()));
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Until the rig's audit holds a row of `event` whose detail `pred` takes.
fn wait_for_row(h: &mut Harness, what: &str, event: &str, pred: impl Fn(&Value) -> bool) {
    h.wait_until(what, T, |h| h.audit_events(event).iter().any(|r| pred(&r["detail"])));
}

/// The one row of `event` whose detail `pred` takes.
fn the_row(rows: &[Value], event: &str, pred: impl Fn(&Value) -> bool) -> Value {
    let found: Vec<&Value> = rows.iter().filter(|r| r["event"] == event && pred(&r["detail"])).collect();
    assert_eq!(found.len(), 1, "one {event} row as asked: {rows:#?}");
    found[0].clone()
}

/// The rig's panel: `[panel] enabled = true` in its bridge.toml, then `ai-env panel serve --port 0` in its
/// environment.
fn panel_of(rig: &RemoteRig) -> Panel {
    rig.config(|doc| {
        toml_table(doc, "panel").insert("enabled".into(), toml::Value::Boolean(true));
    });
    Panel::start(rig.ai_env(&["panel", "serve", "--port", "0"]))
}

/// The live path, then the offline one: each the CLI's move, by the panel, the panel's nonce the request's.
#[test]
fn panel_migrate_is_session_migrate() {
    // Live: a wrapper serves the chat, idle between turns.
    let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &CLI);
    started(&mut h);
    turn(&mut h, "one");
    let sid = session_of(&mut h);
    synced(&mut h, &sid, 1);
    let vm1 = vms_started(&h)[0].clone();
    let p = panel_of(h.rig());
    let confirm = p.get(&format!("confirm?action=session-migrate&target={sid}&json=1")).json();
    assert!(confirm["touch_ids"].as_str().is_some_and(|t| t.starts_with("none here")), "a live chat's wrapper asks its own: {confirm}");
    assert_eq!(confirm["twin"].as_str(), Some(format!("ai-env session migrate {sid}").as_str()));
    let nonce = confirm["nonce"].as_str().expect("the nonce").to_string();
    let r = p.post_action(&nonce, "session-migrate", &sid);
    assert_eq!(r.status, 303, "{}", r.text());
    let done = p.wait_action(&nonce);
    let rows = h.audit_rows();
    let end = the_row(&rows, "session_move_end", |d| d["request"] == nonce.as_str());
    let vm2 = end["detail"]["to_vm"].as_str().expect("the new VM").to_string();
    assert_ne!(vm2, vm1);
    assert_eq!((done["state"].as_str(), done["code"].as_i64()), (Some("done"), Some(0)), "{done}\n{}", p.stderr());
    assert_eq!(done["line"].as_str(), Some(format!("session {sid}: moved from {vm1} to {vm2} (live)").as_str()), "the CLI's line: {done}");
    assert_eq!((end["detail"]["outcome"].as_str(), end["detail"]["actor"].as_str()), (Some("done"), Some("wrapper")), "{end}");
    let asked = the_row(&rows, "session_migrate_request", |d| d["nonce"] == nonce.as_str());
    assert_eq!((asked["detail"]["how"].as_str(), asked["detail"]["actor"].as_str(), asked["detail"]["session"].as_str()), (Some("live"), Some("panel"), Some(sid.as_str())), "{asked}");
    assert_eq!(asked["detail"]["wrapper_pid"], h.pid().to_string());
    wait_for_row(&mut h, "the old VM terminated", "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate");
    let u2 = turn(&mut h, "two");
    assert_eq!(h.out_json().iter().filter(|v| is_result_for(v, &u2)).count(), 1);
    closed(&mut h);
    let (code, _, err) = p.stop();
    assert_eq!(code, Some(0), "{err}");

    // Offline: the chat closed, its VM suspended by the closing suspend; no wrapper serves it.
    let mut first = Harness::prepare().spawn_on(Link::Remote, "", &[], &CLI);
    started(&mut first);
    turn(&mut first, "one");
    let sid = session_of(&mut first);
    synced(&mut first, &sid, 1);
    closed(&mut first);
    let vm1 = vms_started(&first)[0].clone();
    wait_for_state(first.rig(), &vm1, "the closing suspend", |s| *s == VmState::Suspended);
    let rig = first.rig();
    let decrypts = rig.decrypts();
    let p = panel_of(rig);
    let confirm = p.get(&format!("confirm?action=session-migrate&target={sid}&json=1")).json();
    assert!(confirm["touch_ids"].as_str().is_some_and(|t| t.starts_with("one Touch ID")), "an offline move unseals once: {confirm}");
    let nonce = confirm["nonce"].as_str().expect("the nonce").to_string();
    assert_eq!(p.post_action(&nonce, "session-migrate", &sid).status, 303);
    let done = p.wait_action(&nonce);
    assert_eq!((done["state"].as_str(), done["code"].as_i64()), (Some("done"), Some(0)), "{done}\n{}", p.stderr());
    let row = ai_env_cli::bridge::registry::read(&ai_env_cli::bridge::config::Paths::from_root_and_env(rig.bridge(), None), &sid).expect("the row").expect("the chat's row");
    let vm2 = row.microvm_id.clone().expect("the new VM");
    assert_ne!(vm2, vm1);
    assert_eq!((row.status.as_str(), row.migrating_pid), ("closed", None), "{row:?}");
    assert_eq!(done["line"].as_str(), Some(format!("session {sid}: moved from {vm1} to {vm2} (offline)").as_str()), "{done}");
    assert_eq!(rig.decrypts() - decrypts, 1, "one Touch ID, the runtime key's");
    let rows = first.audit_rows();
    let asked = the_row(&rows, "session_migrate_request", |d| d["nonce"] == nonce.as_str());
    assert_eq!((asked["detail"]["how"].as_str(), asked["detail"]["actor"].as_str()), (Some("offline"), Some("panel")), "{asked}");
    the_row(&rows, "vm_terminate", |d| d["id"] == vm1.as_str() && d["by"] == "migrate" && d["actor"] == "panel");
    let (code, _, err) = p.stop();
    assert_eq!(code, Some(0), "{err}");
}
