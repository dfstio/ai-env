//! T2.4 harness — the pump's timing contract and its lab knobs, measured
//! against `tests/fakes/claude-v2.sh`: host stdin EOF → exit ≤ 1500 ms (every
//! rung of the ladder), SIGTERM → exit ≤ 1000 ms (every rung), the
//! `after-init` lab exit, stdout never carrying the wrapper's own noise, the
//! delayed initialize, lines far above 4 MiB passing intact (up to the CLI's 256 MiB),
//! backpressure under a stalled host reader, a host that stops reading, and a
//! slow host after the child's own exit.
//!
//! Every test takes [`SERIAL`] so the wall-clock measurements never overlap
//! (plan R5: a flake is a finding), and prints what it measured. The lab
//! knobs exist only in debug builds, which is what `cargo test` builds.
mod common;

use common::{is_init, is_response_to, is_result_for, note_has, note_number, pid_alive, uuid, Harness};
use serde_json::Value;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Upper bound for a frame (a loaded Mac can start a child seconds late; nothing is measured here).
const T: Duration = Duration::from_secs(30);
/// Upper bound for `wait`; the budgets themselves are asserted on the measured duration.
const WAIT: Duration = Duration::from_secs(30);
const EOF_BUDGET: Duration = Duration::from_millis(1500);
const SIGTERM_BUDGET: Duration = Duration::from_millis(1000);

fn path_str(p: &std::path::Path) -> &str {
    p.to_str().expect("utf-8 path")
}

/// The `stream_event` sequence numbers on stdout, in arrival order.
fn stream_seq(h: &mut Harness) -> Vec<u64> {
    h.out_json().iter().filter(|v| v["type"] == "stream_event").filter_map(|v| v["n"].as_u64()).collect()
}

#[test]
fn eof_honoured_exits_within_1500ms() {
    let _g = serial();
    let mut h = Harness::spawn("local-child", &[], &[]);
    h.send_initialize();
    h.expect_out(is_init, T);
    h.close_stdin();
    let (status, took) = h.wait(WAIT);
    eprintln!("eof_honoured_exits_within_1500ms: EOF -> exit {} ms", took.as_millis());
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{}", h.transcript());
    let rows = h.census();
    assert_eq!(rows.len(), 2, "{rows:#?}");
    assert!(rows[1]["end"].is_u64(), "the second row carries end: {}", rows[1]);
    assert_eq!(rows[1]["exit"], 0, "{}", rows[1]);
    let note = rows[1]["note"].as_str().unwrap_or_default();
    assert!(note_has(note, "end:eof"), "{note}");
}

#[test]
fn eof_ignored_child_is_killed_within_1500ms() {
    let _g = serial();
    let mut h = Harness::spawn("local-child", &[], &[("FAKE_IGNORE_EOF", "1"), ("FAKE_IGNORE_TERM", "1")]);
    h.send_initialize();
    h.expect_out(is_init, T);
    h.close_stdin();
    let (status, took) = h.wait(WAIT);
    eprintln!("eof_ignored_child_is_killed_within_1500ms: EOF -> exit {} ms", took.as_millis());
    assert_eq!(status.code(), Some(0), "a child killed by the EOF ladder still ends the session with 0\n{}", h.transcript());
    assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{}", h.transcript());
    let note = h.end_note();
    assert!(note_has(&note, "end:eof_kill"), "{note}");
    assert_eq!(h.end_row()["exit"], 0);
}

/// The EOF ladder's middle rung: the child ignores EOF but not SIGTERM, so
/// the SIGTERM at +800 ms ends it (never the SIGKILL at +1200 ms).
#[test]
fn eof_ladder_sigterm_rung() {
    let _g = serial();
    let p = Harness::prepare();
    let term_log = p.root.join("term.log");
    let mut h = p.spawn("local-child", &[], &[("FAKE_IGNORE_EOF", "1"), ("FAKE_TERM_LOG", path_str(&term_log))]);
    h.send_initialize();
    h.expect_out(is_init, T);
    h.close_stdin();
    let (status, took) = h.wait(WAIT);
    eprintln!("eof_ladder_sigterm_rung: EOF -> exit {} ms (SIGTERM rung at 800 ms), code {:?}", took.as_millis(), status.code());
    let transcript = h.transcript();
    assert!(took >= Duration::from_millis(700), "the child ignored EOF, so only the SIGTERM rung (+800 ms) could end it; took {took:?}\n{transcript}");
    assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{transcript}");
    assert_eq!(std::fs::read_to_string(&term_log).unwrap_or_default(), "TERM\n", "the child got exactly one SIGTERM\n{transcript}");
    let note = h.end_note();
    assert!(note_has(&note, "end:eof"), "{note}");
    assert_eq!(status.code(), Some(0), "a child ended by the EOF ladder ends the session with 0\n{transcript}");
    assert_eq!(h.end_row()["exit"], 0, "{}", h.end_row());
}

#[test]
fn sigterm_is_forwarded_and_exits_within_1000ms() {
    let _g = serial();
    let p = Harness::prepare();
    let term_log = p.root.join("term.log");
    let mut h = p.spawn("local-child", &[], &[("FAKE_TERM_LOG", path_str(&term_log))]);
    h.send_initialize();
    h.expect_out(is_init, T);
    h.sigterm();
    let (status, took) = h.wait(WAIT);
    eprintln!("sigterm_is_forwarded_and_exits_within_1000ms: SIGTERM -> exit {} ms", took.as_millis());
    assert!(took < SIGTERM_BUDGET, "SIGTERM -> exit took {took:?} (budget {SIGTERM_BUDGET:?})\n{}", h.transcript());
    assert_eq!(std::fs::read_to_string(&term_log).unwrap_or_default(), "TERM\n", "the child got exactly one SIGTERM\n{}", h.transcript());
    assert_eq!(status.code(), Some(143), "the child's own code (its trap exits 143)\n{}", h.transcript());
    let note = h.end_note();
    assert!(note_has(&note, "end:sigterm"), "{note}");
}

/// The SIGTERM ladder's last rung: the child ignores SIGTERM, so the SIGKILL
/// at +600 ms ends it.
#[test]
fn sigterm_ladder_sigkill_rung() {
    let _g = serial();
    let mut h = Harness::spawn("local-child", &[], &[("FAKE_IGNORE_TERM", "1")]);
    h.send_initialize();
    h.expect_out(is_init, T);
    h.sigterm();
    let (status, took) = h.wait(WAIT);
    eprintln!("sigterm_ladder_sigkill_rung: SIGTERM -> exit {} ms (SIGKILL rung at 600 ms), code {:?}", took.as_millis(), status.code());
    let transcript = h.transcript();
    assert!(took >= Duration::from_millis(550), "the child ignored SIGTERM, so only the SIGKILL rung (+600 ms) could end it; took {took:?}\n{transcript}");
    assert!(took < SIGTERM_BUDGET, "SIGTERM -> exit took {took:?} (budget {SIGTERM_BUDGET:?})\n{transcript}");
    let note = h.end_note();
    assert!(note_has(&note, "end:sigterm"), "{note}");
    assert_eq!(status.code(), Some(128 + 9), "the child died of SIGKILL: 128 + 9\n{transcript}");
}

#[cfg(debug_assertions)]
#[test]
fn lab_exit_after_init() {
    let _g = serial();
    let mut h = Harness::spawn(
        "local-child",
        &[],
        &[("AI_ENV_BRIDGE_LAB_EXIT", "3:boom:after-init"), ("FAKE_STDERR", "fake-start"), ("FAKE_TERM_STDERR", "fake-term")],
    );
    h.send_initialize();
    let (status, took) = h.wait(WAIT);
    eprintln!("lab_exit_after_init: spawn -> exit {} ms", took.as_millis());
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(3), "{transcript}");
    let err = h.err_text();
    let lines: Vec<&str> = err.lines().collect();
    assert!(lines.contains(&"fake-start"), "the child's stderr is copied\n{transcript}");
    let term_at = lines.iter().position(|l| *l == "fake-term").unwrap_or_else(|| panic!("the child's TERM-trap line is missing from stderr\n{transcript}"));
    let boom_at = lines.iter().rposition(|l| *l == "boom").unwrap_or_else(|| panic!("no boom on stderr\n{transcript}"));
    assert!(term_at < boom_at, "the child's last words (line {term_at}) come before the lab message (line {boom_at})\n{transcript}");
    let last = lines.iter().rev().find(|l| !l.trim().is_empty()).copied();
    assert_eq!(last, Some("boom"), "the lab message is the last stderr line\n{transcript}");
    assert_eq!(h.spawn_count(), 1, "no relaunch\n{transcript}");
    assert_eq!(h.out_matching(is_init).len(), 1, "{transcript}");
    let pid = h.fake_pid(1).unwrap_or_else(|| panic!("the fake logged no pid: {:?}", h.env_log()));
    assert!(!pid_alive(pid), "the fake (pid {pid}) outlived the wrapper\n{transcript}");
    let end = h.end_row();
    assert!(note_has(end["note"].as_str().unwrap_or_default(), "end:lab_exit"), "{end}");
    assert_eq!(end["exit"], 3, "{end}");
}

#[cfg(debug_assertions)]
#[test]
fn stdout_noise_never_reaches_stdout() {
    let _g = serial();
    let mut h = Harness::spawn("local-child", &[], &[("AI_ENV_BRIDGE_LAB_STDOUT_NOISE", "1")]);
    h.send_initialize();
    h.expect_out(is_init, T);
    let u = h.send_user("noisy");
    h.expect_out(|v| is_result_for(v, &u), T);
    h.close_stdin();
    let (status, _) = h.wait(WAIT);
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    for l in h.out_lines() {
        assert!(serde_json::from_str::<Value>(&l).is_ok(), "a stdout line that is not JSON: {l:?}\n{transcript}");
        assert!(!l.contains("hello"), "the noise reached stdout: {l}");
    }
    assert!(h.err_text().lines().any(|l| l == "ai-env-claude: hello"), "{transcript}");
    assert!(h.wrapper_log().contains("hello"), "the noise is logged\n{transcript}");
}

#[cfg(debug_assertions)]
#[test]
fn delay_init_holds_the_init_response() {
    let _g = serial();
    let mut h = Harness::spawn("local-child", &[], &[("AI_ENV_BRIDGE_LAB_DELAY_INIT_MS", "300")]);
    let id = h.send_initialize();
    let (_, at) = h.expect_out_at(|v| is_response_to(v, &id), T);
    let after = at.duration_since(h.started);
    eprintln!("delay_init_holds_the_init_response: spawn -> initialize response {} ms (delay 300)", after.as_millis());
    assert!(after >= Duration::from_millis(300), "the initialize response arrived {after:?} after spawn (< 300 ms)\n{}", h.transcript());
    h.close_stdin();
    let (status, _) = h.wait(WAIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    let init_ms = note_number(&h.end_note(), "init_ms");
    eprintln!("delay_init_holds_the_init_response: end row init_ms = {init_ms:?}");

    // EOF during a long delay still ends the session within the EOF budget.
    let mut h = Harness::spawn("local-child", &[], &[("AI_ENV_BRIDGE_LAB_DELAY_INIT_MS", "5000")]);
    h.send_initialize();
    h.close_stdin();
    let (status, took) = h.wait(WAIT);
    eprintln!("delay_init_holds_the_init_response: EOF during a 5000 ms delay -> exit {} ms", took.as_millis());
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{}", h.transcript());
}

/// Lines are split at the CLI's own limit (256 MiB), not at 4 MiB (the
/// line cap S2 first planned for the wire): a 5 MiB user line reaches the
/// child and a 5 MiB child line reaches the host, both byte for byte.
#[test]
fn large_lines_pass_intact() {
    let _g = serial();
    const BIG: usize = 5 * 1024 * 1024 + 1;
    let p = Harness::prepare();
    let big_out = format!(r#"{{"type":"stream_event","event":{{"type":"content_block_delta"}},"pad":"{}"}}"#, "y".repeat(BIG));
    let file = p.write_file("big-stdout.ndjson", &format!("{big_out}\n"));
    let mut h = p.spawn("local-child", &[], &[("FAKE_STDOUT_FILE", path_str(&file))]);
    h.send_initialize();
    h.expect_out(is_init, T);
    let text = "x".repeat(BIG);
    let t = Instant::now();
    let u = h.send_user(&text);
    h.expect_out(|v| is_result_for(v, &u), T);
    eprintln!("large_lines_pass_intact: {} byte user line -> its result {} ms", Harness::user_line(&u, &text).len(), t.elapsed().as_millis());
    h.close_stdin();
    let (status, _) = h.wait(WAIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    let user = Harness::user_line(&u, &text);
    assert!(user.len() > BIG);
    let log = h.stdin_of(1);
    assert_eq!(log.iter().filter(|l| **l == user).count(), 1, "the {} byte user line reached the child byte for byte ({} lines logged)", user.len(), log.len());
    let out = h.out_lines();
    assert_eq!(out.iter().filter(|l| **l == big_out).count(), 1, "the {} byte child line reached the host byte for byte", big_out.len());
    let note = h.end_note();
    assert!(note_has(&note, "dropped:0"), "{note}");
}

/// D3: a stalled host stdout never stops the host → child direction. The
/// fake streams from a background subshell (`FAKE_STREAM_BG`) so its main
/// loop keeps reading stdin while every buffer towards the host is full.
#[test]
fn backpressure_survives_a_stalled_host_reader() {
    let _g = serial();
    const LINES: u64 = 20_000;
    let n = LINES.to_string();
    let mut h = Harness::spawn("local-child", &[], &[("FAKE_STREAM_LINES", &n), ("FAKE_STREAM_BG", "1")]);
    h.pause_stdout();
    let t = Instant::now();
    h.send_initialize();
    // Let the stream (≈ 600 KB) fill every pipe and channel between the fake and the harness.
    std::thread::sleep(Duration::from_millis(300));
    let text = "sent during the stall";
    let u = h.send_user(text);
    let line = Harness::user_line(&u, text);
    h.wait_until("the user line reaches the child while the host's stdout is stalled", Duration::from_secs(10), |h| h.stdin_of(1).contains(&line));
    let reached = t.elapsed();
    assert!(h.seen_out.len() < 10, "the harness read nothing during the stall: {} lines", h.seen_out.len());
    eprintln!("backpressure_survives_a_stalled_host_reader: the user line reached the child {} ms into the stall", reached.as_millis());
    h.resume_stdout();
    h.expect_out(|v| v["type"] == "stream_event" && v["n"] == LINES, T);
    h.expect_out(|v| is_result_for(v, &u), T);
    eprintln!("backpressure_survives_a_stalled_host_reader: stall + drain {} ms", t.elapsed().as_millis());
    h.close_stdin();
    let (status, _) = h.wait(WAIT);
    assert_eq!(status.code(), Some(0), "{}", h.transcript());
    let seq = stream_seq(&mut h);
    assert_eq!(seq.len() as u64, LINES, "every stream_event line arrived");
    assert!(seq.iter().copied().eq(1..=LINES), "in order");
    assert_eq!(h.out_matching(|v| is_result_for(v, &u)).len(), 1);
}

#[test]
fn sigterm_is_honoured_while_host_stdout_is_stalled() {
    let _g = serial();
    let mut h = Harness::spawn("local-child", &[], &[("FAKE_STREAM_LINES", "20000")]);
    h.pause_stdout();
    h.send_initialize();
    h.wait_until("the fake read the initialize", T, |h| !h.stdin_of(1).is_empty());
    // The stream (≈ 600 KB) fills every pipe and channel towards the stalled host.
    std::thread::sleep(Duration::from_millis(300));
    h.sigterm();
    let (status, took) = h.wait_exit(WAIT);
    h.resume_stdout();
    let _ = h.wait(WAIT);
    eprintln!("sigterm_is_honoured_while_host_stdout_is_stalled: SIGTERM -> exit {} ms, code {:?}", took.as_millis(), status.code());
    assert!(took < SIGTERM_BUDGET, "SIGTERM -> exit took {took:?} (budget {SIGTERM_BUDGET:?})\n{}", h.transcript());
    let note = h.end_note();
    assert!(note_has(&note, "end:sigterm"), "{note}");
}

#[test]
fn ignore_eof_records_eof_to_sigterm() {
    let _g = serial();
    let mut h = Harness::spawn("local-child", &[], &[("AI_ENV_BRIDGE_LAB_IGNORE_EOF", "1")]);
    h.send_initialize();
    h.expect_out(is_init, T);
    h.close_stdin();
    std::thread::sleep(Duration::from_millis(300));
    h.sigterm();
    let (status, took) = h.wait(WAIT);
    eprintln!("ignore_eof_records_eof_to_sigterm: SIGTERM -> exit {} ms", took.as_millis());
    assert!(took < SIGTERM_BUDGET, "SIGTERM -> exit took {took:?} (budget {SIGTERM_BUDGET:?})\n{}", h.transcript());
    assert_eq!(status.code(), Some(143), "the child dies of SIGTERM: 128 + 15\n{}", h.transcript());
    let note = h.end_note();
    assert!(note_has(&note, "end:sigterm"), "{note}");
    let ms = note_number(&note, "eof_to_sigterm_ms").unwrap_or_else(|| panic!("no eof_to_sigterm_ms in {note}"));
    eprintln!("ignore_eof_records_eof_to_sigterm: eof_to_sigterm_ms = {ms}");
    assert!((250..=1000).contains(&ms), "eof_to_sigterm_ms = {ms}, expected about 300");
}

/// A host EOF while the respawned child has not answered the replay yet
/// starts the EOF ladder at once (the replay window never holds it).
#[test]
fn eof_during_replay_window_exits_within_budget() {
    let _g = serial();
    let p = Harness::prepare();
    let sid = uuid(0x5e55_0101);
    p.plant_transcript(&sid, &[r#"{"type":"user","message":{"role":"user","content":"earlier"}}"#]);
    let marker = p.root.join("resume.marker");
    let resume = format!("--resume={sid}");
    let mut h = p.spawn("local-scratch", &[&resume], &[("FAKE_RESUME_FAIL_ONCE", path_str(&marker)), ("FAKE_IGNORE_CONTROL_GEN", "2")]);
    let init_id = h.send_initialize();
    h.wait_until("generation 2 read the replayed initialize", T, |h| h.stdin_of(2).iter().any(|l| l.contains(r#""subtype":"initialize""#)));
    h.close_stdin();
    let (status, took) = h.wait(WAIT);
    eprintln!("eof_during_replay_window_exits_within_budget: EOF -> exit {} ms", took.as_millis());
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{transcript}");
    assert!(note_has(&h.end_note(), "end:eof"), "{}", h.end_note());
    assert_eq!(h.spawn_count(), 2, "{transcript}");
    assert!(!h.stdin_of(2)[0].contains(&init_id), "gen 2 got a fresh request id: {}", h.stdin_of(2)[0]);
}

/// The host closes its read end of the wrapper's stdout and keeps writing:
/// the next forwarded line fails with EPIPE and the session ends with 0.
#[test]
fn host_gone_ends_the_session() {
    let _g = serial();
    let mut h = Harness::spawn("local-child", &[], &[]);
    h.send_initialize();
    h.expect_out(is_init, T);
    h.close_stdout();
    let deadline = Instant::now() + WAIT;
    let mut n = 0_u64;
    while !h.exited_now() && Instant::now() < deadline {
        n += 1;
        if h.try_send(&Harness::user_line(&uuid(0xb000 + n), "nobody reads the answer")).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let (status, took) = h.wait(WAIT);
    eprintln!("host_gone_ends_the_session: stdout closed -> exit {} ms ({n} user lines sent)", took.as_millis());
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    assert!(took < EOF_BUDGET, "stdout closed -> exit took {took:?} (budget {EOF_BUDGET:?})\n{transcript}");
    let note = h.end_note();
    assert!(["end:eof", "end:eof_kill", "end:host_gone"].iter().any(|p| note_has(&note, p)), "{note}");
    assert_eq!(h.end_row()["exit"], 0, "{}", h.end_row());
}

/// The child exits on its own while the host is not reading: the host still
/// gets every line once it reads again (up to 5 s), the last one included.
/// The lines are 32 KiB each, so they cannot all sit in the host pipe: most
/// wait in the pump when the child's exit is seen.
#[test]
fn slow_host_after_child_exit_gets_every_line() {
    let _g = serial();
    const LINES: u64 = 40;
    let n = LINES.to_string();
    let mut h = Harness::spawn("local-child", &[], &[("FAKE_STREAM_LINES", &n), ("FAKE_STREAM_PAD", "32768"), ("FAKE_EXIT_AFTER_STREAM", "1")]);
    h.send_initialize();
    h.expect_out(is_init, T);
    h.pause_stdout();
    std::thread::sleep(Duration::from_secs(1));
    let running = !h.exited_now();
    h.resume_stdout();
    let (status, _) = h.wait(WAIT);
    eprintln!("slow_host_after_child_exit_gets_every_line: wrapper still running after the 1 s stall: {running}");
    let transcript = h.transcript();
    assert_eq!(status.code(), Some(0), "{transcript}");
    let seq = stream_seq(&mut h);
    assert_eq!(seq.last().copied(), Some(LINES), "the last line arrived: {} of {LINES} lines\n{transcript}", seq.len());
    assert!(seq.iter().copied().eq(1..=LINES), "every line, in order: {} of {LINES}", seq.len());
    let note = h.end_note();
    assert!(note_has(&note, "end:child_exit"), "{note}");
}
