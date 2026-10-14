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
//!
//! S8 (plans/s8-design-tests.md §2.2): all 15 run on both links
//! (`on_links!`), the remote half the wrapper in remote mode against the
//! rig's in-process shim (`tests/common/remote.rs`), under the same
//! [`SERIAL`] and the same budgets: EOF to exit 1500 ms, SIGTERM to exit
//! 1000 ms, the CLOSE deliverable (v6 §2.8). The remote link's own close
//! (plan L2) differs from the local ladder by design, and the remote halves
//! say where: after a host EOF no TERM goes to the VM's CLI, whose own exit
//! is awaited until `detach{final}` at +1.2 s (`end:eof_kill`); a SIGTERM is
//! `Signal(Term)` plus `detach{final}` at once (exit 143, the CLI's own code
//! never comes back), and the shim's ladder ends a CLI that ignores it after
//! the wrapper is gone. A remote half also checks what only it can show:
//! the census's `mode:remote`, nothing left on the VM, and with lines past
//! the shim's 8 MiB stdout window, backpressure reaching the VM's CLI.
mod common;

use common::{is_init, is_response_to, is_result_for, note_has, note_number, pid_alive, uuid, Harness, VM_END};
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
/// The remote link's EOF rung (L2): `detach{final}` this long after the host's EOF.
const REMOTE_DETACH_AFTER: Duration = Duration::from_millis(ai_env_cli::bridge::remote::REMOTE_EOF_DETACH_AFTER_MS);
/// On the remote link, each `stream_event` line's pad: 20000 lines of it are
/// past the shim's 8 MiB stdout window, so a stalled host stalls the VM's CLI.
const REMOTE_PAD: &str = "512";

fn path_str(p: &std::path::Path) -> &str {
    p.to_str().expect("utf-8 path")
}

/// The `stream_event` sequence numbers on stdout, in arrival order.
fn stream_seq(h: &mut Harness) -> Vec<u64> {
    h.out_json().iter().filter(|v| v["type"] == "stream_event").filter_map(|v| v["n"].as_u64()).collect()
}

/// Wait (at most [`VM_END`]) until `path` reads `want`: on the remote link
/// the shim's ladder may signal the CLI after the wrapper is gone.
fn wait_file(h: &mut Harness, what: &str, path: &std::path::Path, want: &str) {
    h.wait_until(what, VM_END, |_| std::fs::read_to_string(path).unwrap_or_default() == want);
}

on_links!(
    /// The child exits by itself at the host's EOF: exit 0 well within the budget.
    eof_honoured_exits_within_1500ms,
    |link| {
        let _g = serial();
        let mut h = Harness::spawn_on(link, "local-child", &[], &[]);
        h.send_initialize();
        h.expect_out(is_init, T);
        h.close_stdin();
        let (status, took) = h.wait(WAIT);
        eprintln!("eof_honoured_exits_within_1500ms ({link:?}): EOF -> exit {} ms", took.as_millis());
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
        assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{}", h.transcript());
        let rows = h.census();
        assert_eq!(rows.len(), 2, "{rows:#?}");
        assert!(rows[1]["end"].is_u64(), "the second row carries end: {}", rows[1]);
        assert_eq!(rows[1]["exit"], 0, "{}", rows[1]);
        let note = rows[1]["note"].as_str().unwrap_or_default();
        assert!(note_has(note, "end:eof"), "{note}");
        h.assert_remote_end(link);
    }
);

on_links!(
    /// A child that ignores EOF and SIGTERM: the last rung (SIGKILL, on the
    /// remote link `detach{final}`, after which the shim's ladder kills it)
    /// ends the session with 0 within the budget.
    eof_ignored_child_is_killed_within_1500ms,
    |link| {
        let _g = serial();
        let mut h = Harness::spawn_on(link, "local-child", &[], &[("FAKE_IGNORE_EOF", "1"), ("FAKE_IGNORE_TERM", "1")]);
        h.send_initialize();
        h.expect_out(is_init, T);
        h.close_stdin();
        let (status, took) = h.wait(WAIT);
        eprintln!("eof_ignored_child_is_killed_within_1500ms ({link:?}): EOF -> exit {} ms", took.as_millis());
        assert_eq!(status.code(), Some(0), "a child killed by the EOF ladder still ends the session with 0\n{}", h.transcript());
        assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{}", h.transcript());
        let note = h.end_note();
        assert!(note_has(&note, "end:eof_kill"), "{note}");
        assert_eq!(h.end_row()["exit"], 0);
        h.assert_remote_end(link);
    }
);

on_links!(
    /// The EOF ladder's middle rung: the child ignores EOF but not SIGTERM, so
    /// the SIGTERM at +800 ms ends it (never the SIGKILL at +1200 ms). The
    /// remote ladder has no TERM rung after EOF (L2): `detach{final}` at
    /// +1200 ms ends the session (`end:eof_kill`), and the shim's ladder then
    /// sends the CLI its one SIGTERM.
    eof_ladder_sigterm_rung,
    |link| {
        let _g = serial();
        let p = Harness::prepare();
        let term_log = p.root.join("term.log");
        let mut h = p.spawn_on(link, "local-child", &[], &[("FAKE_IGNORE_EOF", "1"), ("FAKE_TERM_LOG", path_str(&term_log))]);
        h.send_initialize();
        h.expect_out(is_init, T);
        h.close_stdin();
        let (status, took) = h.wait(WAIT);
        eprintln!("eof_ladder_sigterm_rung ({link:?}): EOF -> exit {} ms (SIGTERM rung at 800 ms, the remote detach at 1200 ms), code {:?}", took.as_millis(), status.code());
        let transcript = h.transcript();
        assert!(took >= Duration::from_millis(700), "the child ignored EOF, so only the SIGTERM rung (+800 ms) could end it; took {took:?}\n{transcript}");
        if link.is_remote() {
            assert!(took >= REMOTE_DETACH_AFTER - Duration::from_millis(100), "only the detach rung (+1200 ms) could end it; took {took:?}\n{transcript}");
        }
        assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{transcript}");
        if link.is_remote() {
            // The shim's ladder sends it after the wrapper is gone; a local child's trap ran before the exit.
            wait_file(&mut h, "the child's TERM trap ran", &term_log, "TERM\n");
        }
        assert_eq!(std::fs::read_to_string(&term_log).unwrap_or_default(), "TERM\n", "the child got exactly one SIGTERM\n{transcript}");
        let note = h.end_note();
        assert!(note_has(&note, if link.is_remote() { "end:eof_kill" } else { "end:eof" }), "{note}");
        assert_eq!(status.code(), Some(0), "a child ended by the EOF ladder ends the session with 0\n{transcript}");
        assert_eq!(h.end_row()["exit"], 0, "{}", h.end_row());
        h.assert_remote_end(link);
    }
);

on_links!(
    /// SIGTERM to the wrapper reaches the child at once: its trap's code
    /// (on the remote link the detach's 143), within the budget. On the
    /// remote link the trap ran within half the shim's `LADDER_TERM_AFTER`
    /// of the SIGTERM: the stop's own `Signal(Term)` (L2), never the TERM the
    /// shim's ladder sends after `detach{final}`.
    sigterm_is_forwarded_and_exits_within_1000ms,
    |link| {
        let _g = serial();
        let p = Harness::prepare();
        let term_log = p.root.join("term.log");
        let mut h = p.spawn_on(link, "local-child", &[], &[("FAKE_TERM_LOG", path_str(&term_log))]);
        h.send_initialize();
        h.expect_out(is_init, T);
        let signalled = Instant::now();
        h.sigterm();
        let (status, took) = h.wait(WAIT);
        eprintln!("sigterm_is_forwarded_and_exits_within_1000ms ({link:?}): SIGTERM -> exit {} ms", took.as_millis());
        assert!(took < SIGTERM_BUDGET, "SIGTERM -> exit took {took:?} (budget {SIGTERM_BUDGET:?})\n{}", h.transcript());
        if link.is_remote() {
            let within = (ai_env_cli::wire::frame::LADDER_TERM_AFTER / 2).saturating_sub(signalled.elapsed());
            h.wait_until("the forwarded TERM reached the CLI before the shim's ladder could send one", within, |_| std::fs::read_to_string(&term_log).unwrap_or_default() == "TERM\n");
        }
        assert_eq!(std::fs::read_to_string(&term_log).unwrap_or_default(), "TERM\n", "the child got exactly one SIGTERM\n{}", h.transcript());
        assert_eq!(status.code(), Some(143), "the child's own code (its trap exits 143)\n{}", h.transcript());
        let note = h.end_note();
        assert!(note_has(&note, "end:sigterm"), "{note}");
        h.assert_remote_end(link);
    }
);

on_links!(
    /// The SIGTERM ladder's last rung: the child ignores SIGTERM, so the SIGKILL
    /// at +600 ms ends it. On the remote link that rung is the shim's, after
    /// the wrapper is gone (L2): the wrapper exits 143 at once, and the shim
    /// kills the CLI (nothing is left on the VM).
    sigterm_ladder_sigkill_rung,
    |link| {
        let _g = serial();
        let mut h = Harness::spawn_on(link, "local-child", &[], &[("FAKE_IGNORE_TERM", "1")]);
        h.send_initialize();
        h.expect_out(is_init, T);
        h.sigterm();
        let (status, took) = h.wait(WAIT);
        eprintln!("sigterm_ladder_sigkill_rung ({link:?}): SIGTERM -> exit {} ms (SIGKILL rung at 600 ms), code {:?}", took.as_millis(), status.code());
        let transcript = h.transcript();
        if !link.is_remote() {
            assert!(took >= Duration::from_millis(550), "the child ignored SIGTERM, so only the SIGKILL rung (+600 ms) could end it; took {took:?}\n{transcript}");
        }
        assert!(took < SIGTERM_BUDGET, "SIGTERM -> exit took {took:?} (budget {SIGTERM_BUDGET:?})\n{transcript}");
        let note = h.end_note();
        assert!(note_has(&note, "end:sigterm"), "{note}");
        let code = if link.is_remote() { 143 } else { 128 + 9 };
        assert_eq!(status.code(), Some(code), "the child died of SIGKILL: 128 + 9 (the remote link's detach: 143)\n{transcript}");
        h.assert_remote_end(link);
    }
);

on_links!(
    /// The pump form of the lab exit knob: after the init the child is
    /// stopped, its stderr copied, and the lab message is the last stderr
    /// line. On the remote link the stop detaches at once (L2): the CLI's
    /// last words after its TERM are not awaited.
    #[cfg(debug_assertions)]
    lab_exit_after_init,
    |link| {
        let _g = serial();
        let mut h = Harness::spawn_on(
            link,
            "local-child",
            &[],
            &[("AI_ENV_BRIDGE_LAB_EXIT", "3:boom:after-init"), ("FAKE_STDERR", "fake-start"), ("FAKE_TERM_STDERR", "fake-term")],
        );
        h.send_initialize();
        let (status, took) = h.wait(WAIT);
        eprintln!("lab_exit_after_init ({link:?}): spawn -> exit {} ms", took.as_millis());
        let transcript = h.transcript();
        assert_eq!(status.code(), Some(3), "{transcript}");
        let err = h.err_text();
        let lines: Vec<&str> = err.lines().collect();
        assert!(lines.contains(&"fake-start"), "the child's stderr is copied\n{transcript}");
        let boom_at = lines.iter().rposition(|l| *l == "boom").unwrap_or_else(|| panic!("no boom on stderr\n{transcript}"));
        match lines.iter().position(|l| *l == "fake-term") {
            Some(term_at) => assert!(term_at < boom_at, "the child's last words (line {term_at}) come before the lab message (line {boom_at})\n{transcript}"),
            None => assert!(link.is_remote(), "the child's TERM-trap line is missing from stderr\n{transcript}"),
        }
        let last = lines.iter().rev().find(|l| !l.trim().is_empty()).copied();
        assert_eq!(last, Some("boom"), "the lab message is the last stderr line\n{transcript}");
        assert_eq!(h.spawn_count(), 1, "no relaunch\n{transcript}");
        assert_eq!(h.out_matching(is_init).len(), 1, "{transcript}");
        let pid = h.fake_pid(1).unwrap_or_else(|| panic!("the fake logged no pid: {:?}", h.env_log()));
        let end = h.end_row();
        assert!(note_has(end["note"].as_str().unwrap_or_default(), "end:lab_exit"), "{end}");
        assert_eq!(end["exit"], 3, "{end}");
        // On the remote link the shim's ladder ends its CLI after the wrapper (awaited here).
        h.assert_remote_end(link);
        assert!(!pid_alive(pid), "the fake (pid {pid}) outlived the wrapper\n{transcript}");
    }
);

on_links!(
    /// The lab's stdout noise goes to stderr and the log, never to stdout.
    #[cfg(debug_assertions)]
    stdout_noise_never_reaches_stdout,
    |link| {
        let _g = serial();
        let mut h = Harness::spawn_on(link, "local-child", &[], &[("AI_ENV_BRIDGE_LAB_STDOUT_NOISE", "1")]);
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
        h.assert_remote_end(link);
    }
);

on_links!(
    /// The init-delay knob holds the `initialize` answer, and EOF during the
    /// delay still ends the session within the EOF budget. On the remote
    /// link the hold starts at the spawn's `Started`, after a pending start
    /// that alone outlasts the delay: it is measured from the VM's CLI
    /// reading the `initialize` (at `Started`, give or take the CLI's own
    /// start), and the EOF comes after that read, during the hold.
    #[cfg(debug_assertions)]
    delay_init_holds_the_init_response,
    |link| {
        let _g = serial();
        let mut h = Harness::spawn_on(link, "local-child", &[], &[("AI_ENV_BRIDGE_LAB_DELAY_INIT_MS", "300")]);
        let id = h.send_initialize();
        let since = if link.is_remote() {
            h.wait_until("the VM's CLI read the initialize", T, |h| !h.stdin_of(1).is_empty());
            Instant::now()
        } else {
            h.started
        };
        let (_, at) = h.expect_out_at(|v| is_response_to(v, &id), T);
        let after = at.saturating_duration_since(since);
        // What is left of the remote hold once the CLI read the line, with room for a loaded Mac.
        let (from, hold) = if link.is_remote() { ("the CLI's read", Duration::from_millis(150)) } else { ("spawn", Duration::from_millis(300)) };
        eprintln!("delay_init_holds_the_init_response ({link:?}): {from} -> initialize response {} ms (delay 300)", after.as_millis());
        assert!(after >= hold, "the initialize response arrived {after:?} after {from} (< {hold:?})\n{}", h.transcript());
        h.close_stdin();
        let (status, _) = h.wait(WAIT);
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
        let init_ms = note_number(&h.end_note(), "init_ms");
        eprintln!("delay_init_holds_the_init_response ({link:?}): end row init_ms = {init_ms:?}");
        h.assert_remote_end(link);

        // EOF during a long delay still ends the session within the EOF budget.
        let mut h = Harness::spawn_on(link, "local-child", &[], &[("AI_ENV_BRIDGE_LAB_DELAY_INIT_MS", "5000")]);
        h.send_initialize();
        if link.is_remote() {
            // Not during the pending start (`a_pending_remote_start_closes_within_budget`'s case).
            h.wait_until("the VM's CLI read the initialize", T, |h| !h.stdin_of(1).is_empty());
        }
        h.close_stdin();
        let (status, took) = h.wait(WAIT);
        eprintln!("delay_init_holds_the_init_response ({link:?}): EOF during a 5000 ms delay -> exit {} ms", took.as_millis());
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
        assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{}", h.transcript());
        h.assert_remote_end(link);
    }
);

on_links!(
    /// Lines are split at the CLI's own limit (256 MiB), not at 4 MiB (the
    /// line cap S2 first planned for the wire): a 5 MiB user line reaches the
    /// child and a 5 MiB child line reaches the host, both byte for byte (on
    /// the remote link through the shim's chunks, re-split into lines).
    large_lines_pass_intact,
    |link| {
        let _g = serial();
        const BIG: usize = 5 * 1024 * 1024 + 1;
        let p = Harness::prepare();
        let big_out = format!(r#"{{"type":"stream_event","event":{{"type":"content_block_delta"}},"pad":"{}"}}"#, "y".repeat(BIG));
        let file = p.write_file("big-stdout.ndjson", &format!("{big_out}\n"));
        let mut h = p.spawn_on(link, "local-child", &[], &[("FAKE_STDOUT_FILE", path_str(&file))]);
        h.send_initialize();
        h.expect_out(is_init, T);
        let text = "x".repeat(BIG);
        let t = Instant::now();
        let u = h.send_user(&text);
        h.expect_out(|v| is_result_for(v, &u), T);
        eprintln!("large_lines_pass_intact ({link:?}): {} byte user line -> its result {} ms", Harness::user_line(&u, &text).len(), t.elapsed().as_millis());
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
        h.assert_remote_end(link);
    }
);

on_links!(
    /// D3: a stalled host stdout never stops the host → child direction. The
    /// fake streams from a background subshell (`FAKE_STREAM_BG`) so its main
    /// loop keeps reading stdin while every buffer towards the host is full.
    /// On the remote link the lines are padded past the shim's 8 MiB stdout
    /// window, so the stall reaches the VM's CLI too; the measurement starts
    /// once the CLI has read the `initialize` (after the pending start).
    backpressure_survives_a_stalled_host_reader,
    |link| {
        let _g = serial();
        const LINES: u64 = 20_000;
        let n = LINES.to_string();
        let mut envs = vec![("FAKE_STREAM_LINES", n.as_str()), ("FAKE_STREAM_BG", "1")];
        if link.is_remote() {
            envs.push(("FAKE_STREAM_PAD", REMOTE_PAD));
        }
        let mut h = Harness::spawn_on(link, "local-child", &[], &envs);
        h.pause_stdout();
        let t = Instant::now();
        h.send_initialize();
        if link.is_remote() {
            h.wait_until("the VM's CLI read the initialize", T, |h| !h.stdin_of(1).is_empty());
        }
        // Let the stream (≈ 600 KB; padded on the remote link) fill every pipe and channel between the fake and the harness.
        std::thread::sleep(Duration::from_millis(300));
        let text = "sent during the stall";
        let u = h.send_user(text);
        let line = Harness::user_line(&u, text);
        h.wait_until("the user line reaches the child while the host's stdout is stalled", Duration::from_secs(10), |h| h.stdin_of(1).contains(&line));
        let reached = t.elapsed();
        assert!(h.seen_out.len() < 10, "the harness read nothing during the stall: {} lines", h.seen_out.len());
        eprintln!("backpressure_survives_a_stalled_host_reader ({link:?}): the user line reached the child {} ms into the stall", reached.as_millis());
        h.resume_stdout();
        h.expect_out(|v| v["type"] == "stream_event" && v["n"] == LINES, T);
        h.expect_out(|v| is_result_for(v, &u), T);
        eprintln!("backpressure_survives_a_stalled_host_reader ({link:?}): stall + drain {} ms", t.elapsed().as_millis());
        h.close_stdin();
        let (status, _) = h.wait(WAIT);
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
        let seq = stream_seq(&mut h);
        assert_eq!(seq.len() as u64, LINES, "every stream_event line arrived");
        assert!(seq.iter().copied().eq(1..=LINES), "in order");
        assert_eq!(h.out_matching(|v| is_result_for(v, &u)).len(), 1);
        h.assert_remote_end(link);
    }
);

on_links!(
    /// A SIGTERM is honoured while the host's stdout is stalled (on the
    /// remote link with the shim's stdout window full too: the stop's frames
    /// still go out).
    sigterm_is_honoured_while_host_stdout_is_stalled,
    |link| {
        let _g = serial();
        let mut envs = vec![("FAKE_STREAM_LINES", "20000")];
        if link.is_remote() {
            envs.push(("FAKE_STREAM_PAD", REMOTE_PAD));
        }
        let mut h = Harness::spawn_on(link, "local-child", &[], &envs);
        h.pause_stdout();
        h.send_initialize();
        h.wait_until("the fake read the initialize", T, |h| !h.stdin_of(1).is_empty());
        // The stream (≈ 600 KB; padded on the remote link) fills every pipe and channel towards the stalled host.
        std::thread::sleep(Duration::from_millis(300));
        h.sigterm();
        let (status, took) = h.wait_exit(WAIT);
        h.resume_stdout();
        let _ = h.wait(WAIT);
        eprintln!("sigterm_is_honoured_while_host_stdout_is_stalled ({link:?}): SIGTERM -> exit {} ms, code {:?}", took.as_millis(), status.code());
        assert!(took < SIGTERM_BUDGET, "SIGTERM -> exit took {took:?} (budget {SIGTERM_BUDGET:?})\n{}", h.transcript());
        let note = h.end_note();
        assert!(note_has(&note, "end:sigterm"), "{note}");
        h.assert_remote_end(link);
    }
);

on_links!(
    /// The lab knob that ignores the host's EOF: the SIGTERM after it ends
    /// the session and the end row records the gap.
    #[cfg(debug_assertions)]
    ignore_eof_records_eof_to_sigterm,
    |link| {
        let _g = serial();
        let mut h = Harness::spawn_on(link, "local-child", &[], &[("AI_ENV_BRIDGE_LAB_IGNORE_EOF", "1")]);
        h.send_initialize();
        h.expect_out(is_init, T);
        h.close_stdin();
        std::thread::sleep(Duration::from_millis(300));
        h.sigterm();
        let (status, took) = h.wait(WAIT);
        eprintln!("ignore_eof_records_eof_to_sigterm ({link:?}): SIGTERM -> exit {} ms", took.as_millis());
        assert!(took < SIGTERM_BUDGET, "SIGTERM -> exit took {took:?} (budget {SIGTERM_BUDGET:?})\n{}", h.transcript());
        assert_eq!(status.code(), Some(143), "the child dies of SIGTERM: 128 + 15\n{}", h.transcript());
        let note = h.end_note();
        assert!(note_has(&note, "end:sigterm"), "{note}");
        let ms = note_number(&note, "eof_to_sigterm_ms").unwrap_or_else(|| panic!("no eof_to_sigterm_ms in {note}"));
        eprintln!("ignore_eof_records_eof_to_sigterm ({link:?}): eof_to_sigterm_ms = {ms}");
        assert!((250..=1000).contains(&ms), "eof_to_sigterm_ms = {ms}, expected about 300");
        h.assert_remote_end(link);
    }
);

on_links!(
    /// A host EOF while the respawned child has not answered the replay yet
    /// starts the EOF ladder at once (the replay window never holds it).
    eof_during_replay_window_exits_within_budget,
    |link| {
        let _g = serial();
        let p = Harness::prepare();
        let sid = uuid(0x5e55_0101);
        p.plant_transcript(&sid, &[r#"{"type":"user","message":{"role":"user","content":"earlier"}}"#]);
        let marker = p.root.join("resume.marker");
        let resume = format!("--resume={sid}");
        let mut h = p.spawn_on(link, "local-scratch", &[&resume], &[("FAKE_RESUME_FAIL_ONCE", path_str(&marker)), ("FAKE_IGNORE_CONTROL_GEN", "2")]);
        let init_id = h.send_initialize();
        h.wait_until("generation 2 read the replayed initialize", T, |h| h.stdin_of(2).iter().any(|l| l.contains(r#""subtype":"initialize""#)));
        h.close_stdin();
        let (status, took) = h.wait(WAIT);
        eprintln!("eof_during_replay_window_exits_within_budget ({link:?}): EOF -> exit {} ms", took.as_millis());
        let transcript = h.transcript();
        assert_eq!(status.code(), Some(0), "{transcript}");
        assert!(took < EOF_BUDGET, "EOF -> exit took {took:?} (budget {EOF_BUDGET:?})\n{transcript}");
        assert!(note_has(&h.end_note(), "end:eof"), "{}", h.end_note());
        assert_eq!(h.spawn_count(), 2, "{transcript}");
        assert!(!h.stdin_of(2)[0].contains(&init_id), "gen 2 got a fresh request id: {}", h.stdin_of(2)[0]);
        h.assert_remote_end(link);
    }
);

on_links!(
    /// The host closes its read end of the wrapper's stdout and keeps writing:
    /// the next forwarded line fails with EPIPE and the session ends with 0.
    host_gone_ends_the_session,
    |link| {
        let _g = serial();
        let mut h = Harness::spawn_on(link, "local-child", &[], &[]);
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
        eprintln!("host_gone_ends_the_session ({link:?}): stdout closed -> exit {} ms ({n} user lines sent)", took.as_millis());
        let transcript = h.transcript();
        assert_eq!(status.code(), Some(0), "{transcript}");
        assert!(took < EOF_BUDGET, "stdout closed -> exit took {took:?} (budget {EOF_BUDGET:?})\n{transcript}");
        let note = h.end_note();
        assert!(["end:eof", "end:eof_kill", "end:host_gone"].iter().any(|p| note_has(&note, p)), "{note}");
        assert_eq!(h.end_row()["exit"], 0, "{}", h.end_row());
        h.assert_remote_end(link);
    }
);

on_links!(
    /// The child exits on its own while the host is not reading: the host still
    /// gets every line once it reads again (up to 5 s), the last one included.
    /// The lines are 32 KiB each, so they cannot all sit in the host pipe: most
    /// wait in the pump when the child's exit is seen.
    slow_host_after_child_exit_gets_every_line,
    |link| {
        let _g = serial();
        const LINES: u64 = 40;
        let n = LINES.to_string();
        let mut h = Harness::spawn_on(link, "local-child", &[], &[("FAKE_STREAM_LINES", &n), ("FAKE_STREAM_PAD", "32768"), ("FAKE_EXIT_AFTER_STREAM", "1")]);
        h.send_initialize();
        h.expect_out(is_init, T);
        h.pause_stdout();
        std::thread::sleep(Duration::from_secs(1));
        let running = !h.exited_now();
        h.resume_stdout();
        let (status, _) = h.wait(WAIT);
        eprintln!("slow_host_after_child_exit_gets_every_line ({link:?}): wrapper still running after the 1 s stall: {running}");
        let transcript = h.transcript();
        assert_eq!(status.code(), Some(0), "{transcript}");
        let seq = stream_seq(&mut h);
        assert_eq!(seq.last().copied(), Some(LINES), "the last line arrived: {} of {LINES} lines\n{transcript}", seq.len());
        assert!(seq.iter().copied().eq(1..=LINES), "every line, in order: {} of {LINES}", seq.len());
        let note = h.end_note();
        assert!(note_has(&note, "end:child_exit"), "{note}");
        h.assert_remote_end(link);
    }
);

/// S8 §2, the remote link only (a local child has no pending start): the
/// host's EOF, or a SIGTERM, while the start is pending (here a Touch ID
/// that never answers) cancels it within the same budgets: the dialog's
/// process group ends with it, no VM is started and no spawn goes out.
/// After the EOF the wrapper exits 0 and says nothing more; after the
/// SIGTERM 143, its one last line saying nothing was started.
#[cfg(feature = "shim")]
#[test]
fn a_pending_remote_start_closes_within_budget() {
    let _g = serial();
    for sigterm in [false, true] {
        let p = Harness::prepare();
        let pidfile = p.root.join("age.pid");
        let mut h = p.spawn_on(common::Link::Remote, "", &[], &[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", path_str(&pidfile))]);
        h.send_initialize();
        let mut dialog = 0;
        h.wait_until("the Touch ID dialog is up", T, |_| {
            dialog = std::fs::read_to_string(&pidfile).ok().and_then(|s| s.trim().parse::<i32>().ok()).unwrap_or(0);
            dialog > 0
        });
        if sigterm {
            h.sigterm();
        } else {
            h.close_stdin();
        }
        let (status, took) = h.wait(WAIT);
        let (budget, code, end) = if sigterm { (SIGTERM_BUDGET, 143, "end:sigterm") } else { (EOF_BUDGET, 0, "end:eof") };
        eprintln!("a_pending_remote_start_closes_within_budget (sigterm {sigterm}): close -> exit {} ms", took.as_millis());
        let transcript = h.transcript();
        assert_eq!(status.code(), Some(code), "{transcript}");
        assert!(took < budget, "close -> exit took {took:?} (budget {budget:?})\n{transcript}");
        let note = h.end_note();
        assert!(note_has(&note, end) && !note.contains("step:"), "a cancelled start names no step: {note}");
        let err = h.err_text();
        let (last, before) = err.lines().collect::<Vec<_>>().split_last().map(|(l, b)| (*l, b.to_vec())).unwrap_or_default();
        let countdown = |l: &&str| l.starts_with("ai-env-claude: waiting for Touch ID");
        if sigterm {
            assert_eq!(last, "ai-env-claude: stopped before the session started: nothing was started; reopen the chat to start it", "{err}");
            assert!(before.iter().all(countdown), "{err}");
        } else {
            assert!(countdown(&last) && before.iter().all(countdown), "a host that closed is told nothing: {err}");
        }
        assert_eq!(h.spawn_count(), 0, "no spawn went out\n{transcript}");
        assert!(!h.rig().fake_calls().iter().any(|c| matches!(c, ai_env_cli::bridge::api::Call::Run { .. })), "no VM was started: {:?}", h.rig().fake_calls());
        // SAFETY: killpg(2) with signal 0 only checks for the fake age's group.
        h.wait_until("the dialog's process group ended", VM_END, |_| unsafe { libc::killpg(dialog, 0) } != 0);
        h.assert_remote_end(common::Link::Remote);
    }
}
