//! Every wait on a child bounded (S8 part A's rule, plans/s8-plan.md: "every
//! wait bounded"): a command run to its end within a limit, its stdout and
//! stderr read on threads meanwhile, so neither pipe fills; past the limit
//! the child is killed and the test fails naming it. The readers are bounded
//! too: a descendant that keeps a pipe open after the child's exit fails the
//! test instead of hanging it (and with it the gate, or a mutant run). Std
//! only and in every feature set: shared through `tests/common/mod.rs`, and
//! by `tests/wrapper_install.rs`, which has no `common`, through `#[path]`.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How often a running child is looked at in its first [`POLL_FINE_FOR`]:
/// a short run's end is seen within a millisecond (a perf test times it).
const POLL_FINE: Duration = Duration::from_millis(1);
/// How long a child is looked at every [`POLL_FINE`].
const POLL_FINE_FOR: Duration = Duration::from_millis(200);
/// How often it is looked at after that.
const POLL: Duration = Duration::from_millis(20);
/// How long the readers may take past the child's exit when its limit is
/// already up (a pipe drains in far less once its writers are gone).
const DRAIN_AFTER_EXIT: Duration = Duration::from_secs(1);

/// `cmd` run to its end within `limit`, `stdin` written to it (`None`:
/// /dev/null, as `Command::output` gives), its stdout and stderr captured:
/// its output ([`finish_within`]'s bounds; `what` names it in a failure).
pub fn run_within(mut cmd: Command, stdin: Option<&[u8]>, limit: Duration, what: &str) -> Output {
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    if let (Some(bytes), Some(mut sink)) = (stdin, child.stdin.take()) {
        let bytes = bytes.to_vec();
        // A child that never reads must not block the wait: the write runs on its own thread.
        std::thread::spawn(move || {
            let _ = sink.write_all(&bytes);
        });
    }
    finish_within(child, limit, what)
}

/// `child` waited for within `limit` (from now), its piped stdout and
/// stderr read meanwhile (one that is not piped reads empty): its output.
/// Past `limit` it is killed and reaped, and the test fails naming `what`;
/// its readers may take until `limit`, or [`DRAIN_AFTER_EXIT`] past its
/// exit when that is later, else the test fails naming the stream.
pub fn finish_within(mut child: Child, limit: Duration, what: &str) -> Output {
    let out = child.stdout.take().map(read_all);
    let err = child.stderr.take().map(read_all);
    let started = Instant::now();
    let until = started + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => panic!("{what}: waiting for it: {e}"),
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} ran past {limit:?} (killed)");
        }
        std::thread::sleep(if started.elapsed() < POLL_FINE_FOR { POLL_FINE } else { POLL });
    };
    let drained = until.max(Instant::now() + DRAIN_AFTER_EXIT);
    let collect = |rx: Option<mpsc::Receiver<Vec<u8>>>, stream: &str| match rx {
        None => Vec::new(),
        Some(rx) => rx.recv_timeout(drained.saturating_duration_since(Instant::now())).unwrap_or_else(|_| panic!("{what} exited ({status}), but its {stream} stayed open: a process it left holds it")),
    };
    Output { status, stdout: collect(out, "stdout"), stderr: collect(err, "stderr") }
}

/// Read `r` to its end on a thread of its own: the bytes, sent once done.
fn read_all(mut r: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = r.read_to_end(&mut bytes);
        let _ = tx.send(bytes);
    });
    rx
}
