//! Shared harness of the S2 pump tests (`tests/hoststate.rs`, `tests/mirror.rs`,
//! `tests/race.rs`) and of the fake cache `tests/wrapper.rs` uses; not a
//! test target of its own. std only: the wrapper is spawned with
//! `std::process::Command` and piped stdio, two reader threads feed one
//! channel of stdout/stderr lines, and every file the run leaves (census,
//! audit, registry, the fake's logs) lives under one tempdir.
//!
//! The child is always `tests/fakes/claude-v2.sh`, hard-linked into the
//! tempdir as `claude` (see [`fake_master`]) and passed as argv[1]: the
//! developer's real `claude` is never run.
//! The tempdir is canonicalized up front (`/var` → `/private/var` on macOS),
//! so `HOME`, the projects root and every `filePath` agree lexically — as they
//! do under a real `HOME`.
#![allow(dead_code)]

use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The fake child, hard-linked into every harness tempdir as `claude` (0755).
pub const FAKE_V2: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/claude-v2.sh");
/// The S1 exec fake (`tests/wrapper.rs`), hard-linked the same way.
pub const FAKE_V1: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/claude.sh");

/// The session argv of extension 2.1.282's chat spawn.
pub const SESSION_ARGV: [&str; 16] = [
    "--output-format",
    "stream-json",
    "--verbose",
    "--input-format",
    "stream-json",
    "--permission-prompt-tool",
    "stdio",
    "--setting-sources=user,project,local",
    "--permission-mode",
    "default",
    "--include-partial-messages",
    "--debug",
    "--debug-to-stderr",
    "--enable-auth-status",
    "--no-chrome",
    "--replay-user-messages",
];

/// Variables a developer's shell may carry that would steer the wrapper or
/// the fake; removed from every harness run before the test's own `envs`.
pub const REMOVED_ENV: [&str; 39] = [
    "AI_ENV_BRIDGE_LOCAL",
    "AI_ENV_BRIDGE_LAB_EXIT",
    "AI_ENV_BRIDGE_CONFIG",
    "AI_ENV_BRIDGE_MODE",
    "AI_ENV_BRIDGE_MIRROR_ROOT",
    "AI_ENV_BRIDGE_LAB_IGNORE_EOF",
    "AI_ENV_BRIDGE_LAB_STDOUT_NOISE",
    "AI_ENV_BRIDGE_LAB_DELAY_INIT_MS",
    "AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS",
    "AI_ENV_BRIDGE_LAB_FAKE_API",
    "AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL",
    "AI_ENV_BRIDGE_LAB_BACKOFF_MS",
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_PROJECT_DIR_NAME",
    "CLAUDE_SECURESTORAGE_CONFIG_DIR",
    "RUST_LOG",
    "FAKE_SESSION_ID",
    "FAKE_RESUME_FAIL_ONCE",
    "FAKE_RESUME_FAIL_AFTER_ACK",
    "FAKE_MISS_AFTER_INIT",
    "FAKE_IGNORE_CONTROL_GEN",
    "FAKE_EXIT_AFTER_INIT",
    "FAKE_STDOUT_FILE",
    "FAKE_STREAM_LINES",
    "FAKE_STREAM_PAD",
    "FAKE_STREAM_BG",
    "FAKE_EXIT_AFTER_STREAM",
    "FAKE_OAUTH_REFRESH",
    "FAKE_NEW_SESSION_AFTER",
    "FAKE_IGNORE_EOF",
    "FAKE_IGNORE_TERM",
    "FAKE_TERM_LOG",
    "FAKE_TERM_STDERR",
    "FAKE_HOLD_STDERR_MS",
    "FAKE_EXIT",
    "FAKE_STDERR",
    "FAKE_STDOUT",
    "FAKE_ECHO_STDIN",
];

/// A canonical-shape uuid built from a counter (no uuid literal in the sources).
#[must_use]
pub fn uuid(n: u64) -> String {
    format!("{n:08x}-0000-4000-8000-{n:012x}")
}

/// The fake's session id when neither `FAKE_SESSION_ID` nor `--resume` is given.
#[must_use]
pub fn fake_fixed_sid() -> String {
    uuid(3054)
}

/// The `session_id` the fake puts in its resume-miss frame (a different uuid).
#[must_use]
pub fn fake_other_sid() -> String {
    uuid(57005)
}

/// The session id the fake switches to after `FAKE_NEW_SESSION_AFTER` turns (`/clear`).
#[must_use]
pub fn fake_clear_sid() -> String {
    uuid(49642)
}

/// `key=<value>` of one fake env-log line (`gen 1 CLAUDE_CONFIG_DIR=… SECURESTORAGE=… pid=…`).
#[must_use]
pub fn env_log_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(' ').find_map(|part| part.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

/// Does a process with this pid exist (a zombie counts)?
#[must_use]
pub fn pid_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else { return false };
    // SAFETY: kill(2) with signal 0 only checks for existence and permission.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// The fake's resume-miss `result` line, byte for byte.
#[must_use]
pub fn resume_miss_frame(resume: &str) -> String {
    format!(
        r#"{{"type":"result","subtype":"error_during_execution","duration_ms":0,"duration_api_ms":0,"is_error":true,"num_turns":0,"stop_reason":null,"session_id":"{}","total_cost_usd":0,"usage":{{}},"modelUsage":{{}},"permission_denials":[],"uuid":"x","errors":["No conversation found with session ID: {resume}"],"result_index":0}}"#,
        fake_other_sid()
    )
}

/// One captured line (without its `\n`; a `\r` is kept) or the end of a stream.
#[derive(Debug)]
pub enum Line {
    Out(String),
    Err(String),
    OutEof,
    ErrEof,
}

// ---- predicates over stdout frames -------------------------------------------------------

/// A `control_response` answering `id`.
#[must_use]
pub fn is_response_to(v: &Value, id: &str) -> bool {
    v["type"] == "control_response" && v["response"]["request_id"] == id
}

/// A `system`/`init` frame.
#[must_use]
pub fn is_init(v: &Value) -> bool {
    v["type"] == "system" && v["subtype"] == "init"
}

/// A `result` acknowledging the user line `uuid`.
#[must_use]
pub fn is_result_for(v: &Value, uuid: &str) -> bool {
    v["type"] == "result" && v["user_message_uuid"] == uuid
}

/// The `isReplay` echo of the user line `uuid`.
#[must_use]
pub fn is_echo_of(v: &Value, uuid: &str) -> bool {
    v["type"] == "user" && v["isReplay"] == true && v["uuid"] == uuid
}

// ---- before the spawn --------------------------------------------------------------------

/// The tempdir set up before the wrapper runs (fake copied, `work/` created),
/// so a test can plant transcripts and files first.
pub struct Prepared {
    pub tmp: tempfile::TempDir,
    /// The canonical tempdir path: the wrapper's `HOME`.
    pub root: PathBuf,
}

impl Default for Prepared {
    fn default() -> Self {
        Self::new()
    }
}

/// One 0755 copy of `src` per content under `CARGO_TARGET_TMPDIR/<cache>`,
/// which every harness hard-links as `<tmp>/claude`. macOS assesses the FIRST
/// exec of every new file (≈200 ms each, serialised system-wide: 30 fresh
/// copies exec'd at once took 6 s), which made a parallel test run's children
/// start seconds late; a hard link shares the inode, so only the master pays.
fn cached_executable(src: &str, cache: &str) -> PathBuf {
    use sha2::Digest;
    use std::os::unix::fs::PermissionsExt;
    let bytes = std::fs::read(src).unwrap_or_else(|e| panic!("read {src}: {e}"));
    let digest = hex::encode(sha2::Sha256::digest(&bytes));
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(cache);
    std::fs::create_dir_all(&dir).expect("mkdir the fake's cache dir");
    let path = dir.join(format!("claude-{}", &digest[..16]));
    if !path.exists() {
        let tmp = dir.join(format!(".claude-{}.{}.tmp", &digest[..16], std::process::id()));
        std::fs::write(&tmp, &bytes).expect("write the fake");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).expect("chmod the fake");
        std::fs::rename(&tmp, &path).expect("install the fake");
    }
    path
}

/// The cached master of fake v2 ([`FAKE_V2`]).
fn fake_master() -> &'static Path {
    static MASTER: OnceLock<PathBuf> = OnceLock::new();
    MASTER.get_or_init(|| cached_executable(FAKE_V2, "fake-claude-v2"))
}

/// The cached master of the S1 fake ([`FAKE_V1`]).
fn fake_v1_master() -> &'static Path {
    static MASTER: OnceLock<PathBuf> = OnceLock::new();
    MASTER.get_or_init(|| cached_executable(FAKE_V1, "fake-claude-v1"))
}

/// Hard-link `master` at `dest`; on another filesystem, copy `src` there (0755;
/// its first exec is then assessed).
fn link_fake(master: &Path, src: &str, dest: &Path) {
    if std::fs::hard_link(master, dest).is_err() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::copy(src, dest).unwrap_or_else(|e| panic!("copy {src}: {e}"));
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755)).expect("chmod fake");
    }
}

/// Put the S1 fake (`tests/fakes/claude.sh`) at `dest`, 0755, from the cache.
pub fn install_fake_v1(dest: &Path) {
    link_fake(fake_v1_master(), FAKE_V1, dest);
}

impl Prepared {
    #[must_use]
    pub fn new() -> Prepared {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize tempdir");
        link_fake(fake_master(), FAKE_V2, &root.join("claude"));
        std::fs::create_dir(root.join("work")).expect("mkdir work");
        Prepared { tmp, root }
    }

    /// The wrapper's cwd.
    #[must_use]
    pub fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    /// The picker's project directory name of the cwd.
    #[must_use]
    pub fn slug(&self) -> String {
        ai_env_cli::wire::slug::project_dir_name(&self.work()).expect("slug of the work dir")
    }

    /// `<HOME>/.claude/projects` — the Mac's projects root.
    #[must_use]
    pub fn mac_projects(&self) -> PathBuf {
        self.root.join(".claude").join("projects")
    }

    /// Plant `<HOME>/.claude/projects/<slug>/<uuid>.jsonl` holding `lines`, each + `\n`.
    pub fn plant_transcript(&self, uuid: &str, lines: &[&str]) -> PathBuf {
        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        self.plant_project_file(&format!("{uuid}.jsonl"), &text)
    }

    /// Plant `<HOME>/.claude/projects/<slug>/<rel>` with `text` (parents created).
    pub fn plant_project_file(&self, rel: &str, text: &str) -> PathBuf {
        let path = self.mac_projects().join(self.slug()).join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir project dir");
        std::fs::write(&path, text).expect("plant file");
        path
    }

    /// Write `<tmp>/<name>` with `text`.
    pub fn write_file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::write(&path, text).expect("write file");
        path
    }

    /// Spawn the wrapper: `ai-env-claude <tmp>/claude SESSION_ARGV… extra_args…`
    /// in `<tmp>/work`, `HOME=<tmp>`, `AI_ENV_BRIDGE_DIR=<tmp>/bridge`, the
    /// fake's logs under `<tmp>`, `AI_ENV_BRIDGE_MODE=mode` (unset for ""),
    /// [`REMOVED_ENV`] removed, then `envs` applied in order.
    pub fn spawn(self, mode: &str, extra_args: &[&str], envs: &[(&str, &str)]) -> Harness {
        let root = self.root.clone();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env-claude"));
        cmd.arg(root.join("claude")).args(SESSION_ARGV).args(extra_args).current_dir(root.join("work"));
        cmd.env("HOME", &root)
            .env("AI_ENV_BRIDGE_DIR", root.join("bridge"))
            .env("ARGV_LOG", root.join("argv.log"))
            .env("FAKE_STDIN_LOG", root.join("stdin.log"))
            .env("FAKE_ENV_LOG", root.join("env.log"))
            .env("FAKE_SPAWN_COUNT", root.join("spawn.count"));
        for k in REMOVED_ENV {
            cmd.env_remove(k);
        }
        if !mode.is_empty() {
            cmd.env("AI_ENV_BRIDGE_MODE", mode);
        }
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let started = Instant::now();
        let mut child = cmd.spawn().expect("spawn ai-env-claude");
        let stdin = child.stdin.take();
        let (tx, rx) = mpsc::channel();
        let ctl = Arc::new(ReaderCtl::default());
        let out = child.stdout.take().expect("piped stdout");
        let err = child.stderr.take().expect("piped stderr");
        let out_thread = {
            let tx = tx.clone();
            let ctl = ctl.clone();
            std::thread::spawn(move || read_stdout(out, &tx, &ctl))
        };
        std::thread::spawn(move || read_stderr(err, &tx));
        Harness {
            prepared: self,
            child,
            stdin,
            lines: rx,
            seen_out: Vec::new(),
            seen_err: Vec::new(),
            out_eof: false,
            err_eof: false,
            started,
            reference: None,
            exited: None,
            counter: 0,
            ctl,
            out_thread: Some(out_thread),
            sent: Vec::new(),
        }
    }
}

/// Steers the stdout reader thread.
#[derive(Default)]
struct ReaderCtl {
    /// While set the pipe is not read at all (the host stops reading: backpressure).
    paused: AtomicBool,
    /// Once set the thread drops its read end (the host is gone) and ends.
    close: AtomicBool,
}

/// Send the complete lines of `pending` (from `scan` on for the newline
/// search) and keep the incomplete tail.
fn emit_lines(pending: &mut Vec<u8>, scan: usize, tx: &mpsc::Sender<Line>, is_out: bool) -> bool {
    let mut from = 0;
    let mut at = scan;
    while let Some(i) = pending[at..].iter().position(|b| *b == b'\n') {
        let end = at + i;
        let text = String::from_utf8_lossy(&pending[from..end]).into_owned();
        if tx.send(if is_out { Line::Out(text) } else { Line::Err(text) }).is_err() {
            return false;
        }
        from = end + 1;
        at = from;
    }
    pending.drain(..from);
    true
}

/// The wrapper's stdout, split on `\n` (a `\r` stays) into `Line`s until
/// EOF. The pipe is polled so that a pause or a close takes effect within a
/// few ms even while no output arrives; while paused the pipe is not read.
fn read_stdout(mut stream: ChildStdout, tx: &mpsc::Sender<Line>, ctl: &ReaderCtl) {
    let fd = stream.as_raw_fd();
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = vec![0_u8; 8 * 1024];
    loop {
        if ctl.close.load(Ordering::SeqCst) {
            drop(stream);
            let _ = tx.send(Line::OutEof);
            return;
        }
        if ctl.paused.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: poll(2) on one valid pollfd we own, 5 ms timeout.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, 5) };
        if rc == 0 || (rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted) {
            continue;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let scan = pending.len();
                pending.extend_from_slice(&buf[..n]);
                if !emit_lines(&mut pending, scan, tx, true) {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if !pending.is_empty() {
        let _ = tx.send(Line::Out(String::from_utf8_lossy(&pending).into_owned()));
    }
    let _ = tx.send(Line::OutEof);
}

/// The wrapper's stderr, split like stdout, until EOF.
fn read_stderr(stream: impl Read, tx: &mpsc::Sender<Line>) {
    let mut reader = BufReader::new(stream);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if buf.last() == Some(&b'\n') {
                    buf.pop();
                }
                if tx.send(Line::Err(String::from_utf8_lossy(&buf).into_owned())).is_err() {
                    return;
                }
            }
        }
    }
    let _ = tx.send(Line::ErrEof);
}

// ---- the running wrapper -----------------------------------------------------------------

pub struct Harness {
    pub prepared: Prepared,
    pub child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<Line>,
    /// Every stdout line received so far, in order.
    pub seen_out: Vec<String>,
    /// Every stderr line received so far, in order.
    pub seen_err: Vec<String>,
    out_eof: bool,
    err_eof: bool,
    /// Just before the spawn.
    pub started: Instant,
    /// The last `close_stdin` / `sigterm` instant: what `wait` measures from.
    reference: Option<Instant>,
    exited: Option<(ExitStatus, Instant)>,
    counter: u64,
    ctl: Arc<ReaderCtl>,
    out_thread: Option<JoinHandle<()>>,
    /// Every line written to the wrapper's stdin (without `\n`).
    pub sent: Vec<String>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        // A paused reader would otherwise poll until the test binary exits.
        self.ctl.close.store(true, Ordering::SeqCst);
    }
}

impl Harness {
    /// A tempdir to plant files in before [`Prepared::spawn`].
    #[must_use]
    pub fn prepare() -> Prepared {
        Prepared::new()
    }

    /// `Harness::prepare().spawn(mode, extra_args, envs)`.
    pub fn spawn(mode: &str, extra_args: &[&str], envs: &[(&str, &str)]) -> Harness {
        Prepared::new().spawn(mode, extra_args, envs)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.prepared.root
    }

    #[must_use]
    pub fn bridge(&self) -> PathBuf {
        self.root().join("bridge")
    }

    #[must_use]
    pub fn slug(&self) -> String {
        self.prepared.slug()
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    fn next_n(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    /// Write `line` + `\n` to the wrapper's stdin.
    pub fn send(&mut self, line: &str) {
        if let Err(e) = self.try_send(line) {
            let mut len = line.len().min(200);
            while !line.is_char_boundary(len) {
                len -= 1;
            }
            panic!("write to the wrapper's stdin failed ({e}) for {:?}\n{}", &line[..len], self.transcript());
        }
    }

    /// [`Harness::send`] that reports a failed write (the wrapper may be gone).
    pub fn try_send(&mut self, line: &str) -> std::io::Result<()> {
        let Some(stdin) = self.stdin.as_mut() else { panic!("send after close_stdin: {line}") };
        stdin.write_all(line.as_bytes()).and_then(|()| stdin.write_all(b"\n")).and_then(|()| stdin.flush())?;
        self.sent.push(line.to_string());
        Ok(())
    }

    /// Send an `initialize` request; its (unique) request id.
    pub fn send_initialize(&mut self) -> String {
        let id = format!("init{:04}", self.next_n());
        self.send(&format!(r#"{{"request_id":"{id}","type":"control_request","request":{{"subtype":"initialize","hooks":{{}},"jsonSchema":null}}}}"#));
        id
    }

    /// Send `control_request{subtype, ...body}` (`body_json` is a JSON object
    /// whose members follow `subtype` in `request`); its request id.
    pub fn send_control(&mut self, subtype: &str, body_json: &str) -> String {
        let id = format!("req{:04}", self.next_n());
        let body = body_json.trim();
        assert!(body.starts_with('{') && body.ends_with('}'), "body must be a JSON object: {body}");
        let inner = body[1..body.len() - 1].trim();
        let request = if inner.is_empty() { format!(r#"{{"subtype":"{subtype}"}}"#) } else { format!(r#"{{"subtype":"{subtype}",{inner}}}"#) };
        self.send(&format!(r#"{{"request_id":"{id}","type":"control_request","request":{request}}}"#));
        id
    }

    /// The exact user line [`Harness::send_user`] writes for `uuid` and `text`.
    #[must_use]
    pub fn user_line(uuid: &str, text: &str) -> String {
        let content = serde_json::to_string(text).expect("json string");
        format!(r#"{{"type":"user","message":{{"role":"user","content":{content}}},"parent_tool_use_id":null,"session_id":"","uuid":"{uuid}"}}"#)
    }

    /// Send a user line with a fresh uuid; the uuid.
    pub fn send_user(&mut self, text: &str) -> String {
        let n = self.next_n();
        let u = uuid(0xa000 + n);
        self.send(&Self::user_line(&u, text));
        u
    }

    /// Close the wrapper's stdin (the extension's `stdin.end()`); `wait` measures from here.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
        self.reference = Some(Instant::now());
    }

    /// SIGTERM the wrapper; `wait` measures from here.
    pub fn sigterm(&mut self) {
        let pid = i32::try_from(self.pid()).expect("pid fits i32");
        self.reference = Some(Instant::now());
        // SAFETY: kill(2) on the pid of our own not-yet-reaped child.
        let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
        assert_eq!(rc, 0, "kill(SIGTERM) failed");
    }

    /// Stop reading the wrapper's stdout (the pipe fills; backpressure).
    pub fn pause_stdout(&self) {
        self.ctl.paused.store(true, Ordering::SeqCst);
    }

    pub fn resume_stdout(&self) {
        self.ctl.paused.store(false, Ordering::SeqCst);
    }

    /// Close the read end of the wrapper's stdout (the host is gone: its next
    /// write fails with EPIPE); returns once the fd is closed. `wait`
    /// measures from here.
    pub fn close_stdout(&mut self) {
        self.ctl.close.store(true, Ordering::SeqCst);
        if let Some(t) = self.out_thread.take() {
            t.join().expect("stdout reader thread");
        }
        self.reference = Some(Instant::now());
    }

    /// Poll `cond` (every few ms, taking the output that arrived) until it
    /// holds; panics with everything seen after `timeout`.
    pub fn wait_until(&mut self, what: &str, timeout: Duration, mut cond: impl FnMut(&mut Harness) -> bool) {
        let deadline = Instant::now() + timeout;
        loop {
            self.drain();
            if cond(self) {
                return;
            }
            if Instant::now() >= deadline {
                panic!("{what}: not within {timeout:?}\n{}", self.transcript());
            }
            std::thread::sleep(Duration::from_millis(3));
        }
    }

    fn absorb(&mut self, line: Line) {
        match line {
            Line::Out(s) => self.seen_out.push(s),
            Line::Err(s) => self.seen_err.push(s),
            Line::OutEof => self.out_eof = true,
            Line::ErrEof => self.err_eof = true,
        }
    }

    /// Take every line already received, without blocking.
    pub fn drain(&mut self) {
        while let Ok(line) = self.lines.try_recv() {
            self.absorb(line);
        }
    }

    /// Everything seen so far, for panic messages.
    #[must_use]
    pub fn transcript(&self) -> String {
        let read = |name: &str| std::fs::read_to_string(self.root().join(name)).unwrap_or_default();
        format!(
            "--- stdout ({} lines, eof={}):\n{}\n--- stderr ({} lines, eof={}):\n{}\n--- fake: spawn.count={} stdin.log:\n{}\n--- fake argv.log:\n{}\n--- census:\n{}\n--- wrapper.log (tail):\n{}",
            self.seen_out.len(),
            self.out_eof,
            self.seen_out.iter().map(|l| shorten(l)).collect::<Vec<_>>().join("\n"),
            self.seen_err.len(),
            self.err_eof,
            self.seen_err.iter().map(|l| shorten(l)).collect::<Vec<_>>().join("\n"),
            read("spawn.count").trim(),
            read("stdin.log").lines().map(shorten).collect::<Vec<_>>().join("\n"),
            read("argv.log").lines().collect::<Vec<_>>().join(" "),
            std::fs::read_to_string(self.bridge().join("logs").join("census.jsonl")).unwrap_or_default().lines().map(shorten).collect::<Vec<_>>().join("\n"),
            tail(&self.wrapper_log(), 40),
        )
    }

    /// Wait for the first stdout line (seen before or arriving within
    /// `timeout`) that parses as JSON and satisfies `pred`; panics with
    /// everything seen so far otherwise.
    pub fn expect_out(&mut self, pred: impl Fn(&Value) -> bool, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        let mut idx = 0;
        loop {
            while idx < self.seen_out.len() {
                if let Ok(v) = serde_json::from_str::<Value>(&self.seen_out[idx]) {
                    if pred(&v) {
                        return v;
                    }
                }
                idx += 1;
            }
            let now = Instant::now();
            if now >= deadline {
                panic!("expected stdout frame not seen within {timeout:?}\n{}", self.transcript());
            }
            match self.lines.recv_timeout(deadline - now) {
                Ok(line) => self.absorb(line),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => panic!("wrapper output ended before the expected frame\n{}", self.transcript()),
            }
        }
    }

    /// The instant a matching stdout frame was taken off the channel (≈ its arrival).
    pub fn expect_out_at(&mut self, pred: impl Fn(&Value) -> bool, timeout: Duration) -> (Value, Instant) {
        let before = self.seen_out.len();
        let v = self.expect_out(&pred, timeout);
        let at = Instant::now();
        let seen_earlier = self.seen_out[..before].iter().any(|l| serde_json::from_str::<Value>(l).is_ok_and(|x| pred(&x)));
        assert!(!seen_earlier, "the frame was already seen before this call; its arrival time is unknown");
        (v, at)
    }

    /// Every stdout line seen (after taking what already arrived).
    pub fn out_lines(&mut self) -> Vec<String> {
        self.drain();
        self.seen_out.clone()
    }

    /// Every stdout line that parses as JSON.
    pub fn out_json(&mut self) -> Vec<Value> {
        self.out_lines().iter().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    /// Every stdout frame satisfying `pred`.
    pub fn out_matching(&mut self, pred: impl Fn(&Value) -> bool) -> Vec<Value> {
        self.out_json().into_iter().filter(|v| pred(v)).collect()
    }

    /// Stderr so far, lines joined by `\n`.
    pub fn err_text(&mut self) -> String {
        self.drain();
        self.seen_err.join("\n")
    }

    /// Has the wrapper exited? (Records the instant for [`Harness::wait`].)
    pub fn exited_now(&mut self) -> bool {
        if self.exited.is_some() {
            return true;
        }
        match self.child.try_wait() {
            Ok(Some(st)) => {
                self.exited = Some((st, Instant::now()));
                true
            }
            Ok(None) => false,
            Err(e) => panic!("try_wait: {e}"),
        }
    }

    /// Wait for the wrapper to exit (kills it and panics after `timeout`),
    /// without waiting for its output streams to end (a paused stdout reader
    /// stays paused). Returns the status and the time from the last
    /// `close_stdin`/`close_stdout`/`sigterm` (else from the spawn) to the exit.
    pub fn wait_exit(&mut self, timeout: Duration) -> (ExitStatus, Duration) {
        let reference = self.reference.unwrap_or(self.started);
        let deadline = Instant::now() + timeout;
        let (status, at) = loop {
            if let Some(done) = self.exited {
                break done;
            }
            match self.child.try_wait() {
                Ok(Some(st)) => {
                    let done = (st, Instant::now());
                    self.exited = Some(done);
                    break done;
                }
                Ok(None) => {}
                Err(e) => panic!("try_wait: {e}"),
            }
            if Instant::now() >= deadline {
                eprintln!("wait timeout; process table around the wrapper (pid {}):\n{}", self.pid(), process_tree(self.pid()));
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.resume_stdout();
                self.drain();
                panic!("the wrapper did not exit within {timeout:?}; killed\n{}", self.transcript());
            }
            self.drain();
            std::thread::sleep(Duration::from_millis(1));
        };
        (status, at.saturating_duration_since(reference))
    }

    /// [`Harness::wait_exit`], then wait for both output streams to end
    /// (the stdout reader must not be paused).
    pub fn wait(&mut self, timeout: Duration) -> (ExitStatus, Duration) {
        let (status, took) = self.wait_exit(timeout);
        let eof_deadline = Instant::now() + Duration::from_secs(10);
        while !(self.out_eof && self.err_eof) {
            let now = Instant::now();
            if now >= eof_deadline {
                panic!("the wrapper exited but its stdout/stderr did not end within 10 s\n{}", self.transcript());
            }
            match self.lines.recv_timeout(eof_deadline - now) {
                Ok(line) => self.absorb(line),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        (status, took)
    }

    // ---- files the run leaves ------------------------------------------------------------

    fn jsonl(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{}: unparseable line {l:?}: {e}", path.display())))
            .collect()
    }

    /// Every census row, oldest first.
    #[must_use]
    pub fn census(&self) -> Vec<Value> {
        Self::jsonl(&self.bridge().join("logs").join("census.jsonl"))
    }

    /// The end row (the one with `end`); panics unless exactly one exists.
    #[must_use]
    pub fn end_row(&self) -> Value {
        let rows = self.census();
        let ends: Vec<&Value> = rows.iter().filter(|r| r.get("end").is_some()).collect();
        assert_eq!(ends.len(), 1, "expected exactly one end row: {rows:#?}");
        ends[0].clone()
    }

    /// The end row's note.
    #[must_use]
    pub fn end_note(&self) -> String {
        self.end_row()["note"].as_str().unwrap_or_default().to_string()
    }

    /// Every `audit.jsonl` row, oldest first.
    #[must_use]
    pub fn audit_rows(&self) -> Vec<Value> {
        Self::jsonl(&self.bridge().join("audit.jsonl"))
    }

    /// The audit rows with `event`.
    #[must_use]
    pub fn audit_events(&self, event: &str) -> Vec<Value> {
        self.audit_rows().into_iter().filter(|r| r["event"] == event).collect()
    }

    /// `state/sessions/*.toml`: (file name, raw text), sorted by name; `.*.tmp` skipped.
    #[must_use]
    pub fn registry_files(&self) -> Vec<(String, String)> {
        let dir = self.bridge().join("state").join("sessions");
        let mut out: Vec<(String, String)> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".toml") && !n.starts_with('.'))
                .map(|n| {
                    let text = std::fs::read_to_string(dir.join(&n)).expect("read registry row");
                    (n, text)
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        out.sort();
        out
    }

    /// The parsed registry rows (sorted by file name).
    #[must_use]
    pub fn registry_rows(&self) -> Vec<toml::Value> {
        self.registry_files()
            .into_iter()
            .map(|(n, t)| toml::from_str::<toml::Value>(&t).unwrap_or_else(|e| panic!("registry row {n}: {e}\n{t}")))
            .collect()
    }

    /// `logs/wrapper.log`, empty when absent.
    #[must_use]
    pub fn wrapper_log(&self) -> String {
        std::fs::read_to_string(self.bridge().join("logs").join("wrapper.log")).unwrap_or_default()
    }

    /// The fake's stdin log: (generation, line), in order.
    #[must_use]
    pub fn stdin_log(&self) -> Vec<(u32, String)> {
        std::fs::read_to_string(self.root().join("stdin.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| {
                let (g, line) = l.split_once('\t').unwrap_or_else(|| panic!("stdin log line without a tab: {l:?}"));
                (g.parse().unwrap_or_else(|_| panic!("stdin log generation {g:?}")), line.to_string())
            })
            .collect()
    }

    /// The lines generation `gen` read.
    #[must_use]
    pub fn stdin_of(&self, gen: u32) -> Vec<String> {
        self.stdin_log().into_iter().filter(|(g, _)| *g == gen).map(|(_, l)| l).collect()
    }

    /// The fake's argv per generation, in spawn order.
    #[must_use]
    pub fn argv_log(&self) -> Vec<Vec<String>> {
        let mut out: Vec<Vec<String>> = Vec::new();
        for l in std::fs::read_to_string(self.root().join("argv.log")).unwrap_or_default().lines() {
            if l.starts_with("--- gen ") {
                out.push(Vec::new());
            } else {
                out.last_mut().unwrap_or_else(|| panic!("argv log starts without a generation header: {l:?}")).push(l.to_string());
            }
        }
        out
    }

    /// The fake's environment log lines.
    #[must_use]
    pub fn env_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.root().join("env.log")).unwrap_or_default().lines().map(str::to_string).collect()
    }

    /// How many fake processes ran (0 when none did).
    #[must_use]
    pub fn spawn_count(&self) -> u32 {
        std::fs::read_to_string(self.root().join("spawn.count")).map_or(0, |t| t.trim().parse().expect("spawn count"))
    }

    /// `<bridge>/state/scratch/<uuid>`.
    #[must_use]
    pub fn scratch_dir(&self, uuid: &str) -> PathBuf {
        self.bridge().join("state").join("scratch").join(uuid)
    }

    /// The names under `<bridge>/state/scratch`, sorted (empty when absent).
    #[must_use]
    pub fn scratch_names(&self) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(self.bridge().join("state").join("scratch"))
            .map(|rd| rd.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        out.sort();
        out
    }

    /// The pid generation `gen` of the fake logged (`FAKE_ENV_LOG`).
    #[must_use]
    pub fn fake_pid(&self, gen: u32) -> Option<u32> {
        let prefix = format!("gen {gen} ");
        self.env_log().iter().find(|l| l.starts_with(&prefix)).and_then(|l| env_log_field(l, "pid")).and_then(|p| p.parse().ok())
    }
}

/// `ps` rows of `pid` and its children (diagnostics for a hung run).
fn process_tree(pid: u32) -> String {
    let Ok(out) = Command::new("/bin/ps").args(["-A", "-o", "pid=,ppid=,stat=,command="]).output() else { return "ps unavailable".into() };
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut keep: Vec<u32> = vec![pid];
    let rows: Vec<(u32, u32, String)> = text
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let p = it.next()?.parse().ok()?;
            let pp = it.next()?.parse().ok()?;
            Some((p, pp, l.to_string()))
        })
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for (p, pp, _) in &rows {
            if keep.contains(pp) && !keep.contains(p) {
                keep.push(*p);
                changed = true;
            }
        }
    }
    rows.iter().filter(|(p, _, _)| keep.contains(p)).map(|(_, _, l)| l.clone()).collect::<Vec<_>>().join("\n")
}

fn shorten(line: &str) -> String {
    if line.len() <= 400 {
        line.to_string()
    } else {
        let mut cut = 400;
        while !line.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}… ({} bytes)", &line[..cut], line.len())
    }
}

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// `note` contains `key:<n>`; the number.
#[must_use]
pub fn note_number(note: &str, key: &str) -> Option<u64> {
    note.split("; ").find_map(|p| p.strip_prefix(key).and_then(|r| r.strip_prefix(':'))).and_then(|v| v.parse().ok())
}

/// `note` has the exact `; `-separated part `part`.
#[must_use]
pub fn note_has(note: &str, part: &str) -> bool {
    note.split("; ").any(|p| p == part)
}
