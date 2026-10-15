//! S8 operators: `ai-env creds deployer-key`, the deployer key's hand-over
//! through the concealed clipboard (plans/s8-operators-contracts.md §6),
//! through the binary: stdin is the JSON pipe, the controlling terminal a pty
//! the test drives (§11.4), tests/fakes/osascript.sh the pasteboard
//! (`AI_ENV_BRIDGE_LAB_OSASCRIPT`, debug builds) and the fake aws the sts
//! answers; keys are built at run time (`aws_keys`). Phase 0 declares the
//! file; wave 1 (W2b) writes its tests.
// Debug builds only: every test here runs tests/fakes/osascript.sh through
// AI_ENV_BRIDGE_LAB_OSASCRIPT, which a release build ignores: it would run the
// real /usr/bin/osascript on the clipboard of whoever runs the tests.
#![cfg(debug_assertions)]
use super::aws_keys::{create_access_key_json, key_id, secret, DEPLOYER_TAIL};
use super::common::*;
use super::creds::{audit_rows, holds, Env};
use std::fs::{self, File};
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const DEPLOYER: &str = "ai-env-deployer";
const STACK: &str = "123456789012";
const PASTED: &str = "press Enter here when it is pasted: ";
const SAVED: &str = "press Enter here when the entry is saved: ";
const ID_BACK: &str = "access key id (from Strongbox): ";
const SECRET_BACK: &str = "secret access key (from Strongbox): ";
const TRIED: &str = "press Enter here when you have tried: ";
const CLIPBOARD_REFUSED: &str = "execution error: Error: Error: setString:forType: refused (-2700)";
const CLEAR_ENTRY: &str = "  and clear the Strongbox entry (its history keeps the previous values)";

/// The deployer key a test hands over: tail 9001, which the fake aws answers as ai-env-deployer.
struct Key {
    id: String,
    secret: String,
    json: String,
}

fn deployer_key(block: &str) -> Key {
    let (id, secret) = (key_id(DEPLOYER_TAIL), secret(block));
    Key { json: create_access_key_json(DEPLOYER, &id, &secret), id, secret }
}

/// The cleanup note of `key` (contracts §6.3), with the third line once the paste-back matched. Its delete command
/// starts with the deployer's runner, which can run it on this Mac, where a bare `aws` has no credentials (D13): the
/// harness runs as `ai-env as ops` leaves it.
fn cleanup(user: &str, id: &str, matched: bool) -> String {
    let mut note = format!(
        "the access key ...{} of IAM user {user} was NOT handed over; if you just created it, delete it:\n  ai-env as deployer -- aws iam delete-access-key --user-name {user} --access-key-id {id} --region eu-central-1\n",
        &id[id.len() - 4..]
    );
    if matched {
        note.push_str(CLEAR_ENTRY);
        note.push('\n');
    }
    note
}

/// The creds harness (fake age and aws) plus the fake osascript (shared with
/// `as deployer`'s terminal tests in tests/infra/identity.rs).
pub(super) struct World {
    pub(super) env: Env,
}

impl World {
    pub(super) fn new() -> World {
        let env = Env::new(true);
        let osascript = env.bin().join("osascript");
        fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/osascript.sh"), &osascript).unwrap();
        fs::set_permissions(&osascript, fs::Permissions::from_mode(0o755)).unwrap();
        // macOS takes seconds over the first exec of a new file: paid here (no
        // knob set, so nothing is logged), never inside osascript's 10 s timeout.
        let warm = Command::new(&osascript).env_clear().env("PATH", "/usr/bin:/bin").stdin(Stdio::null()).output().unwrap();
        assert_eq!(warm.status.code(), Some(1), "the fake refuses an empty argv: {}", String::from_utf8_lossy(&warm.stderr));
        World { env }
    }

    pub(super) fn osa_log(&self) -> PathBuf {
        self.env.root().join("osa.log")
    }

    fn aws_env_log(&self) -> PathBuf {
        self.env.root().join("aws-env.log")
    }

    /// The fake pasteboard as new: no state (no set so far), an empty log.
    pub(super) fn fresh_clipboard(&self) {
        let _ = fs::remove_file(self.osa_log());
        let _ = fs::remove_file(self.env.root().join("pb.state"));
    }

    /// `ai-env creds deployer-key <args>` as `ai-env as ops` would leave it (the
    /// harness's identity), the fakes on PATH, the fake osascript, polls in
    /// milliseconds; `AI_ENV_PASTE_STDIN` unset (stdin is the JSON).
    fn cmd(&self, args: &[&str]) -> Command {
        let mut all = vec!["deployer-key"];
        all.extend_from_slice(args);
        let mut cmd = self.env.creds(&all);
        cmd.env_remove("AI_ENV_PASTE_STDIN")
            .env("AI_ENV_BRIDGE_LAB_OSASCRIPT", self.env.bin().join("osascript"))
            .env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1")
            .env("FAKE_PB_STATE", self.env.root().join("pb.state"))
            .env("FAKE_OSA_LOG", self.osa_log())
            .env("FAKE_AWS_ENV_LOG", self.aws_env_log());
        cmd
    }

    /// The hand-over of `key` for the stack's account, the fake pasteboard checking what each set places.
    fn handover(&self, key: &Key, extra: &[(&str, &str)]) -> Command {
        let mut cmd = self.cmd(&["--account", STACK]);
        cmd.env("FAKE_PB_EXPECT_1", &key.id).env("FAKE_PB_EXPECT_2", &key.secret);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd
    }

    /// What the fake osascript logged, one operation per line (never a value).
    pub(super) fn osa(&self) -> Vec<String> {
        fs::read_to_string(self.osa_log()).unwrap_or_default().lines().map(str::to_string).collect()
    }

    /// The sts calls the fake aws saw, by their environment's names and pins.
    fn sts_calls(&self) -> Vec<String> {
        fs::read_to_string(self.aws_env_log()).unwrap_or_default().lines().filter(|l| l.starts_with("sts get-caller-identity")).map(str::to_string).collect()
    }

    fn last_audit(&self) -> Option<serde_json::Value> {
        audit_rows(&self.env).into_iter().rfind(|r| r["event"] == "creds_deployer_key")
    }
}

/// An `openpty` pair, both close-on-exec.
fn openpty() -> (OwnedFd, OwnedFd) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: both out-pointers are valid for the call; name, termios and winsize may be null.
    let rc = unsafe { libc::openpty(&raw mut master, &raw mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    for fd in [master, slave] {
        // SAFETY: fd is one of the two descriptors openpty just returned.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) }, 0, "FD_CLOEXEC: {}", std::io::Error::last_os_error());
    }
    // SAFETY: openpty returned two open descriptors that nothing else owns.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

/// Whether the terminal of `master` echoes what is typed.
fn echoes(master: &File) -> bool {
    // SAFETY: tcgetattr(3) fills a zeroed (valid) termios from an open descriptor.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(master.as_raw_fd(), &raw mut t) }, 0, "tcgetattr: {}", std::io::Error::last_os_error());
    t.c_lflag & libc::ECHO != 0
}

/// What a drain read so far, and the end of its source once it is sent.
type Drained = (Arc<Mutex<Vec<u8>>>, mpsc::Receiver<()>);

/// A drain of `r` into a shared buffer; the sender says it ended.
fn drain(mut r: impl std::io::Read + Send + 'static) -> Drained {
    let (buf, (tx, rx)) = (Arc::new(Mutex::new(Vec::new())), mpsc::channel());
    let into = Arc::clone(&buf);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => into.lock().unwrap().extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                // EIO: the terminal is gone.
                Err(_) => break,
            }
        }
        let _ = tx.send(());
    });
    (buf, rx)
}

fn text(buf: &Mutex<Vec<u8>>) -> String {
    String::from_utf8_lossy(&buf.lock().unwrap()).into_owned()
}

/// What the test's terminal is to the child: its controlling terminal
/// (`controlling`; else the child runs in a session without one: no
/// `/dev/tty`), and its stdin (no input is written then) or its stdout too.
#[derive(Debug, Clone, Copy, Default)]
struct Attach {
    controlling: bool,
    stdin: bool,
    stdout: bool,
}

/// A hand-over running, its terminal the test's pty (§11.4): `openpty`, both
/// ends close-on-exec; the child's `pre_exec` makes it a session leader
/// (`setsid`) whose controlling terminal is the slave (`TIOCSCTTY`), so its
/// `/dev/tty` is the slave (a child without that ioctl has no `/dev/tty` at
/// all: never this test run's terminal). The test keeps its own copy of the
/// slave until the child ended, as a shell keeps its terminal open, then
/// drops it: a thread drains the master until EOF or EIO. The test answers a
/// prompt only once the prompt is on the terminal and the child turned its
/// echo off (`tcgetattr` on the master), so what the master shows is what the
/// child wrote: the prompts and nothing typed. That it never holds the id or
/// the secret proves echo is off. `ai-env as deployer`'s terminal tests
/// (tests/infra/identity.rs) drive it too.
pub(super) struct Session {
    child: Child,
    master: File,
    /// The test's copy of the terminal, kept while the child runs.
    slave: Option<OwnedFd>,
    tty: Drained,
    /// `None` when stdout is the terminal.
    stdout: Option<Drained>,
    stderr: Drained,
}

/// What a finished hand-over left.
pub(super) struct Done {
    status: ExitStatus,
    /// Empty when stdout was the terminal.
    pub(super) stdout: String,
    pub(super) stderr: String,
    /// What the child wrote on its terminal, `\r` dropped.
    pub(super) tty: String,
    raw_tty: Vec<u8>,
    /// Whether the terminal echoed again once the child ended.
    pub(super) echo: bool,
}

impl Done {
    pub(super) fn code(&self) -> Option<i32> {
        self.status.code()
    }

    /// Neither the terminal nor stderr ever shows `value` (or a 16-byte piece
    /// of it): for a secret, whose pieces nothing else shares.
    pub(super) fn never_shows(&self, value: &str, what: &str) {
        assert!(!holds(&self.raw_tty, value), "{what} (or a piece of it) is on the terminal");
        assert!(!holds(self.stderr.as_bytes(), value), "{what} (or a piece of it) is on stderr");
    }

    /// The terminal never shows `id` (or a piece of it), stderr never all of
    /// it but in `allowed` delete commands: the fakes' key ids share their
    /// first 16 bytes, so stderr is searched for the whole id.
    pub(super) fn never_shows_id(&self, id: &str, allowed: usize, what: &str) {
        assert!(!holds(&self.raw_tty, id), "{what} (or a piece of it) is on the terminal");
        let shown = self.stderr.matches(id).count();
        let deletes = self.stderr.matches(&format!("--access-key-id {id} ")).count();
        assert!(shown == deletes && deletes <= allowed, "{what} on stderr outside a delete command ({shown} times, {deletes} in delete commands)");
    }
}

impl Session {
    /// Run `cmd` with `input` on stdin, the slave its controlling terminal
    /// when `controlling` (else a session without one: no `/dev/tty`).
    pub(super) fn start(cmd: Command, input: &[u8], controlling: bool) -> Session {
        Session::start_with(cmd, input, Attach { controlling, ..Attach::default() })
    }

    /// [`Session::start`], the terminal attached as `on` says.
    fn start_with(mut cmd: Command, input: &[u8], on: Attach) -> Session {
        let (master, slave) = openpty();
        let slave_fd = slave.as_raw_fd();
        let tty = || Stdio::from(slave.try_clone().unwrap());
        cmd.stdin(if on.stdin { tty() } else { Stdio::piped() }).stdout(if on.stdout { tty() } else { Stdio::piped() }).stderr(Stdio::piped());
        let controlling = on.controlling;
        // SAFETY: runs in the forked child before exec; setsid(2), ioctl(2) and
        // signal(3) are async-signal-safe, and slave_fd is open there until the exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if controlling && libc::ioctl(slave_fd, libc::c_ulong::from(libc::TIOCSCTTY), 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // As at a terminal: a `cargo test &` would hand these down ignored.
                for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                    libc::signal(sig, libc::SIG_DFL);
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn ai-env");
        // The command's own copies of the slave close here: only the test's is left.
        drop(cmd);
        if let Some(mut stdin) = child.stdin.take() {
            // A refusal may come before the read: a closed pipe is no failure here. Then EOF.
            let _ = stdin.write_all(input);
        }
        let master = File::from(master);
        let tty = drain(master.try_clone().unwrap());
        let stdout = child.stdout.take().map(drain);
        let stderr = drain(child.stderr.take().unwrap());
        Session { child, master, slave: Some(slave), tty, stdout, stderr }
    }

    /// Poll `ready` for at most 30 s; a child that ended meanwhile, or the
    /// deadline, fails the test with what it said.
    fn wait(&mut self, what: &str, ready: &dyn Fn(&Session) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready(self) {
            if let Some(status) = self.child.try_wait().unwrap() {
                std::thread::sleep(Duration::from_millis(100));
                panic!("waiting for {what}: ai-env ended ({status}); stderr:\n{}\nterminal:\n{}", text(&self.stderr.0), text(&self.tty.0));
            }
            assert!(Instant::now() < deadline, "waiting for {what} for 30 s; stderr:\n{}\nterminal:\n{}", text(&self.stderr.0), text(&self.tty.0));
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Wait until `prompt` is on the terminal for the `n`-th time and the child
    /// turned echo off, then type `line` and Enter.
    pub(super) fn answer(&mut self, prompt: &str, n: usize, line: &str) {
        self.answer_bytes(prompt, n, line.as_bytes());
    }

    /// Wait until `prompt` is on the terminal for the `n`-th time and the
    /// child turned echo off: it is reading that prompt's answer.
    pub(super) fn wait_prompt(&mut self, prompt: &str, n: usize) {
        self.wait(&format!("{prompt:?} #{n}"), &|s| text(&s.tty.0).matches(prompt).count() >= n);
        self.wait("echo off", &|s| !echoes(&s.master));
    }

    /// [`Session::answer`] with bytes that need not be UTF-8.
    fn answer_bytes(&mut self, prompt: &str, n: usize, line: &[u8]) {
        self.wait_prompt(prompt, n);
        let mut typed = line.to_vec();
        typed.push(b'\n');
        (&self.master).write_all(&typed).unwrap();
    }

    /// Ctrl-C on the terminal: SIGINT to its foreground process group, the child's.
    pub(super) fn ctrl_c(&self) {
        (&self.master).write_all(&[0x03]).unwrap();
    }

    /// Send `sig` to the child, which is still running.
    pub(super) fn signal(&self, sig: libc::c_int) {
        let pid = i32::try_from(self.child.id()).unwrap();
        // SAFETY: kill(2) on the child this test started and has not reaped.
        assert_eq!(unsafe { libc::kill(pid, sig) }, 0, "kill: {}", std::io::Error::last_os_error());
    }

    /// Wait until stderr holds `needle`.
    fn wait_stderr(&mut self, needle: &str) {
        self.wait(&format!("{needle:?} on stderr"), &|s| text(&s.stderr.0).contains(needle));
    }

    /// The child's end (at most 60 s), then the terminal's.
    pub(super) fn finish(mut self) -> Done {
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("ai-env still running after 60 s; stderr:\n{}", text(&self.stderr.0));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let echo = echoes(&self.master);
        drop(self.slave.take());
        let mut ends = vec![("the terminal", &self.tty.1), ("stderr", &self.stderr.1)];
        if let Some((_, ended)) = &self.stdout {
            ends.push(("stdout", ended));
        }
        for (what, ended) in ends {
            ended.recv_timeout(Duration::from_secs(30)).unwrap_or_else(|_| panic!("{what} never ended"));
        }
        let raw_tty = self.tty.0.lock().unwrap().clone();
        let stdout = self.stdout.as_ref().map(|(buf, _)| text(buf)).unwrap_or_default();
        Done { status, stdout, stderr: text(&self.stderr.0), tty: String::from_utf8_lossy(&raw_tty).replace('\r', ""), raw_tty, echo }
    }
}

/// The whole conversation of a hand-over whose paste-back matches.
fn converse(s: &mut Session, key: &Key) {
    s.answer(PASTED, 1, "");
    s.answer(SAVED, 1, "");
    s.answer(ID_BACK, 1, &key.id);
    s.answer(SECRET_BACK, 1, &key.secret);
}

/// The terminal of a conversation that matched at once: the prompts, each
/// followed by the line break the reader writes, nothing typed.
fn prompts_only() -> String {
    format!("{PASTED}\n{SAVED}\n{ID_BACK}\n{SECRET_BACK}\n")
}

/// The id goes on the clipboard, then the secret, each cleared after its
/// Enter; both are pasted back with no echo and match; sts answers after one
/// refusal (IAM propagation) as ai-env-deployer of the stack's account: exit
/// 0, stdout the `id` and `arn` lines, every stderr line the contract's, the
/// terminal only the prompts, the clipboard's child without a key or the
/// marker, sts with the new key alone, the audit row.
#[test]
fn the_deployer_key_is_handed_over_through_a_concealed_clipboard_and_checked_back() {
    let w = World::new();
    let key = deployer_key("Ho4+");
    let answers = w.env.root().join("answers");
    fs::create_dir_all(&answers).unwrap();
    fs::write(answers.join("sts.get-caller-identity.1.rc"), "254\n").unwrap();
    fs::write(answers.join("sts.get-caller-identity.1.stderr"), "\nAn error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: The security token included in the request is invalid.\n").unwrap();
    let mut s = Session::start(w.handover(&key, &[("FAKE_AWS_ANSWERS", &answers.display().to_string())]), key.json.as_bytes(), true);
    // Something typed at an Enter prompt is discarded unseen.
    s.answer(PASTED, 1, "typed-by-mistake");
    s.answer(SAVED, 1, "");
    s.answer(ID_BACK, 1, &key.id);
    s.answer(SECRET_BACK, 1, &format!("  {}  ", key.secret));
    let done = s.finish();
    assert_eq!(done.code(), Some(0), "stderr:\n{}", done.stderr);
    assert_eq!(done.stdout, format!("id {}\narn arn:aws:iam::{STACK}:user/{DEPLOYER}\n", key.id));
    let said: Vec<&str> = done.stderr.lines().collect();
    assert_eq!(
        said,
        [
            "ai-env: hand-over of the ai-env-deployer access key ...9001 to Strongbox (the clipboard stays on this Mac and is marked concealed; nothing is shown)",
            "ai-env: 1/2: the access key id is on the clipboard: paste it into the Strongbox entry's user name field",
            "ai-env: warning: something was typed or pasted at the Enter prompt: discarded, never shown",
            "ai-env: cleared the clipboard",
            "ai-env: 2/2: the secret access key is on the clipboard: paste it into the same entry's password field and save the entry",
            "ai-env: cleared the clipboard",
            "ai-env: now copy both back from the saved Strongbox entry and paste them here (nothing is shown)",
            "ai-env: both match the key that was created; cleared the clipboard",
            "ai-env: the key ...9001 does not answer yet (1/8: IAM propagation)",
            "ai-env: the access key ...9001 answers as user/ai-env-deployer: it is in Strongbox only; ai-env as deployer -- … asks for it",
        ]
    );
    assert_eq!(done.tty, prompts_only(), "the terminal shows the prompts and nothing typed");
    done.never_shows(&key.secret, "the secret");
    done.never_shows_id(&key.id, 0, "the full key id");
    assert!(!done.tty.contains("typed-by-mistake") && !done.stderr.contains("typed-by-mistake"));
    assert!(done.echo, "echo is on again");
    // The fake pasteboard got the id, then the secret (each compared there, never logged), each cleared, then the copy from Strongbox cleared.
    assert_eq!(w.osa(), ["set 1 match", "clear-if cleared", "set 2 match", "clear-if cleared", "clear cleared"], "no ENV= suffix: neither a key nor the marker reached osascript");
    // sts: twice, with the new key alone (the ops marker and key of this process gone, the files pinned).
    let sts = w.sts_calls();
    assert_eq!(sts.len(), 2, "{sts:?}");
    for l in &sts {
        assert!(l.starts_with("sts get-caller-identity | AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true"), "{l}");
    }
    let row = w.last_audit().expect("an audit row");
    for (k, v) in [("user", DEPLOYER), ("key_id_last4", DEPLOYER_TAIL), ("result", "verified")] {
        assert_eq!(row["detail"][k], v, "{k}");
    }
    assert_eq!(audit_rows(&w.env).len(), 1, "one row: a stop's row is never written besides");
    super::creds::assert_nowhere(w.env.root(), &key.secret, "the secret");
}

/// A value pasted back that does not match goes back on the clipboard and is
/// asked again (only it), three rounds at most: then exit 1 with the delete
/// command (no third line: Strongbox never held the key as created), no sts
/// call, and the clipboard, which held what was copied from Strongbox last,
/// cleared on the way out. A paste of the user's name, registered with the
/// scrubber as any paste, leaves the delete command whole.
#[test]
fn a_paste_back_that_never_matches_prints_the_delete_command() {
    let w = World::new();
    let key = deployer_key("Mm5+");
    let wrong = key_id("9099");
    let mut cmd = w.handover(&key, &[]);
    cmd.env("FAKE_PB_EXPECT_3", &key.id).env("FAKE_PB_EXPECT_4", &key.id);
    let mut s = Session::start(cmd, key.json.as_bytes(), true);
    s.answer(PASTED, 1, "");
    s.answer(SAVED, 1, "");
    s.answer(ID_BACK, 1, &format!(" {wrong} "));
    s.answer(SECRET_BACK, 1, &key.secret);
    s.answer(SAVED, 2, "");
    // The entry's title by mistake.
    s.answer(ID_BACK, 2, DEPLOYER);
    s.answer(SAVED, 3, "");
    s.answer(ID_BACK, 3, &key.id[..10]);
    let done = s.finish();
    assert_eq!(done.code(), Some(1), "stderr:\n{}", done.stderr);
    assert_eq!(done.stdout, format!("id {}\n", key.id), "no arn line: sts was never asked");
    let again = |n: usize| format!("ai-env: the access key id pasted back does not match the one created ({n} characters, expected 20): it is on the clipboard again: paste it into the entry, save it, then paste it back here");
    for n in [20, 15] {
        assert_eq!(done.stderr.lines().filter(|l| *l == again(n)).count(), 1, "{n} characters:\n{}", done.stderr);
    }
    let end = format!("ai-env: creds deployer-key: the access key id pasted back never matched the one created (3 rounds): it was NOT handed over\n{}", cleanup(DEPLOYER, &key.id, false));
    assert!(done.stderr.ends_with(&end), "{}", done.stderr);
    assert!(!done.stderr.contains("both match") && !done.stderr.contains(CLEAR_ENTRY) && !done.stderr.contains("[redacted"), "{}", done.stderr);
    assert_eq!((done.tty.matches(ID_BACK).count(), done.tty.matches(SECRET_BACK).count(), done.tty.matches(SAVED).count()), (3, 1, 3), "only the id is asked again:\n{}", done.tty);
    assert_eq!(w.osa(), ["set 1 match", "clear-if cleared", "set 2 match", "clear-if cleared", "set 3 match", "clear-if cleared", "set 4 match", "clear-if cleared", "clear cleared"]);
    assert!(w.sts_calls().is_empty(), "{:?}", w.sts_calls());
    assert_eq!(w.last_audit().unwrap()["detail"]["result"], "mismatch");
    done.never_shows(&key.secret, "the secret");
    done.never_shows_id(&wrong, 0, "the wrong id pasted back");
    done.never_shows_id(&key.id, 1, "the full key id");
    assert!(done.echo);
}

/// A value that does not match in one round can match in the next: here the
/// id pasted back could not be read (not UTF-8: a value that does not match,
/// not the end of the hand-over) and the secret was a character short. Each
/// goes back on the clipboard with its own line, only they are asked again,
/// and the key is handed over.
#[test]
fn a_paste_back_that_matches_in_a_later_round_hands_the_key_over() {
    let w = World::new();
    let key = deployer_key("Lr4+");
    let other = secret("Wr0/");
    let short = &other[..39];
    let mut cmd = w.handover(&key, &[]);
    cmd.env("FAKE_PB_EXPECT_3", &key.id).env("FAKE_PB_EXPECT_4", &key.secret);
    let mut s = Session::start(cmd, key.json.as_bytes(), true);
    s.answer(PASTED, 1, "");
    s.answer(SAVED, 1, "");
    s.answer_bytes(ID_BACK, 1, b"\xc3\x28");
    s.answer(SECRET_BACK, 1, short);
    s.answer(SAVED, 2, "");
    s.answer(SAVED, 3, "");
    s.answer(ID_BACK, 2, &key.id);
    s.answer(SECRET_BACK, 2, &key.secret);
    let done = s.finish();
    assert_eq!(done.code(), Some(0), "stderr:\n{}", done.stderr);
    assert_eq!(done.stdout, format!("id {}\narn arn:aws:iam::{STACK}:user/{DEPLOYER}\n", key.id));
    let again = |what: &str, got: &str| format!("ai-env: the {what} pasted back does not match the one created ({got}): it is on the clipboard again: paste it into the entry, save it, then paste it back here");
    for line in [again("access key id", "pasted input is not valid UTF-8; expected 20 characters"), again("secret access key", "39 characters, expected 40")] {
        assert_eq!(done.stderr.lines().filter(|l| *l == line).count(), 1, "{line}\n{}", done.stderr);
    }
    assert!(done.stderr.contains("\nai-env: both match the key that was created; cleared the clipboard\n") && !done.stderr.contains("NOT handed over"), "{}", done.stderr);
    assert_eq!((done.tty.matches(ID_BACK).count(), done.tty.matches(SECRET_BACK).count(), done.tty.matches(SAVED).count()), (2, 2, 3), "{}", done.tty);
    assert_eq!(w.osa(), ["set 1 match", "clear-if cleared", "set 2 match", "clear-if cleared", "set 3 match", "clear-if cleared", "set 4 match", "clear-if cleared", "clear cleared"]);
    assert_eq!(w.last_audit().unwrap()["detail"]["result"], "verified");
    done.never_shows(&key.secret, "the secret");
    done.never_shows(short, "the short secret pasted back");
    done.never_shows_id(&key.id, 0, "the full key id");
    assert!(done.echo);
}

/// An empty paste-back is a cancel: exit 3, its one line and the delete
/// command, no `ai-env: cancelled` line (D19); the clipboard (what was copied
/// from Strongbox, if anything) is cleared first, without a word.
#[test]
fn nothing_pasted_back_is_a_cancel_in_one_line() {
    let w = World::new();
    let key = deployer_key("Cn6+");
    let mut s = Session::start(w.handover(&key, &[]), key.json.as_bytes(), true);
    s.answer(PASTED, 1, "");
    s.answer(SAVED, 1, "");
    s.answer(ID_BACK, 1, "   ");
    let done = s.finish();
    assert_eq!(done.code(), Some(3), "stderr:\n{}", done.stderr);
    let after: Vec<&str> = done.stderr.lines().skip_while(|l| !l.starts_with("ai-env: now copy both back")).skip(1).collect();
    assert_eq!(after.first().copied(), Some("ai-env: creds deployer-key: nothing was pasted back: cancelled, it was NOT handed over"), "{}", done.stderr);
    assert!(done.stderr.ends_with(&format!("ai-env: creds deployer-key: nothing was pasted back: cancelled, it was NOT handed over\n{}", cleanup(DEPLOYER, &key.id, false))), "{}", done.stderr);
    assert!(!done.stderr.contains("ai-env: cancelled"), "{}", done.stderr);
    assert_eq!(w.osa(), ["set 1 match", "clear-if cleared", "set 2 match", "clear-if cleared", "clear cleared"]);
    assert_eq!(w.last_audit().unwrap()["detail"]["result"], "cancelled");
    assert!(w.sts_calls().is_empty() && done.echo);
}

/// Refused before any clipboard: a terminal on stdin (exit 2, nothing read),
/// another user's key (exit 9, the delete command naming that user, no `id`
/// line), JSON that is not a key (exit 1), no account known (exit 1) and no
/// terminal for the hand-over (exit 5), the last two after the `id` line and
/// with the delete command.
#[test]
fn the_handover_refuses_a_terminal_on_stdin_and_another_users_key() {
    let w = World::new();
    // stdin a terminal: refused before anything is read.
    let (master, slave) = openpty();
    let mut cmd = w.cmd(&["--account", STACK]);
    cmd.stdin(Stdio::from(slave)).stdout(Stdio::piped()).stderr(Stdio::piped());
    // SAFETY: runs in the forked child before exec; setsid(2) is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let out = super::creds::wait_bounded(cmd.spawn().unwrap(), "deployer-key read the terminal instead of refusing it");
    drop(master);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(stderr(&out), "ai-env: stdin is a terminal: pipe the JSON of aws iam create-access-key --user-name ai-env-deployer --output json into this command; never paste it\n");
    assert!(stdout(&out).is_empty());

    // Another user's key: exit 9, the delete command names the user the key belongs to.
    let id = key_id("9002");
    let foreign = create_access_key_json("ai-env-ops", &id, &secret("Fr7+"));
    let done = Session::start(w.cmd(&["--account", STACK]), foreign.as_bytes(), true).finish();
    assert_eq!(done.code(), Some(9), "{}", done.stderr);
    assert_eq!(done.stderr, format!("ai-env: the access key belongs to IAM user \"ai-env-ops\", not \"{DEPLOYER}\": refusing to hand over another principal's key\n{}", cleanup("ai-env-ops", &id, false)));
    assert!(done.stdout.is_empty() && done.tty.is_empty(), "nothing shown: {:?} {:?}", done.stdout, done.tty);
    // Under the account root's runner (make operator-keys, the bootstrap: the deployer has no key yet) the delete
    // command is the root's (D13).
    let mut cmd = w.cmd(&["--account", STACK]);
    cmd.env("AI_ENV_BRIDGE_AS", "root").env_remove("AWS_ACCESS_KEY_ID").env_remove("AWS_SECRET_ACCESS_KEY");
    let done = Session::start(cmd, foreign.as_bytes(), true).finish();
    assert_eq!(done.code(), Some(9), "{}", done.stderr);
    let root_note = format!("was NOT handed over; if you just created it, delete it:\n  ai-env as root -- aws iam delete-access-key --user-name ai-env-ops --access-key-id {id} --region eu-central-1\n");
    assert!(done.stderr.ends_with(&root_note) && !done.stderr.contains("ai-env as deployer --"), "{}", done.stderr);
    // Not a key: exit 1, how to find and delete one.
    let done = Session::start(w.cmd(&["--account", STACK]), b"{\"AccessKey\": {}}", true).finish();
    assert_eq!(done.code(), Some(1), "{}", done.stderr);
    assert!(
        done.stderr.ends_with(&format!(
            "\n  ai-env as deployer -- aws iam list-access-keys --user-name {DEPLOYER} --region eu-central-1\n  ai-env as deployer -- aws iam delete-access-key --user-name {DEPLOYER} --access-key-id <id> --region eu-central-1\n"
        )),
        "{}",
        done.stderr
    );
    assert!(w.osa().is_empty() && w.last_audit().is_none(), "nothing past the parse: no clipboard, no audit row");

    // The account unknown (no --account, no state, no [aws] ARN): exit 1 after the id line.
    let key = deployer_key("Na8+");
    let done = Session::start(w.cmd(&[]), key.json.as_bytes(), true).finish();
    assert_eq!(done.code(), Some(1), "{}", done.stderr);
    assert_eq!(done.stdout, format!("id {}\n", key.id));
    assert_eq!(done.stderr, format!("ai-env: creds deployer-key: the stack's account is unknown here (no state/infra.toml, no [aws] ARN in bridge.toml): pass --account with its 12 digits\n{}", cleanup(DEPLOYER, &key.id, false)));
    assert_eq!(w.last_audit().unwrap()["detail"]["result"], "no-account");
    // A malformed --account: a usage error, still with the delete command.
    let done = Session::start(w.cmd(&["--account", "12345"]), key.json.as_bytes(), true).finish();
    assert_eq!(done.code(), Some(2), "{}", done.stderr);
    assert!(done.stderr.starts_with("ai-env: creds deployer-key: --account 12345: expected the 12 digits of an AWS account\n") && done.stderr.contains(&cleanup(DEPLOYER, &key.id, false)), "{}", done.stderr);
    // No terminal for the hand-over (a session without one): exit 5.
    let done = Session::start(w.cmd(&["--account", STACK]), key.json.as_bytes(), false).finish();
    assert_eq!(done.code(), Some(5), "{}", done.stderr);
    assert_eq!(done.stderr, format!("ai-env: creds deployer-key: no terminal for the hand-over (the key is never shown or read anywhere else)\n{}", cleanup(DEPLOYER, &key.id, false)));
    assert_eq!(w.last_audit().unwrap()["detail"]["result"], "no-terminal");
    assert!(w.osa().is_empty(), "the clipboard was never touched: {:?}", w.osa());
}

/// A key that IAM never accepts (8 tries, the lab's backoff in milliseconds):
/// exit 42 with its line and the delete command, the third line too (the
/// entry holds it now); no `arn` line.
#[test]
fn a_key_that_never_answers_is_not_handed_over() {
    let w = World::new();
    let key = deployer_key("Nv9+");
    let mut s = Session::start(w.handover(&key, &[("FAKE_AWS_KEY_USERS", "9002:ai-env-ops 9003:ai-env-runtime")]), key.json.as_bytes(), true);
    converse(&mut s, &key);
    let done = s.finish();
    assert_eq!(done.code(), Some(42), "stderr:\n{}", done.stderr);
    assert_eq!(done.stdout, format!("id {}\n", key.id));
    let retries: Vec<&str> = done.stderr.lines().filter(|l| l.contains("does not answer yet")).collect();
    assert_eq!(retries.len(), 7, "{}", done.stderr);
    assert_eq!(retries[0], "ai-env: the key ...9001 does not answer yet (1/8: IAM propagation)");
    let end = format!("ai-env: creds deployer-key: the key ...9001 never answered (8 tries, 5 s apart; last: InvalidClientTokenId): it was NOT handed over\n{}", cleanup(DEPLOYER, &key.id, true));
    assert!(done.stderr.ends_with(&end), "{}", done.stderr);
    assert!(!done.stderr.contains("ai-env: cancelled"));
    assert_eq!(w.sts_calls().len(), 8);
    assert_eq!(w.last_audit().unwrap()["detail"]["result"], "never-answered");
    done.never_shows(&key.secret, "the secret");
    assert_eq!(done.tty, prompts_only());
}

/// sts answers as another identity: exit 9, the `arn` line, the `as deployer`
/// texts with `creds deployer-key:` and `: it was NOT handed over`, and the
/// delete command with its third line: another user, the root, another
/// account (`--account`), another ARN (`state/infra.toml`).
#[test]
fn an_answer_as_another_identity_is_not_handed_over() {
    let w = World::new();
    let key = deployer_key("An1+");
    let cases = [
        ("9001:rust", format!("the key ...9001 answers as arn:aws:iam::{STACK}:user/rust, not {DEPLOYER}"), format!("arn:aws:iam::{STACK}:user/rust"), "other-principal"),
        ("9001:root", "the key ...9001 is the account ROOT's: never paste it here (the deployer's key is its own Strongbox entry); delete root's access key".to_string(), format!("arn:aws:iam::{STACK}:root"), "root"),
        (
            "9001:ai-env-deployer@999999999999",
            format!("the key ...9001 is {DEPLOYER} of account 999999999999, but the stack (--account) is in account {STACK}"),
            format!("arn:aws:iam::999999999999:user/{DEPLOYER}"),
            "other-account",
        ),
    ];
    for (users, why, arn, result) in cases {
        let mut s = Session::start(w.handover(&key, &[("FAKE_AWS_KEY_USERS", users)]), key.json.as_bytes(), true);
        converse(&mut s, &key);
        let done = s.finish();
        assert_eq!(done.code(), Some(9), "{users}: {}", done.stderr);
        assert_eq!(done.stdout, format!("id {}\narn {arn}\n", key.id), "{users}");
        assert!(done.stderr.ends_with(&format!("ai-env: creds deployer-key: {why}: it was NOT handed over\n{}", cleanup(DEPLOYER, &key.id, true))), "{users}: {}", done.stderr);
        assert_eq!(w.last_audit().unwrap()["detail"]["result"], result, "{users}");
        done.never_shows(&key.secret, "the secret");
    }
    // The stack's deployer as state/infra.toml records it, under another path: its exact ARN decides.
    w.env.infra_state(&format!("stack = \"dev\"\naccount_id = \"{STACK}\"\ndeployer_user_arn = \"arn:aws:iam::{STACK}:user/x/{DEPLOYER}\"\n"));
    let mut cmd = w.cmd(&[]);
    cmd.env("FAKE_PB_EXPECT_1", &key.id).env("FAKE_PB_EXPECT_2", &key.secret);
    let mut s = Session::start(cmd, key.json.as_bytes(), true);
    converse(&mut s, &key);
    let done = s.finish();
    assert_eq!(done.code(), Some(9), "{}", done.stderr);
    let why = format!("the key ...9001 answers as arn:aws:iam::{STACK}:user/{DEPLOYER}, but the stack's deployer is arn:aws:iam::{STACK}:user/x/{DEPLOYER} (state/infra.toml)");
    assert!(done.stderr.ends_with(&format!("ai-env: creds deployer-key: {why}: it was NOT handed over\n{}", cleanup(DEPLOYER, &key.id, true))), "{}", done.stderr);
    assert_eq!(w.last_audit().unwrap()["detail"]["result"], "other-arn");
}

/// D8: at a terminal (a person, not the recipe that captures them) neither
/// command writes its `id` or `arn` line: the hand-over's terminal shows the
/// prompts alone and `creds aws-verify`'s nothing, the full id is nowhere,
/// and the verdicts are on stderr as ever.
#[test]
fn the_id_and_arn_lines_never_reach_a_terminal() {
    let w = World::new();
    let on = Attach { controlling: true, stdin: false, stdout: true };
    let key = deployer_key("Tt7+");
    let mut s = Session::start_with(w.handover(&key, &[]), key.json.as_bytes(), on);
    converse(&mut s, &key);
    let done = s.finish();
    assert_eq!(done.code(), Some(0), "stderr:\n{}", done.stderr);
    assert_eq!(done.tty, prompts_only(), "no id or arn line on the terminal");
    done.never_shows_id(&key.id, 0, "the full key id");
    assert!(done.stderr.ends_with("ai-env: the access key ...9001 answers as user/ai-env-deployer: it is in Strongbox only; ai-env as deployer -- … asks for it\n"), "{}", done.stderr);

    // `creds aws-verify` of a sealed ops key, at a terminal.
    w.env.keystore(super::creds::KEY, true);
    let (id, ops_secret) = (key_id("9023"), secret("Av8+"));
    let sealed = super::creds::piped(&mut w.env.creds(&["aws-set", "--user", "ai-env-ops"]), create_access_key_json("ai-env-ops", &id, &ops_secret).as_bytes());
    assert_eq!(sealed.status.code(), Some(0), "{}", stderr(&sealed));
    let mut cmd = w.env.creds(&["aws-verify", "--user", "ai-env-ops"]);
    cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1").env("FAKE_AWS_KEY_USERS", "9023:ai-env-ops");
    let done = Session::start_with(cmd, b"", on).finish();
    assert_eq!(done.code(), Some(0), "{}", done.stderr);
    assert_eq!(done.tty, "", "nothing on the terminal");
    done.never_shows_id(&id, 0, "the ops key's full id");
    assert!(done.stderr.ends_with("ai-env: aws-verify: the sealed key ...9023 answers as user/ai-env-ops\n"), "{}", done.stderr);
}

/// osascript cannot set the clipboard: the hand-over stops before anything is
/// shown (no prompt on the terminal), exit 1 with the IAM console route and
/// the delete command. osascript may have set the value before it failed (a
/// timeout, an answer that is not a change count), so the clipboard is
/// cleared first and the text says how that went (D14). `--clipboard-check`
/// places a marker the same way, waits for Enter, clears it (or leaves
/// another copy alone), and refuses without a terminal; it reads no stdin, so
/// a terminal on its stdin (as Mike runs it) is no refusal.
#[test]
fn a_clipboard_failure_stops_before_anything_is_shown() {
    let w = World::new();
    let key = deployer_key("Cb2+");
    let route = |left: &str| {
        format!(
            "ai-env: the clipboard could not be set this-Mac-only and concealed ({CLIPBOARD_REFUSED}): {left}. Delete the key, then create the deployer's key in the IAM console (Users → {DEPLOYER} → Security credentials → Create access key), copy both into Strongbox there (never download the .csv), and check it with: ai-env as deployer -- true\n{}",
            cleanup(DEPLOYER, &key.id, false)
        )
    };
    for (fail, left, osa) in [
        ("set", "cleared, so nothing of the key is on it".to_string(), ["fail set", "clear cleared"]),
        ("1", format!("it could not be cleared either ({CLIPBOARD_REFUSED}): the key may be on it, clear it yourself"), ["fail set", "fail clear"]),
    ] {
        w.fresh_clipboard();
        let done = Session::start(w.handover(&key, &[("FAKE_OSA_FAIL", fail)]), key.json.as_bytes(), true).finish();
        assert_eq!(done.code(), Some(1), "{fail}: {}", done.stderr);
        assert_eq!(done.stdout, format!("id {}\n", key.id));
        assert!(done.stderr.ends_with(&route(&left)), "{fail}: {}", done.stderr);
        assert!(!done.stderr.contains("1/2:") && !done.stderr.contains("nothing was put on it"), "{}", done.stderr);
        assert!(done.tty.is_empty(), "nothing on the terminal: {:?}", done.tty);
        assert_eq!(w.osa(), osa, "{fail}: the failed place, then the clear");
        assert_eq!(w.last_audit().unwrap()["detail"]["result"], "clipboard");
        done.never_shows(&key.secret, "the secret");
    }

    // --clipboard-check: the marker, Enter, cleared; no stdin read, no audit row.
    let audits = audit_rows(&w.env).len();
    w.fresh_clipboard();
    let mut s = Session::start(w.cmd(&["--clipboard-check"]), b"", true);
    s.answer(TRIED, 1, "");
    let done = s.finish();
    assert_eq!(done.code(), Some(0), "{}", done.stderr);
    let lines: Vec<&str> = done.stderr.lines().collect();
    assert_eq!(lines.len(), 2, "{}", done.stderr);
    let marker = lines[0].strip_prefix("ai-env: clipboard check: the marker ").and_then(|l| l.strip_suffix(" is on the clipboard, this Mac only and concealed: try to paste it on another Apple device now; it must NOT paste there")).unwrap_or_else(|| panic!("{}", lines[0]));
    assert!(marker.len() == 12 && marker.bytes().all(|b| b.is_ascii_alphanumeric()), "{marker}");
    assert_eq!(lines[1], "ai-env: cleared the clipboard");
    assert_eq!((done.stdout.as_str(), done.tty.as_str()), ("", "press Enter here when you have tried: \n"));
    assert_eq!(w.osa(), ["set 1 unchecked", "clear-if cleared"]);
    assert_eq!(audit_rows(&w.env).len(), audits);
    // Run from a terminal, its stdin that terminal too: the same.
    w.fresh_clipboard();
    let mut s = Session::start_with(w.cmd(&["--clipboard-check"]), b"", Attach { controlling: true, stdin: true, stdout: false });
    s.answer(TRIED, 1, "");
    let done = s.finish();
    assert_eq!(done.code(), Some(0), "{}", done.stderr);
    assert!(done.stderr.starts_with("ai-env: clipboard check: the marker ") && done.stderr.ends_with("\nai-env: cleared the clipboard\n"), "{}", done.stderr);
    assert_eq!(w.osa(), ["set 1 unchecked", "clear-if cleared"]);
    // Another copy came since: left alone, with the warning.
    let mut cmd = w.cmd(&["--clipboard-check"]);
    cmd.env("FAKE_PB_TOUCH", "1");
    let mut s = Session::start(cmd, b"", true);
    s.answer(TRIED, 1, "");
    let done = s.finish();
    assert_eq!(done.code(), Some(0), "{}", done.stderr);
    assert!(done.stderr.ends_with("ai-env: warning: the clipboard changed since (another copy): left as it is — make sure the key is not on it\n"), "{}", done.stderr);
    // osascript refuses: exit 1, nothing on the terminal, the clipboard cleared after the failed place (or not).
    for (fail, left, osa) in [("set", "cleared, so the marker is not on it".to_string(), ["fail set", "clear cleared"]), ("1", format!("it could not be cleared either ({CLIPBOARD_REFUSED}): clear it yourself"), ["fail set", "fail clear"])] {
        w.fresh_clipboard();
        let mut cmd = w.cmd(&["--clipboard-check"]);
        cmd.env("FAKE_OSA_FAIL", fail);
        let done = Session::start(cmd, b"", true).finish();
        assert_eq!(done.code(), Some(1), "{fail}: {}", done.stderr);
        assert_eq!(done.stderr, format!("ai-env: clipboard check: the clipboard could not be set this-Mac-only and concealed ({CLIPBOARD_REFUSED}): {left}\n"));
        assert!(done.tty.is_empty());
        assert_eq!(w.osa(), osa, "{fail}");
    }
    // No terminal: nothing is placed.
    let before = w.osa().len();
    let done = Session::start(w.cmd(&["--clipboard-check"]), b"", false).finish();
    assert_eq!(done.code(), Some(5), "{}", done.stderr);
    assert_eq!(w.osa().len(), before, "nothing placed");
    // With --account: clap refuses the pair.
    let out = run(&mut w.cmd(&["--clipboard-check", "--account", STACK]));
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

/// D14 (recheck), A15: a value pasted back that does not match goes back on
/// the clipboard; when that place fails (osascript may have set the value
/// before it failed), the rounds end, the clipboard is cleared, and the
/// hand-over fails with A15's text once, `cleared, so nothing of the key is on
/// it`, or `it could not be cleared either (…): the key may be on it` when the
/// clear fails too, never with the paste-back's own warning beside it. A
/// paste-back that ends otherwise (here a cancel) with the clear refused says
/// that warning, once.
#[test]
fn a_failed_place_at_the_paste_back_clears_the_clipboard_and_says_so_once() {
    let w = World::new();
    let key = deployer_key("Rp4+");
    let wrong = key_id("9098");
    let route = |left: &str| {
        format!(
            "ai-env: the clipboard could not be set this-Mac-only and concealed ({CLIPBOARD_REFUSED}): {left}. Delete the key, then create the deployer's key in the IAM console (Users → {DEPLOYER} → Security credentials → Create access key), copy both into Strongbox there (never download the .csv), and check it with: ai-env as deployer -- true\n{}",
            cleanup(DEPLOYER, &key.id, false)
        )
    };
    // The third set is the id going back on the clipboard after round 1.
    for (fail, left, last) in [
        ("set@3", "cleared, so nothing of the key is on it".to_string(), "clear cleared"),
        ("set@3 clear", format!("it could not be cleared either ({CLIPBOARD_REFUSED}): the key may be on it, clear it yourself"), "fail clear"),
    ] {
        w.fresh_clipboard();
        let mut s = Session::start(w.handover(&key, &[("FAKE_OSA_FAIL", fail)]), key.json.as_bytes(), true);
        s.answer(PASTED, 1, "");
        s.answer(SAVED, 1, "");
        s.answer(ID_BACK, 1, &wrong);
        s.answer(SECRET_BACK, 1, &key.secret);
        let done = s.finish();
        assert_eq!(done.code(), Some(1), "{fail}: {}", done.stderr);
        assert_eq!(done.stdout, format!("id {}\n", key.id), "{fail}: no arn line: sts was never asked");
        assert!(done.stderr.ends_with(&route(&left)), "{fail}: {}", done.stderr);
        assert_eq!(done.stderr.matches("the clipboard could not be").count(), 1, "{fail}: A15's text alone, no warning beside it: {}", done.stderr);
        assert!(!done.stderr.contains("warning:") && !done.stderr.contains("nothing was put on it") && !done.stderr.contains("it is on the clipboard again"), "{fail}: {}", done.stderr);
        assert_eq!(w.osa(), ["set 1 match", "clear-if cleared", "set 2 match", "clear-if cleared", "fail set", last], "{fail}: the failed re-place, then the clear");
        assert_eq!(w.last_audit().unwrap()["detail"]["result"], "clipboard", "{fail}");
        assert!(w.sts_calls().is_empty(), "{fail}: {:?}", w.sts_calls());
        assert_eq!((done.tty.matches(ID_BACK).count(), done.tty.matches(SAVED).count()), (1, 1), "{fail}: no Enter prompt for a value never placed: {}", done.tty);
        done.never_shows(&key.secret, "the secret");
        done.never_shows_id(&wrong, 0, "the wrong id pasted back");
        done.never_shows_id(&key.id, 1, "the full key id");
        assert!(done.echo, "{fail}");
    }
    // A cancel at the paste-back with the clear refused: the paste-back's own warning, once, then the cancel's line.
    w.fresh_clipboard();
    let mut s = Session::start(w.handover(&key, &[("FAKE_OSA_FAIL", "clear")]), key.json.as_bytes(), true);
    s.answer(PASTED, 1, "");
    s.answer(SAVED, 1, "");
    s.answer(ID_BACK, 1, "");
    let done = s.finish();
    assert_eq!(done.code(), Some(3), "{}", done.stderr);
    let end = format!(
        "ai-env: warning: the clipboard could not be cleared ({CLIPBOARD_REFUSED}): clear it yourself\nai-env: creds deployer-key: nothing was pasted back: cancelled, it was NOT handed over\n{}",
        cleanup(DEPLOYER, &key.id, false)
    );
    assert!(done.stderr.ends_with(&end), "{}", done.stderr);
    assert_eq!(done.stderr.matches("could not be cleared").count(), 1, "{}", done.stderr);
    assert_eq!(w.osa(), ["set 1 match", "clear-if cleared", "set 2 match", "clear-if cleared", "fail clear"]);
    assert_eq!(w.last_audit().unwrap()["detail"]["result"], "cancelled");
}

/// D11: the hand-over's prompts read the terminal and nothing else, even in a
/// debug build with `AI_ENV_PASTE_STDIN=1` exported (a test session's
/// leftover in the shell of a `make operator-keys`): its stdin is the JSON
/// pipe, whose end of file would otherwise answer every Enter prompt and the
/// first paste-back, cancelling a hand-over nobody saw.
#[test]
fn the_handover_never_reads_its_prompts_from_stdin_even_with_the_debug_knob() {
    let w = World::new();
    let key = deployer_key("Kn5+");
    let mut cmd = w.handover(&key, &[]);
    cmd.env("AI_ENV_PASTE_STDIN", "1");
    let mut s = Session::start(cmd, key.json.as_bytes(), true);
    converse(&mut s, &key);
    let done = s.finish();
    assert_eq!(done.code(), Some(0), "stderr:\n{}", done.stderr);
    assert_eq!(done.tty, prompts_only(), "every prompt on the terminal, none on stderr");
    assert!(!done.stderr.contains("press Enter") && !done.stderr.contains("(from Strongbox): "), "{}", done.stderr);
    assert_eq!(w.osa(), ["set 1 match", "clear-if cleared", "set 2 match", "clear-if cleared", "clear cleared"]);
    done.never_shows(&key.secret, "the secret");
    assert!(done.echo);
}

/// The stop's audit row: result `cancelled`, stamped between `from` and now.
fn assert_stop_row(w: &World, from: u64) {
    let row = w.last_audit().expect("the stop's audit row");
    for (k, v) in [("user", DEPLOYER), ("key_id_last4", DEPLOYER_TAIL), ("result", "cancelled")] {
        assert_eq!(row["detail"][k], v, "{k}: {row}");
    }
    let at = row["ts"].as_str().and_then(ai_env_cli::wire::time::parse_rfc3339_utc).unwrap_or_else(|| panic!("{row}"));
    assert!(from <= at && at <= ai_env_cli::wire::time::unix_now(), "stamped when it stopped: {row}");
}

/// Ctrl-C at a prompt (echo off) ends the hand-over through the stop handler:
/// exit 130, the id it had put on the clipboard cleared, the delete command on
/// stderr, the terminal's echo back on, the audit row (`cancelled`). A Ctrl-C
/// at a paste-back prompt clears what was copied from Strongbox the same way,
/// or warns that it could not. A SIGTERM once the paste-back matched (sts
/// still retrying, real 5 s steps), when the clipboard holds nothing of the
/// key any more: exit 143 and the delete command with the third line, the
/// clipboard left alone.
#[test]
fn ctrl_c_during_the_handover_prints_the_delete_command_and_restores_echo() {
    let w = World::new();
    let key = deployer_key("Cc3+");
    let from = ai_env_cli::wire::time::unix_now();
    let mut s = Session::start(w.handover(&key, &[]), key.json.as_bytes(), true);
    s.wait(&format!("{PASTED:?}"), &|s| text(&s.tty.0).contains(PASTED));
    s.wait("echo off", &|s| !echoes(&s.master));
    // Ctrl-C on the terminal: SIGINT to its foreground process group, the child's.
    (&s.master).write_all(&[0x03]).unwrap();
    let done = s.finish();
    assert_eq!(done.code(), Some(130), "stderr:\n{}", done.stderr);
    assert!(done.stderr.ends_with(&format!("ai-env: {}", cleanup(DEPLOYER, &key.id, false))) && !done.stderr.contains("could not be cleared"), "{}", done.stderr);
    assert!(done.echo, "the stop handler restored the terminal's echo");
    assert_eq!(done.stdout, format!("id {}\n", key.id));
    assert_eq!(w.osa(), ["set 1 match", "clear cleared"], "the id was on the clipboard when it stopped: cleared");
    assert_stop_row(&w, from);
    done.never_shows(&key.secret, "the secret");
    done.never_shows_id(&key.id, 1, "the full key id");

    // At the paste-back, the clear refused: the warning, then the note.
    w.fresh_clipboard();
    let mut s = Session::start(w.handover(&key, &[("FAKE_OSA_FAIL", "clear")]), key.json.as_bytes(), true);
    s.answer(PASTED, 1, "");
    s.answer(SAVED, 1, "");
    s.wait(&format!("{ID_BACK:?}"), &|s| text(&s.tty.0).contains(ID_BACK));
    s.wait("echo off", &|s| !echoes(&s.master));
    (&s.master).write_all(&[0x03]).unwrap();
    let done = s.finish();
    assert_eq!(done.code(), Some(130), "stderr:\n{}", done.stderr);
    assert!(done.stderr.ends_with(&format!("ai-env: warning: the clipboard could not be cleared: clear it yourself\nai-env: {}", cleanup(DEPLOYER, &key.id, false))), "{}", done.stderr);
    assert!(done.echo);
    assert_eq!(w.osa(), ["set 1 match", "clear-if cleared", "set 2 match", "clear-if cleared", "fail clear"]);
    assert_stop_row(&w, from);

    w.fresh_clipboard();
    let rows = audit_rows(&w.env).len();
    let mut cmd = w.handover(&key, &[("FAKE_AWS_KEY_USERS", "9002:ai-env-ops")]);
    cmd.env_remove("AI_ENV_BRIDGE_LAB_BACKOFF_MS");
    let mut s = Session::start(cmd, key.json.as_bytes(), true);
    converse(&mut s, &key);
    s.wait_stderr("does not answer yet (1/8: IAM propagation)");
    let pid = i32::try_from(s.child.id()).unwrap();
    // SAFETY: kill(2) on the child this test started, which is still running (it sleeps 5 s between tries).
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let done = s.finish();
    assert_eq!(done.code(), Some(143), "stderr:\n{}", done.stderr);
    assert!(done.stderr.ends_with(&format!("ai-env: {}", cleanup(DEPLOYER, &key.id, true))), "{}", done.stderr);
    assert!(done.echo);
    assert_eq!(done.tty, prompts_only());
    assert_eq!(w.osa(), ["set 1 match", "clear-if cleared", "set 2 match", "clear-if cleared", "clear cleared"], "cleared once, at the match");
    assert_eq!(audit_rows(&w.env).len(), rows + 1, "one row");
    assert_stop_row(&w, from);
    done.never_shows(&key.secret, "the secret");
}
