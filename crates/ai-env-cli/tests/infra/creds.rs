//! `ai-env creds aws-set` (plan D23) through the binary. PATH is a temp bin
//! dir holding the shared fake age (tests/fakes/age.sh, which hex-encodes, so
//! "no plaintext on disk" is testable) and the fake aws (tests/fakes/aws.sh),
//! then /usr/bin:/bin for the tools those scripts use. The keystore key is a
//! fake key dir built the way tests/cli.rs builds one, with its public test
//! recipients. HOME, AI_ENV_DIR, AI_ENV_BRIDGE_DIR and TMPDIR all live in one
//! temp tree, so walking that tree covers every file the run could write.
//! Every access key id and secret is built at run time.
use super::common::*;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

pub(crate) const USER: &str = "ai-env-runtime";
pub(crate) const KEY: &str = "ai-env-bridge";
/// The public SE tag recipient and X25519 recovery recipient of tests/cli.rs.
const SE_REC: &str = "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";

fn fake(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fakes").join(name)
}

/// One temp tree: `bin/` (the fakes), `keys/` (AI_ENV_DIR), `bridge/`
/// (AI_ENV_BRIDGE_DIR), `tmp/` (TMPDIR) and the two fake logs.
pub(crate) struct Env {
    tmp: tempfile::TempDir,
}

impl Env {
    pub(crate) fn new(with_aws: bool) -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(tmp.path().join("tmp")).unwrap();
        let install = |src: &str, name: &str| {
            let dst = bin.join(name);
            fs::copy(fake(src), &dst).unwrap();
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o755)).unwrap();
        };
        for name in ["age", "age-keygen", "age-plugin-se"] {
            install("age.sh", name);
        }
        if with_aws {
            install("aws.sh", "aws");
        }
        Env { tmp }
    }

    pub(crate) fn root(&self) -> &Path {
        self.tmp.path()
    }

    pub(crate) fn bin(&self) -> PathBuf {
        self.root().join("bin")
    }

    /// `keys/keys/<name>/` with an SE identity stub and, when `recovery`, the
    /// X25519 recovery recipient beside the tag recipient.
    pub(crate) fn keystore(&self, name: &str, recovery: bool) {
        let dir = self.root().join("keys").join("keys").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("identity.txt"), format!("# public key: {SE_REC}\nAGE-PLUGIN-SE-1FAKEFAKE\n")).unwrap();
        let recipients = if recovery { format!("{SE_REC}\n{X_REC}\n") } else { format!("{SE_REC}\n") };
        fs::write(dir.join("recipients.txt"), recipients).unwrap();
        fs::write(dir.join("meta.toml"), "created = \"2026-09-29\"\naccess_control = \"none\"\n").unwrap();
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut all = vec!["aws-set"];
        all.extend_from_slice(args);
        self.creds(&all)
    }

    /// `ai-env creds <args>` with the fakes on PATH and their logs (no other
    /// fake knob: [`ai_env`] removed the developer's), run as `ai-env as ops`
    /// would leave it (S8 operators: the ops key and its marker; a test that
    /// needs another identity sets it). A hidden paste reads the (piped or
    /// null) stdin, never this run's terminal.
    pub(crate) fn creds(&self, args: &[&str]) -> Command {
        let mut all = vec!["creds"];
        all.extend_from_slice(args);
        let mut cmd = ai_env(self.root(), &all);
        cmd.env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("TMPDIR", self.root().join("tmp"))
            .env("FAKE_AGE_LOG", self.age_log())
            .env("FAKE_AWS_LOG", self.aws_log())
            .env("AI_ENV_PASTE_STDIN", "1")
            .envs(super::aws_keys::identity_env("ops", super::aws_keys::OPS_TAIL));
        cmd
    }

    pub(crate) fn credentials(&self) -> PathBuf {
        self.root().join("bridge").join("credentials")
    }

    pub(crate) fn aws_env(&self) -> PathBuf {
        self.credentials().join("aws.env")
    }

    pub(crate) fn audit(&self) -> PathBuf {
        self.root().join("bridge").join("audit.jsonl")
    }

    pub(crate) fn age_log(&self) -> PathBuf {
        self.root().join("age.log")
    }

    pub(crate) fn aws_log(&self) -> PathBuf {
        self.root().join("aws.log")
    }

    /// The fake age's `-d`: the sealed container back to its plaintext. Only
    /// PATH reaches it, so no knob of the developer's shell (`FAKE_AGE_HANG`)
    /// does; bounded like [`run`].
    pub(crate) fn open(&self, container_text: &str) -> String {
        let c = ai_env_cli::container::read(container_text).expect("a valid ai-env container");
        let identity = self.root().join("keys").join("keys").join(KEY).join("identity.txt");
        let mut child = Command::new(self.bin().join("age"))
            .args(["-d", "-i"])
            .arg(&identity)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&c.data).unwrap();
        let out = finish(child, RUN_LIMIT, "fake age -d");
        assert!(out.status.success(), "fake age -d: {}", stderr(&out));
        String::from_utf8(out.stdout).unwrap()
    }
}

/// Run with `input` on a pipe that is closed after writing, bounded like
/// [`run`].
pub(crate) fn piped(cmd: &mut Command, input: &[u8]) -> Output {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
    child.stdin.take().unwrap().write_all(input).unwrap();
    finish(child, RUN_LIMIT, "ai-env with a piped stdin")
}

/// A stdout whose reader is gone before the child starts: every write fails
/// with EPIPE (Rust ignores SIGPIPE), the extreme of `--check | head -1`.
fn closed_stdout() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    Stdio::from(writer)
}

/// [`run`] with stdout a [`closed_stdout`] (only stderr is captured).
fn run_closed_stdout(cmd: &mut Command) -> Output {
    let child = cmd.stdout(closed_stdout()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
    finish(child, RUN_LIMIT, "ai-env with a closed stdout")
}

/// Wait for `child`, killing it and failing the test after 30 s: a child that
/// reads a stdin nobody writes to would otherwise hang the suite.
pub(crate) fn wait_bounded(child: std::process::Child, what: &str) -> Output {
    finish(child, Duration::from_secs(30), what)
}

/// A test access key: `AKIA` + `CREDCRED` + the tag twice (20), and 40
/// characters of the secret alphabet ending in the lowercased tag.
pub(crate) struct TestKey {
    pub(crate) id: String,
    pub(crate) secret: String,
}

pub(crate) fn test_key(tag: &str) -> TestKey {
    assert_eq!(tag.len(), 4);
    TestKey { id: format!("AKIA{}{}", "CRED".repeat(2), tag.repeat(2)), secret: format!("{}{}", "Tq8+".repeat(9), tag.to_lowercase()) }
}

/// What `aws iam create-access-key --output json` prints.
pub(crate) fn key_json(user: &str, key: &TestKey, status: &str) -> String {
    format!(
        "{{\n    \"AccessKey\": {{\n        \"UserName\": \"{user}\",\n        \"AccessKeyId\": \"{}\",\n        \"Status\": \"{status}\",\n        \"SecretAccessKey\": \"{}\",\n        \"CreateDate\": \"2026-09-29T10:00:00+00:00\"\n    }}\n}}\n",
        key.id, key.secret
    )
}

pub(crate) fn expected_env(key: &TestKey) -> String {
    format!("AWS_ACCESS_KEY_ID={}\nAWS_SECRET_ACCESS_KEY={}\n", key.id, key.secret)
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            files_under(&path, out);
        } else if meta.is_file() {
            out.push(path);
        }
    }
}

/// The length of the pieces [`holds`] looks for.
const PIECE: usize = 16;

/// Does `hay` hold `needle`, or any [`PIECE`]-byte piece of it (a truncated
/// copy counts as much as a whole one)?
pub(crate) fn holds(hay: &[u8], needle: &str) -> bool {
    let w = needle.len().min(PIECE);
    w > 0 && needle.as_bytes().windows(w).any(|piece| hay.windows(w).any(|h| h == piece))
}

/// Neither stdout nor stderr of `out` holds `needle` or a piece of it; the
/// message names the stream, never the value.
pub(crate) fn assert_unprinted(out: &Output, needle: &str, what: &str) {
    for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        assert!(!holds(bytes, needle), "{what} (or a {PIECE}-byte piece of it) is in the {stream}");
    }
}

/// `needle`, or any piece of it, appears in no file anywhere under `root`.
pub(crate) fn assert_nowhere(root: &Path, needle: &str, what: &str) {
    let mut files = Vec::new();
    files_under(root, &mut files);
    assert!(!files.is_empty());
    for f in files {
        let bytes = fs::read(&f).unwrap();
        assert!(!holds(&bytes, needle), "{what} (or a {PIECE}-byte piece of it) found in {}", f.display());
    }
}

pub(crate) fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

pub(crate) fn audit_rows(env: &Env) -> Vec<serde_json::Value> {
    fs::read_to_string(env.audit()).unwrap_or_default().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

/// The cleanup note's delete command as the harness's identity (`ai-env as ops`) gets it: started with the deployer's
/// runner, which can run it on this Mac, where a bare `aws` has no credentials (D13).
fn delete_command(user: &str, id: &str) -> String {
    format!("  ai-env as deployer -- aws iam delete-access-key --user-name {user} --access-key-id {id} --region eu-central-1\n")
}

#[test]
fn creds_check_fails_without_the_keystore_key() {
    let env = Env::new(true);
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(5), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).lines().any(|l| l.starts_with("[NO ] keystore key")), "{}", stdout(&out));
    assert!(stderr(&out).contains("ai-env keygen ai-env-bridge"), "{}", stderr(&out));

    // Sealing hits the same preflight after the key was read: nothing is
    // written and the operator gets the command that deletes the new key.
    let key = test_key("NOKY");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(5), "stderr {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("ai-env keygen ai-env-bridge") && err.contains("was NOT stored"), "{err}");
    assert!(err.contains(&delete_command(USER, &key.id)), "{err}");
    assert!(!err.contains(&key.secret) && !stdout(&out).contains(&key.secret));
    assert!(!env.credentials().exists(), "nothing may be created");
}

#[test]
fn creds_check_passes_with_the_fakes_and_never_reads_stdin() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    // stdin stays an open pipe nobody writes to: a read would block until the deadline.
    let mut child = env.cmd(&["--check"]).env("FAKE_AWS_KEYS", "1").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let held = child.stdin.take();
    let out = wait_bounded(child, "--check blocked (reading stdin?)");
    drop(held);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "stdout {text} stderr {}", stderr(&out));
    let rows: Vec<&str> = text.lines().collect();
    assert_eq!(rows.len(), 5, "{text}");
    assert!(rows.iter().all(|r| r.starts_with("[ok ] ")), "{text}");
    for want in ["keystore key ai-env-bridge", "has a recovery recipient", "age v1.3.2", "aws.env (new; ", "has 1 access key(s)"] {
        assert!(text.contains(want), "{want:?} missing from {text}");
    }
    let aws = fs::read_to_string(env.aws_log()).unwrap();
    assert_eq!(aws.trim(), format!("iam list-access-keys --user-name {USER} --region eu-central-1 --output json"));
    assert!(!env.credentials().exists() && !env.audit().exists(), "--check writes nothing");
}

#[test]
fn creds_check_refuses_a_user_that_has_two_keys() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let out = run(env.cmd(&["--check"]).env("FAKE_AWS_KEYS", "2"));
    assert_eq!(out.status.code(), Some(9), "stdout {} stderr {}", stdout(&out), stderr(&out));
    let text = stdout(&out);
    let row = text.lines().find(|l| l.starts_with("[NO ]")).expect("a failing row");
    // D13: the delete command starts with the runner that can run it on this Mac, where a bare `aws` has no
    // credentials once root's key is retired: the deployer's for the operator `ai-env as ops` leaves (and for the
    // deployer's runner, which make ops-key ROTATE=1 runs this check under).
    let two = |runner: &str| {
        format!(
            "[NO ] IAM user {USER} already has 2 access keys (AKIAFAKE{:012}, AKIAFAKE{:012}), the IAM maximum: delete one first ({runner}aws iam delete-access-key --user-name {USER} --access-key-id <id> --region eu-central-1)",
            1, 2
        )
    };
    assert_eq!(row, two("ai-env as deployer -- "), "{text}");
    assert_eq!(text.lines().filter(|l| l.starts_with("[ok ] ")).count(), 4, "{text}");
    let mut cmd = env.cmd(&["--check", "--user", "ai-env-ops"]);
    cmd.env("FAKE_AWS_KEYS", "2").envs(super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL));
    let out = run(&mut cmd);
    assert_eq!(out.status.code(), Some(9), "{}", stdout(&out));
    assert!(stdout(&out).contains("delete one first (ai-env as deployer -- aws iam delete-access-key --user-name ai-env-ops --access-key-id <id> --region eu-central-1)"), "{}", stdout(&out));
    // Under the account root's runner (make operator-keys, the bootstrap) the root's own; under an ambient one (another
    // account's own credentials, where the stack's deployer does not exist) the ambient runner's.
    for (word, caller, runner) in [("root", "root", "ai-env as root -- "), ("ambient", "rust", "ai-env as ambient -- ")] {
        let mut cmd = env.cmd(&["--check"]);
        cmd.env("FAKE_AWS_KEYS", "2").env("AI_ENV_BRIDGE_AS", word).env("FAKE_AWS_CALLER", caller).env_remove("AWS_ACCESS_KEY_ID").env_remove("AWS_SECRET_ACCESS_KEY");
        let out = run(&mut cmd);
        assert_eq!(out.status.code(), Some(9), "{word}: stdout {} stderr {}", stdout(&out), stderr(&out));
        assert!(stdout(&out).lines().any(|l| l == two(runner)), "{word}: {}", stdout(&out));
    }

    // An aws failure (expired session) fails the check as an AWS error.
    let out = run(env.cmd(&["--check"]).env("FAKE_AWS_FAIL", "1"));
    assert_eq!(out.status.code(), Some(7), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains("[NO ] aws iam list-access-keys") && stdout(&out).contains("ExpiredToken"), "{}", stdout(&out));
}

#[test]
fn creds_check_names_a_missing_iam_user() {
    // Before `make deploy` the user does not exist: the row says so instead of
    // echoing the API error, and still fails (runtime-key needs the user).
    let env = Env::new(true);
    env.keystore(KEY, true);
    let out = run(env.cmd(&["--check"]).env("FAKE_AWS_FAIL", "nouser"));
    assert_eq!(out.status.code(), Some(7), "stdout {} stderr {}", stdout(&out), stderr(&out));
    let text = stdout(&out);
    let failing: Vec<&str> = text.lines().filter(|l| l.starts_with("[NO ]")).collect();
    assert_eq!(failing, [format!("[NO ] IAM user {USER} does not exist yet (make deploy creates it)")], "{text}");
    assert_eq!(text.lines().filter(|l| l.starts_with("[ok ] ")).count(), 4, "{text}");
    assert!(!text.contains("NoSuchEntity"), "{text}");
}

#[test]
fn creds_check_fails_on_a_closed_stdout() {
    // `--check | head -1`: the rows cannot be written, yet a failing check
    // keeps its exit class (a broken pipe alone would be exit 0).
    let env = Env::new(true);
    let out = run_closed_stdout(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(5), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("ai-env keygen ai-env-bridge"), "{}", stderr(&out));
    // The class is the first failing row's, even when that row is printed last.
    env.keystore(KEY, true);
    let out = run_closed_stdout(env.cmd(&["--check"]).env("FAKE_AWS_KEYS", "2"));
    assert_eq!(out.status.code(), Some(9), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("already has 2 access keys"), "{}", stderr(&out));
    // Every row passed: the closed pipe is the documented silent exit 0.
    let out = run_closed_stdout(env.cmd(&["--check"]).env("FAKE_AWS_KEYS", "1"));
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    assert_eq!(stderr(&out), "");
}

#[test]
fn creds_check_fails_without_the_aws_cli() {
    if ["/usr/bin/aws", "/bin/aws"].iter().any(|p| Path::new(p).exists()) {
        eprintln!("skipped: a system aws on /usr/bin:/bin cannot be hidden from PATH");
        return;
    }
    let env = Env::new(false);
    env.keystore(KEY, true);
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(1), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains("[NO ] aws CLI not found on PATH"), "{}", stdout(&out));
}

#[test]
fn creds_aws_set_seals_without_plaintext_anywhere() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let key = test_key("WXYZ");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert_eq!(stdout(&out), format!("sealed {USER} access key ...WXYZ into {} (key {KEY})\n", env.aws_env().display()));
    assert_eq!(stderr(&out), "");

    // 0600 container in a 0700 dir; it decrypts to exactly render_env's text.
    assert_eq!(mode(&env.aws_env()), 0o600);
    assert_eq!(mode(&env.credentials()), 0o700);
    let text = fs::read_to_string(env.aws_env()).unwrap();
    assert!(ai_env_cli::container::detect(&text));
    let plain = env.open(&text);
    assert_eq!(plain, expected_env(&key));
    let parsed = ai_env_cli::bridge::creds::parse_key_input(key_json(USER, &key, "Active").as_bytes(), USER).unwrap();
    assert_eq!(plain, ai_env_cli::bridge::creds::render_env(&parsed).as_str());
    // Encrypted to the key's recipients file: both recipients, via -R, no secret in argv.
    let data = ai_env_cli::container::read(&text).unwrap().data;
    let header = String::from_utf8_lossy(&data);
    assert!(header.contains(&format!("-> fake-age {SE_REC}")) && header.contains(&format!("-> fake-age {X_REC}")), "{header}");
    let age_log = fs::read_to_string(env.age_log()).unwrap();
    let recipients = env.root().join("keys").join("keys").join(KEY).join("recipients.txt");
    assert!(age_log.lines().any(|l| l == format!("age -e -R {}", recipients.display())), "{age_log}");
    assert!(!age_log.contains(&key.secret));

    // The secret is nowhere on disk in the clear, nor in any output; the full
    // id is nowhere either (the audit row keeps the last four characters).
    assert_nowhere(env.root(), &key.secret, "the secret");
    assert_nowhere(env.root(), &key.id, "the full access key id");
    assert!(!stdout(&out).contains(&key.secret) && !stdout(&out).contains(&key.id));
    let rows = audit_rows(&env);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["event"], "creds_aws_set");
    assert_eq!(rows[0]["detail"]["user"], USER);
    assert_eq!(rows[0]["detail"]["key_id_last4"], "WXYZ");
    assert_eq!(rows[0]["detail"]["key"], KEY);
    assert_eq!(rows[0]["detail"]["rotated"], "false");
    assert!(!fs::read_dir(env.credentials()).unwrap().flatten().any(|e| e.file_name().to_string_lossy().ends_with(".bak")), "no backup on a first seal");
}

#[test]
fn creds_rotation_backs_up_the_previous_container() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let first = test_key("ROT1");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &first, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    let before = fs::read_to_string(env.aws_env()).unwrap();

    // The second key comes through the real pipe shape: the fake aws's
    // create-access-key output (key number 2) straight into aws-set.
    let created = run(Command::new(env.bin().join("aws"))
        .args(["iam", "create-access-key", "--user-name", USER, "--region", "eu-central-1", "--output", "json"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("FAKE_AWS_KEYS", "1"));
    assert!(created.status.success(), "{}", stderr(&created));
    let json: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let second = TestKey {
        id: json["AccessKey"]["AccessKeyId"].as_str().unwrap().to_string(),
        secret: json["AccessKey"]["SecretAccessKey"].as_str().unwrap().to_string(),
    };
    // Backups are named by the second; never let two seals share one.
    std::thread::sleep(Duration::from_millis(1100));
    let out = piped(&mut env.cmd(&[]), &created.stdout);
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with(&format!("sealed {USER} access key ...0002 into ")), "{text}");
    assert!(text.contains("previous container kept as "), "{text}");

    let backups: Vec<PathBuf> = fs::read_dir(env.credentials())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            n.starts_with("aws.env.") && n.ends_with(".bak") && n[8..n.len() - 4].bytes().all(|b| b.is_ascii_digit())
        })
        .collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(mode(&backups[0]), 0o600);
    assert_eq!(fs::read_to_string(&backups[0]).unwrap(), before, "the backup is the previous container, byte for byte");
    assert_eq!(env.open(&before), expected_env(&first));
    assert_eq!(env.open(&fs::read_to_string(env.aws_env()).unwrap()), expected_env(&second));
    assert_nowhere(env.root(), &first.secret, "the first secret");
    assert_nowhere(env.root(), &second.secret, "the second secret");
    let rows = audit_rows(&env);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["detail"]["key_id_last4"], "0002");
    assert_eq!(rows[1]["detail"]["rotated"], "true");
}

/// A terminal on stdin (the slave side of an `openpty` pair) is refused before
/// anything is read, so the JSON is never pasted into a scrollback; a pipe
/// reaches parsing, where another user's key is refused with the cleanup.
#[test]
fn creds_refuses_a_tty_or_a_foreign_user() {
    use std::io::IsTerminal as _;
    use std::os::fd::{FromRawFd as _, OwnedFd};
    let env = Env::new(true);
    env.keystore(KEY, true);
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: both out-pointers are valid for the call; name, termios and winsize may be null.
    let rc = unsafe { libc::openpty(&raw mut master, &raw mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // openpty's descriptors are inheritable: mark both close-on-exec so neither
    // leaks into the child (its stdin is a dup2 copy, which drops the flag) nor
    // into children other tests spawn meanwhile.
    for fd in [master, slave] {
        // SAFETY: fd is one of the two descriptors openpty just returned.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) }, 0, "FD_CLOEXEC: {}", std::io::Error::last_os_error());
    }
    // SAFETY: openpty returned two open descriptors that nothing else owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    // What the child tests with `is_terminal()`: the refusal below is the TTY branch.
    assert!(slave.is_terminal(), "the openpty slave must be a terminal");
    // The master stays open until the child is done, so a read of the
    // terminal would block (bounded by wait_bounded) instead of seeing EOF.
    let child = env.cmd(&[]).stdin(Stdio::from(slave)).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let out = wait_bounded(child, "aws-set read the terminal instead of refusing it");
    drop(master);
    assert_eq!(out.status.code(), Some(2), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stderr(&out).contains("stdin is a terminal: pipe the JSON of aws iam create-access-key into this command"), "{}", stderr(&out));
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    assert!(!env.credentials().exists() && !env.audit().exists(), "nothing may be created");

    let key = test_key("FRGN");
    let out = piped(&mut env.cmd(&[]), key_json("rust", &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(9), "stdout {} stderr {}", stdout(&out), stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("\"rust\"") && err.contains(&format!("\"{USER}\"")), "both user names: {err}");
    assert!(err.contains("was NOT stored") && err.contains(&delete_command("rust", &key.id)), "{err}");
    assert!(!err.contains(&key.secret) && !stdout(&out).contains(&key.secret));
    assert!(!env.credentials().exists() && !env.audit().exists());
    assert!(!env.age_log().exists() || !fs::read_to_string(env.age_log()).unwrap().contains(" -e "), "nothing encrypted");
    // D13: under the account root's runner (the bootstrap's make operator-keys) the delete command is the root's, under
    // an ambient one (another account's credentials) the ambient runner's: the runner that can run it on this Mac.
    for (word, runner) in [("root", "ai-env as root -- "), ("ambient", "ai-env as ambient -- ")] {
        let mut cmd = env.cmd(&[]);
        cmd.env("AI_ENV_BRIDGE_AS", word).env_remove("AWS_ACCESS_KEY_ID").env_remove("AWS_SECRET_ACCESS_KEY");
        let out = piped(&mut cmd, key_json("rust", &key, "Active").as_bytes());
        assert_eq!(out.status.code(), Some(9), "{word}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.ends_with(&format!("was NOT stored; if you just created it, delete it:\n  {runner}aws iam delete-access-key --user-name rust --access-key-id {} --region eu-central-1\n", key.id)), "{word}: {err}");
        assert_eq!(err.matches("aws iam ").count(), 1, "{word}: {err}");
    }

    // An inactive key of the right user is refused too, with the cleanup.
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Inactive").as_bytes());
    assert_eq!(out.status.code(), Some(1), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("not \"Active\"") && stderr(&out).contains(&delete_command(USER, &key.id)), "{}", stderr(&out));

    // Garbage names no key: the note says how to find and delete it, as the deployer (D13).
    let out = piped(&mut env.cmd(&[]), b"not json");
    assert_eq!(out.status.code(), Some(1));
    let find = format!(
        "\n  ai-env as deployer -- aws iam list-access-keys --user-name {USER} --region eu-central-1\n  ai-env as deployer -- aws iam delete-access-key --user-name {USER} --access-key-id <id> --region eu-central-1\n"
    );
    assert!(stderr(&out).ends_with(&find), "{}", stderr(&out));
    // So does an empty stdin (the harness default is /dev/null).
    let out = run(&mut env.cmd(&[]));
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("stdin is empty"), "{}", stderr(&out));
    assert!(!env.credentials().exists());
    assert_nowhere(env.root(), &key.secret, "the secret");
}

#[test]
fn creds_refuses_a_key_without_recovery_unless_forced() {
    let env = Env::new(true);
    env.keystore(KEY, false);
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(9), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).lines().any(|l| l.starts_with("[NO ] ") && l.contains("no recovery recipient") && l.contains("--force")), "{}", stdout(&out));

    let key = test_key("NREC");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(9), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("--force") && stderr(&out).contains(&delete_command(USER, &key.id)), "{}", stderr(&out));
    assert!(!env.aws_env().exists());

    let out = run(&mut env.cmd(&["--check", "--force"]));
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains("[ok ] key ai-env-bridge has NO recovery recipient (accepted by --force)"), "{}", stdout(&out));

    let out = piped(&mut env.cmd(&["--force"]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    assert_eq!(env.open(&fs::read_to_string(env.aws_env()).unwrap()), expected_env(&key));
    assert_nowhere(env.root(), &key.secret, "the secret");
}

#[test]
fn creds_failure_after_parse_prints_the_cleanup_command() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let key = test_key("FAIL");
    let out = piped(env.cmd(&[]).env("FAKE_AGE_FAIL", "encrypt"), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(1), "stderr {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("fake encryption failure"), "{err}");
    assert!(err.contains("the access key ...FAIL of IAM user ai-env-runtime was NOT stored"), "{err}");
    assert!(err.contains(&delete_command(USER, &key.id)), "{err}");
    assert!(!err.contains(&key.secret) && stdout(&out).is_empty());
    assert!(!env.aws_env().exists() && !env.audit().exists());
    assert_nowhere(env.root(), &key.secret, "the secret");
}

#[test]
fn creds_tightens_a_wider_credentials_dir() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    fs::create_dir_all(env.credentials()).unwrap();
    fs::set_permissions(env.credentials(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(mode(&env.credentials()), 0o755);
    let key = test_key("WIDE");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    assert_eq!(mode(&env.credentials()), 0o700, "an existing 0755 dir is tightened to 0700");
    assert_eq!(mode(&env.aws_env()), 0o600);
    assert_eq!(env.open(&fs::read_to_string(env.aws_env()).unwrap()), expected_env(&key));
}

#[test]
fn creds_refuses_a_symlinked_credentials_dir() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let elsewhere = env.root().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(env.root().join("bridge")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, env.credentials()).unwrap();
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(1), "stdout {}", stdout(&out));
    assert!(stdout(&out).contains("is a symlink"), "{}", stdout(&out));
    let key = test_key("LINK");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(1), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("is a symlink") && stderr(&out).contains(&delete_command(USER, &key.id)), "{}", stderr(&out));
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0, "nothing written through the link");
}

#[test]
fn creds_uses_the_creds_key_from_bridge_toml() {
    let env = Env::new(true);
    env.keystore("team-key", true);
    fs::create_dir_all(env.root().join("bridge")).unwrap();
    fs::write(env.root().join("bridge").join("bridge.toml"), "# operator config\n[creds]\nkey = \"team-key\"\n").unwrap();
    let key = test_key("TEAM");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    assert!(stdout(&out).ends_with("(key team-key)\n"), "{}", stdout(&out));
    let recipients = env.root().join("keys").join("keys").join("team-key").join("recipients.txt");
    assert!(fs::read_to_string(env.age_log()).unwrap().lines().any(|l| l == format!("age -e -R {}", recipients.display())));
    // Without that key the hint names it.
    fs::write(env.root().join("bridge").join("bridge.toml"), "[creds]\nkey = \"other-key\"\n").unwrap();
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(5));
    assert!(stderr(&out).contains("ai-env keygen other-key"), "{}", stderr(&out));
}

/// The harness keeps the developer's fake knobs out of every `ai-env` it
/// runs: a test that decrypts, run with `FAKE_AGE_HANG=1` in its own
/// environment (a shell left set from trying the fake age), still passes,
/// where every decrypt would hang. The run is a process group of its own,
/// killed whole if it hangs all the same.
#[test]
fn a_developers_fake_knobs_never_reach_the_harness() {
    use std::os::unix::process::CommandExt as _;
    let test = "setup_token::combined_env_joins_the_runtime_key_and_the_token";
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--test-threads=1"])
        .env("FAKE_AGE_HANG", "1")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let group = i32::try_from(child.id()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            // SAFETY: killpg(2) on the group made for the child: that test binary, its ai-env and the fake age.
            unsafe { libc::killpg(group, libc::SIGKILL) };
            panic!("{test} hung with the developer's FAKE_AGE_HANG=1");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success() && stdout(&out).contains("1 passed"), "exit {:?}: {}", out.status.code(), stdout(&out));
}

/// [`wait_bounded`] drains the child's stdout and stderr while it waits: a
/// child that prints more than a pipe holds finishes at once, where an
/// undrained pipe would block it until the limit killed it.
#[test]
fn a_bounded_wait_drains_what_the_child_prints() {
    let started = std::time::Instant::now();
    let child = Command::new("/bin/sh").args(["-c", "head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let out = wait_bounded(child, "a child blocked on a full pipe");
    assert_eq!((out.status.code(), out.stdout.len(), out.stderr.len()), (Some(0), 300_000, 300_000));
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
}

// ---- S8 operators: the ops key, aws-verify, forget --ops (plans/s8-operators-contracts.md §5) ----

/// The daily operator's IAM user.
const OPS: &str = "ai-env-ops";
/// The deployer's IAM user.
const DEPLOYER: &str = "ai-env-deployer";

impl Env {
    pub(crate) fn ops_env(&self) -> PathBuf {
        self.credentials().join("ops.env")
    }

    /// `bridge/state/infra.toml` holding `toml`.
    pub(crate) fn infra_state(&self, toml: &str) {
        let state = self.root().join("bridge").join("state");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("infra.toml"), toml).unwrap();
    }
}

/// An ops key of the fakes (its tail `tail` maps to a user in tests/fakes/aws.sh), its secret `block` ten times.
fn fake_key(tail: &str, block: &str) -> TestKey {
    TestKey { id: super::aws_keys::key_id(tail), secret: super::aws_keys::secret(block) }
}

/// How many decrypts (Touch IDs) the fake age has served.
fn decrypts(env: &Env) -> usize {
    fs::read_to_string(env.age_log()).unwrap_or_default().lines().filter(|l| l.starts_with("age -d ")).count()
}

/// `cmd` with an open stdin nobody writes to: a command that read it would
/// block until the bound, so a pass proves it refused before reading.
fn unread_stdin(cmd: &mut Command, what: &str) -> Output {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let held = child.stdin.take();
    let out = wait_bounded(child, what);
    drop(held);
    out
}

/// `--user ai-env-ops` seals into credentials/ops.env, with the key's notes
/// (user, last four, the sealing time); a rotation keeps the previous container
/// as ops.env.<unix>.bak; aws.env and combined.env are never touched and no
/// Touch ID rebuilds anything; `--check --user ai-env-ops` checks ops.env and
/// counts ai-env-ops' keys; another user's key is refused with its cleanup.
#[test]
fn creds_aws_set_seals_the_ops_key_into_ops_env_only() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    // The runtime key and a combined.env are there already.
    let runtime = test_key("RUN1");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &runtime, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    let combined = env.credentials().join("combined.env");
    fs::write(&combined, ai_env_cli::container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
    let (aws_before, combined_before) = (fs::read(env.aws_env()).unwrap(), fs::read(&combined).unwrap());

    let out = run(env.cmd(&["--check", "--user", OPS]).env("FAKE_AWS_KEYS", "1"));
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    let text = stdout(&out);
    for want in [format!("[ok ] {} (new)", env.ops_env().display()), format!("[ok ] IAM user {OPS} has 1 access key(s), below the maximum of 2")] {
        assert!(text.lines().any(|l| l == want), "{want:?} missing from {text}");
    }
    assert!(fs::read_to_string(env.aws_log()).unwrap().lines().any(|l| l == format!("iam list-access-keys --user-name {OPS} --region eu-central-1 --output json")));
    assert!(!env.ops_env().exists(), "--check seals nothing");

    let before = decrypts(&env);
    let ops = fake_key(super::aws_keys::OPS_TAIL, "Op7/");
    let out = piped(&mut env.cmd(&["--user", OPS]), key_json(OPS, &ops, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    assert_eq!(stdout(&out), format!("sealed {OPS} access key ...{} into {} (key {KEY})\n", super::aws_keys::OPS_TAIL, env.ops_env().display()));
    assert_eq!(stderr(&out), "", "no combined.env rebuild, nothing to say");
    assert_eq!(decrypts(&env), before, "no Touch ID: the ops key is never part of combined.env");
    assert_eq!(fs::read(env.aws_env()).unwrap(), aws_before, "aws.env untouched");
    assert_eq!(fs::read(&combined).unwrap(), combined_before, "combined.env untouched");
    assert_eq!(mode(&env.ops_env()), 0o600);
    let text = fs::read_to_string(env.ops_env()).unwrap();
    assert_eq!(env.open(&text), expected_env(&ops));
    let meta = ai_env_cli::container::meta(&text);
    assert_eq!((meta["kind"].as_str(), meta["user"].as_str(), meta["key_id_last4"].as_str()), ("aws-key", OPS, super::aws_keys::OPS_TAIL));
    let sealed = ai_env_cli::wire::time::parse_rfc3339_utc(&meta["sealed"]).expect("the sealing time, RFC 3339");
    assert!(ai_env_cli::wire::time::unix_now().abs_diff(sealed) < 600, "sealed now: {}", meta["sealed"]);
    let row = audit_rows(&env).pop().unwrap();
    assert_eq!(row["event"], "creds_aws_set");
    for (k, v) in [("user", OPS), ("file", "ops.env"), ("key_id_last4", super::aws_keys::OPS_TAIL), ("key", KEY), ("rotated", "false")] {
        assert_eq!(row["detail"][k], v, "{k}");
    }
    assert_eq!(audit_rows(&env)[0]["detail"]["file"], "aws.env", "the runtime key's row names its file");

    // A rotation keeps the previous container; aws.env is still untouched.
    std::thread::sleep(Duration::from_millis(1100));
    let ops2 = fake_key("9020", "Rt8+");
    let out = piped(&mut env.cmd(&["--user", OPS]), key_json(OPS, &ops2, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with(&format!("sealed {OPS} access key ...9020 into ")) && text.contains("previous container kept as "), "{text}");
    let baks: Vec<String> = fs::read_dir(env.credentials()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".bak")).collect();
    assert_eq!(baks.len(), 1, "{baks:?}");
    assert!(baks[0].starts_with("ops.env.") && baks[0][8..baks[0].len() - 4].bytes().all(|b| b.is_ascii_digit()), "{baks:?}");
    assert_eq!(env.open(&fs::read_to_string(env.credentials().join(&baks[0])).unwrap()), expected_env(&ops));
    assert_eq!(env.open(&fs::read_to_string(env.ops_env()).unwrap()), expected_env(&ops2));
    assert_eq!((fs::read(env.aws_env()).unwrap(), fs::read(&combined).unwrap()), (aws_before, combined_before));
    assert_eq!(audit_rows(&env).pop().unwrap()["detail"]["rotated"], "true");

    // Another user's key: refused (exit 9), the delete command naming the user it belongs to.
    let foreign = test_key("FRG2");
    let out = piped(&mut env.cmd(&["--user", OPS]), key_json(USER, &foreign, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(9), "stderr {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains(&format!("the access key belongs to IAM user \"{USER}\", not \"{OPS}\": refusing to seal another principal's key")) && err.contains(&delete_command(USER, &foreign.id)), "{err}");
    for (secret, what) in [(&ops.secret, "the first ops secret"), (&ops2.secret, "the second ops secret"), (&foreign.secret, "the refused secret"), (&runtime.secret, "the runtime secret")] {
        assert_nowhere(env.root(), secret, what);
    }
}

/// The deployer's key is never stored here: `--user ai-env-deployer` is
/// refused (exit 9) before anything is read, `--check` included, with how to
/// find and delete a key just created for it; any other user is a usage
/// error (exit 2), also before anything is read; nothing is written.
#[test]
fn creds_aws_set_refuses_the_deployer_user_and_unknown_users() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    // D13: every aws iam command it names starts with the runner that can run it on this Mac (a bare aws has no
    // credentials once root's key is retired): the deployer's here (the harness runs as ai-env as ops).
    let refusal = "ai-env: --user ai-env-deployer: the deployer's key is never stored on this Mac: it lives in Strongbox and is pasted per command (ai-env as deployer -- …); hand a new one over with: ai-env as deployer -- aws iam create-access-key --user-name ai-env-deployer --output json | ai-env creds deployer-key\n";
    for args in [&["--user", DEPLOYER][..], &["--user", DEPLOYER, "--check"], &["--check", "--user", DEPLOYER, "--force"]] {
        let out = unread_stdin(&mut env.cmd(args), "aws-set --user ai-env-deployer read stdin");
        assert_eq!(out.status.code(), Some(9), "{args:?}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.starts_with(refusal), "{args:?}: {err}");
        for line in [
            format!("  ai-env as deployer -- aws iam list-access-keys --user-name {DEPLOYER} --region eu-central-1"),
            format!("  ai-env as deployer -- aws iam delete-access-key --user-name {DEPLOYER} --access-key-id <id> --region eu-central-1"),
        ] {
            assert!(err.lines().any(|l| l == line), "{line:?} missing: {err}");
        }
        assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    }
    // The deployer's JSON piped in changes nothing: it is never read.
    let deployer = fake_key(super::aws_keys::DEPLOYER_TAIL, "Dp9+");
    let mut child = env.cmd(&["--user", DEPLOYER]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // The refusal may come before the write: a closed pipe is no failure here.
    let _ = child.stdin.take().unwrap().write_all(key_json(DEPLOYER, &deployer, "Active").as_bytes());
    let out = wait_bounded(child, "aws-set --user ai-env-deployer");
    assert_eq!(out.status.code(), Some(9), "{}", stderr(&out));
    assert_unprinted(&out, &deployer.secret, "the deployer's secret");
    for user in ["rust", "ai-env-runtime-2", "ai-env-ops2"] {
        for check in [false, true] {
            let mut args = vec!["--user", user];
            if check {
                args.push("--check");
            }
            let out = unread_stdin(&mut env.cmd(&args), "aws-set --user <other> read stdin");
            assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
            assert_eq!(stderr(&out), format!("ai-env: --user \"{user}\": aws-set seals ai-env-runtime (credentials/aws.env) or ai-env-ops (credentials/ops.env)\n"));
        }
    }
    let out = run(&mut env.cmd(&["--user", "a b", "--check"]));
    assert!(out.status.code() == Some(2) && stderr(&out).contains("is not an IAM user name"), "{}", stderr(&out));
    assert!(!env.credentials().exists() && !env.audit().exists(), "nothing sealed, nothing audited");
    assert!(!env.age_log().exists() || !fs::read_to_string(env.age_log()).unwrap().contains(" -e "), "nothing encrypted");
    assert!(!env.aws_log().exists(), "no IAM call: {}", fs::read_to_string(env.aws_log()).unwrap_or_default());
}

/// `creds status` shows the ops key (its notes, no Touch ID) and the
/// deployer state/infra.toml records, in text and in --json; `creds forget
/// --ops` lists ops.env and its backups first, deletes them only with --yes
/// (nothing else), and says how to delete the key in IAM.
#[test]
fn creds_status_and_forget_ops_show_and_remove_the_ops_key() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let status = |env: &Env| {
        let out = run(&mut env.creds(&["status"]));
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        stdout(&out)
    };
    let text = status(&env);
    for want in ["[-  ] ops.env: absent (the ai-env-ops key: ai-env as deployer -- make ops-key)", "[-  ] deployer: none recorded in state/infra.toml (the bootstrap deploy, then make infra-status WRITE=1)"] {
        assert!(text.lines().any(|l| l == want), "{want:?} missing from {text}");
    }
    let rows: Vec<&str> = text.lines().collect();
    let at = |prefix: &str| rows.iter().position(|l| l.contains(prefix)).unwrap_or_else(|| panic!("{prefix}: {text}"));
    assert!(at("aws.env") < at("ops.env") && at("ops.env") < at("] deployer") && at("] deployer") < at("setup-token.env"), "the two rows after aws.env's: {text}");

    let runtime = test_key("STA1");
    assert_eq!(piped(&mut env.cmd(&[]), key_json(USER, &runtime, "Active").as_bytes()).status.code(), Some(0));
    let ops = fake_key("9031", "St3+");
    assert_eq!(piped(&mut env.cmd(&["--user", OPS]), key_json(OPS, &ops, "Active").as_bytes()).status.code(), Some(0));
    std::thread::sleep(Duration::from_millis(1100));
    let ops2 = fake_key("9032", "St4+");
    assert_eq!(piped(&mut env.cmd(&["--user", OPS]), key_json(OPS, &ops2, "Active").as_bytes()).status.code(), Some(0));
    let sealed = ai_env_cli::container::meta(&fs::read_to_string(env.ops_env()).unwrap())["sealed"].clone();
    let day = &sealed[..10];
    let arn = format!("arn:aws:iam::123456789012:user/{DEPLOYER}");
    env.infra_state(&format!("stack = \"dev\"\naccount_id = \"123456789012\"\ndeployer_user_arn = \"{arn}\"\n"));
    let before = decrypts(&env);
    let text = status(&env);
    assert_eq!(decrypts(&env), before, "status asks for no Touch ID");
    // The fake age's header names `fake-age` stanzas no keystore key matches: which key opens it is unknown here.
    let ops_row = text.lines().find(|l| l.contains("ops.env:")).unwrap();
    assert!(ops_row.starts_with("[!! ] ops.env: sealed; which key opens it is unknown ("), "{ops_row}");
    assert!(ops_row.ends_with(&format!("); recorded at sealing, not authenticated: {OPS} ...9032, sealed {day}")), "{ops_row}");
    for want in [format!("[ok ] deployer user/{DEPLOYER} (state/infra.toml): its key lives in Strongbox only (ai-env as deployer -- … asks for it)"), "[-  ] backups: ops.env x1".to_string()] {
        assert!(text.lines().any(|l| l == want), "{want:?} missing from {text}");
    }
    assert!(!text.contains("123456789012"), "no account in a row: {text}");
    let out = run(&mut env.creds(&["status", "--json"]));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let o = &v["ops_env"];
    assert_eq!((o["path"].as_str(), o["state"].as_str()), (Some(env.ops_env().display().to_string().as_str()), Some("sealed")));
    assert_eq!((o["recorded"]["user"].as_str(), o["recorded"]["key_id_last4"].as_str(), o["recorded"]["sealed_at"].as_str()), (Some(OPS), Some("9032"), Some(sealed.as_str())));
    assert!(o.as_object().unwrap().contains_key("opens_with"), "{o}");
    assert_eq!((v["deployer_user_arn"].as_str(), v["backups"]["ops.env"].as_u64()), (Some(arn.as_str()), Some(1)));
    // A state that cannot be read: the deployer row says so; --json has no ARN.
    env.infra_state("stack = [\n");
    let text = status(&env);
    assert!(text.lines().any(|l| l.starts_with("[!! ] deployer: state/infra.toml unreadable (")), "{text}");
    let v: serde_json::Value = serde_json::from_str(&stdout(&run(&mut env.creds(&["status", "--json"])))).unwrap();
    assert!(v["deployer_user_arn"].is_null() && v["ops_env"]["recorded"]["user"] == OPS, "{v}");

    // forget --ops: a dry run first.
    let bak = fs::read_dir(env.credentials()).unwrap().flatten().map(|e| e.path()).find(|p| p.file_name().unwrap().to_string_lossy().starts_with("ops.env.")).unwrap();
    let iam = [
        "ai-env cannot deactivate the key ...9032: delete it in IAM:".to_string(),
        format!("  ai-env as deployer -- aws iam list-access-keys --user-name {OPS} --region eu-central-1"),
        format!("  ai-env as deployer -- aws iam delete-access-key --user-name {OPS} --access-key-id <id> --region eu-central-1"),
    ];
    let out = run(&mut env.creds(&["forget", "--ops"]));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let mut want: Vec<String> = vec![format!("would delete {}", env.ops_env().display()), format!("would delete {}", bak.display())];
    want.extend(iam.iter().cloned());
    want.push("dry run: nothing deleted; pass --yes to delete".into());
    assert_eq!(stdout(&out).lines().collect::<Vec<_>>(), want);
    assert!(env.ops_env().exists() && bak.exists(), "a dry run deletes nothing");
    let out = run(&mut env.creds(&["forget", "--ops", "--yes"]));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let mut want: Vec<String> = vec![format!("deleting {}", env.ops_env().display()), format!("deleting {}", bak.display())];
    want.extend(iam.iter().cloned());
    want.push("deleted 2 file(s)".into());
    assert_eq!(stdout(&out).lines().collect::<Vec<_>>(), want);
    assert!(!env.ops_env().exists() && !bak.exists());
    assert!(env.aws_env().exists(), "the runtime key is not the ops key");
    let row = audit_rows(&env).pop().unwrap();
    assert_eq!((row["event"].as_str(), row["detail"]["ops"].as_str(), row["detail"]["files"].as_str(), row["detail"]["failed"].as_str()), (Some("creds_forget"), Some("true"), Some("2"), Some("0")));
    let out = run(&mut env.creds(&["forget", "--ops"]));
    let text = stdout(&out);
    assert!(text.starts_with(&format!("nothing to delete: no ops.env or backup of it under {}\n", env.credentials().display())), "{text}");
    assert!(text.contains("ai-env cannot deactivate the key (its last four not recorded): delete it in IAM:"), "{text}");
    assert!(status(&env).lines().any(|l| l == "[-  ] ops.env: absent (the ai-env-ops key: ai-env as deployer -- make ops-key)"));
    for (secret, what) in [(&ops.secret, "the first ops secret"), (&ops2.secret, "the second ops secret"), (&runtime.secret, "the runtime secret")] {
        assert_nowhere(env.root(), secret, what);
    }
}

/// `creds aws-verify`: one unseal (one Touch ID), `id` then `arn` on stdout,
/// sts with the sealed key alone (the marker, the inherited key, a session
/// token and a profile gone, the files pinned), retried while IAM propagates
/// (6 tries); then exit 0 for the user, 9 for another principal, the root,
/// another account or another ARN, 5 when it never answered; the deployer is
/// never sealed (9), another user is a usage error (2); a dismissed Touch ID
/// is exit 3, an absent file 5. The sealed key (tail 9022) is not the key of
/// `ai-env as ops` this process inherits (9002, `Env::creds`), which the fake
/// answers as nobody: a run that used the inherited key, or printed its id,
/// fails here.
#[test]
fn creds_aws_verify_retries_while_iam_propagates() {
    const SEALED: &str = "9022";
    let env = Env::new(true);
    env.keystore(KEY, true);
    let ops = fake_key(SEALED, "Vf5+");
    assert_eq!(piped(&mut env.cmd(&["--user", OPS]), key_json(OPS, &ops, "Active").as_bytes()).status.code(), Some(0));
    let answers = env.root().join("answers");
    fs::create_dir_all(&answers).unwrap();
    let refused = "\nAn error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: The security token included in the request is invalid.\n";
    for n in [1, 2] {
        fs::write(answers.join(format!("sts.get-caller-identity.{n}.rc")), "254\n").unwrap();
        fs::write(answers.join(format!("sts.get-caller-identity.{n}.stderr")), refused).unwrap();
    }
    let env_log = env.root().join("aws-env.log");
    let verify = |extra: &[(&str, &str)]| {
        let mut cmd = env.creds(&["aws-verify", "--user", OPS]);
        // A session token and a profile beside the inherited key: neither may reach sts (either fails every call there).
        cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1")
            .env("FAKE_AWS_ENV_LOG", &env_log)
            .env("FAKE_AWS_KEY_USERS", format!("{SEALED}:{OPS} 9001:ai-env-deployer"))
            .env("AWS_SESSION_TOKEN", "a-token-of-the-caller")
            .env("AWS_PROFILE", "callers-profile");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let before = decrypts(&env);
        let out = run(&mut cmd);
        assert_eq!(decrypts(&env), before + 1, "one Touch ID per run");
        out
    };
    let id_line = format!("id {}\n", ops.id);
    let label = format!("ai-env: aws-verify: the sealed key ...{SEALED}");

    // Refused twice while IAM propagates, then the ops user.
    let out = verify(&[("FAKE_AWS_ANSWERS", &answers.display().to_string())]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), format!("{id_line}arn arn:aws:iam::123456789012:user/{OPS}\n"));
    let err = stderr(&out);
    let notes: Vec<&str> = err.lines().filter(|l| l.contains("does not answer yet")).collect();
    assert_eq!(notes, [format!("ai-env: the sealed key ...{SEALED} does not answer yet (1/6: IAM propagation)"), format!("ai-env: the sealed key ...{SEALED} does not answer yet (2/6: IAM propagation)")]);
    assert!(err.lines().any(|l| l == format!("{label} answers as user/{OPS}")), "{err}");
    assert_unprinted(&out, &ops.secret, "the ops secret");
    // Every sts call had the sealed key alone: no marker, no selector, the files pinned.
    let calls = fs::read_to_string(&env_log).unwrap();
    let sts: Vec<&str> = calls.lines().filter(|l| l.starts_with("sts get-caller-identity")).collect();
    assert_eq!(sts.len(), 3, "{calls}");
    for l in sts {
        assert!(l.starts_with("sts get-caller-identity | AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true"), "{l}");
    }
    let row = audit_rows(&env).pop().unwrap();
    assert_eq!((row["event"].as_str(), row["detail"]["user"].as_str(), row["detail"]["key_id_last4"].as_str(), row["detail"]["result"].as_str()), (Some("creds_aws_verify"), Some(OPS), Some(SEALED), Some("verified")));

    // Never answered: exit 5, the id line and no arn line (the inherited key would have answered as ai-env-ops).
    let out = verify(&[("FAKE_AWS_KEY_USERS", "9001:ai-env-deployer 9002:ai-env-ops")]);
    assert_eq!(out.status.code(), Some(5), "{}", stderr(&out));
    assert_eq!(stdout(&out), id_line);
    let err = stderr(&out);
    assert_eq!(err.lines().filter(|l| l.contains("does not answer yet")).count(), 5, "{err}");
    assert!(err.ends_with(&format!("{label} never answered (6 tries, 5 s apart; last: InvalidClientTokenId)\n")), "{err}");
    assert_eq!(audit_rows(&env).pop().unwrap()["detail"]["result"], "never-answered");

    // Answered as someone else: exit 9, the arn line, never retried.
    let other = |users: &str| verify(&[("FAKE_AWS_KEY_USERS", users)]);
    let out = other(&format!("{SEALED}:rust"));
    assert_eq!((out.status.code(), stdout(&out)), (Some(9), format!("{id_line}arn arn:aws:iam::123456789012:user/rust\n")), "{}", stderr(&out));
    assert!(stderr(&out).ends_with(&format!("{label} answers as arn:aws:iam::123456789012:user/rust, not user/{OPS}\n")), "{}", stderr(&out));
    assert!(!stderr(&out).contains("does not answer yet"), "an answer is never retried");
    assert_eq!(audit_rows(&env).pop().unwrap()["detail"]["result"], "other-principal");
    let out = other(&format!("{SEALED}:root"));
    assert_eq!(out.status.code(), Some(9), "{}", stderr(&out));
    assert!(stderr(&out).ends_with(&format!("{label} is the account ROOT's: never seal it (delete it in the IAM console)\n")), "{}", stderr(&out));
    assert_eq!(audit_rows(&env).pop().unwrap()["detail"]["result"], "root");
    // The stack's account and the user's recorded ARN, when state/infra.toml names them.
    env.infra_state("stack = \"dev\"\naccount_id = \"123456789012\"\n");
    let out = other(&format!("{SEALED}:ai-env-ops@999999999999"));
    assert_eq!(out.status.code(), Some(9), "{}", stderr(&out));
    assert!(stderr(&out).ends_with(&format!("{label} is {OPS} of account 999999999999, but the stack (state/infra.toml) is in account 123456789012\n")), "{}", stderr(&out));
    assert_eq!(audit_rows(&env).pop().unwrap()["detail"]["result"], "other-account");
    env.infra_state(&format!("stack = \"dev\"\naccount_id = \"123456789012\"\nops_user_arn = \"arn:aws:iam::123456789012:user/team/{OPS}\"\n"));
    let out = verify(&[]);
    assert_eq!(out.status.code(), Some(9), "{}", stderr(&out));
    assert!(stderr(&out).ends_with(&format!("{label} answers as arn:aws:iam::123456789012:user/{OPS}, but the stack's {OPS} is arn:aws:iam::123456789012:user/team/{OPS} (state/infra.toml)\n")), "{}", stderr(&out));
    assert_eq!(audit_rows(&env).pop().unwrap()["detail"]["result"], "other-arn");
    fs::remove_file(env.root().join("bridge").join("state").join("infra.toml")).unwrap();

    // A dismissed Touch ID: exit 3, nothing on stdout.
    let out = verify(&[("FAKE_AGE_FAIL", "cancel")]);
    assert_eq!((out.status.code(), stdout(&out).as_str()), (Some(3), ""), "{}", stderr(&out));
    // The deployer is never sealed; another user is a usage error; neither unseals.
    let before = decrypts(&env);
    let out = run(&mut env.creds(&["aws-verify", "--user", DEPLOYER]));
    assert_eq!((out.status.code(), stderr(&out)), (Some(9), "ai-env: --user ai-env-deployer: its key is never sealed here: check it with ai-env as deployer -- true\n".to_string()));
    let out = run(&mut env.creds(&["aws-verify", "--user", "rust"]));
    assert_eq!((out.status.code(), stderr(&out)), (Some(2), "ai-env: --user \"rust\": aws-verify checks ai-env-runtime (credentials/aws.env) or ai-env-ops (credentials/ops.env)\n".to_string()));
    // The runtime key's file is absent: exit 5 naming how to seal it.
    let out = run(&mut env.creds(&["aws-verify"]));
    assert_eq!((out.status.code(), stderr(&out)), (Some(5), format!("ai-env: {} does not exist: seal the runtime key with make runtime-key\n", env.aws_env().display())));
    assert_eq!(decrypts(&env), before, "no Touch ID for a refusal");
    assert_nowhere(env.root(), &ops.secret, "the ops secret");
}
