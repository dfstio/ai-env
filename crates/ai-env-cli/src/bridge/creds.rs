//! `ai-env creds aws-set` (S3 step 12, plan D23): seal the runtime principal's
//! AWS access key into `credentials/aws.env`, an ai-env container encrypted to
//! the `[creds].key` keystore key (default `ai-env-bridge`).
//!
//! Why this shape: runtime credentials never enter Pulumi (its config, outputs
//! and state stay secret-free), so `make runtime-key` pipes the JSON of
//! `aws iam create-access-key` straight into this command. The secret crosses
//! that one pipe into zeroizing memory, is registered with the scrubber the
//! moment it is parsed, reaches `age` only on its stdin, and exists on disk
//! only inside the encrypted container. Nothing prints it: rows, errors and the
//! audit row carry the user and at most the last four characters of the id.
//!
//! A key that was created but not stored is a live credential nobody holds, so
//! every failure after the input named a key ends with the exact
//! `aws iam delete-access-key` command that removes it (the id is not secret).
//! `--check` is the same preflight without stdin, plus the IAM two-key limit,
//! so the Makefile can refuse before it creates anything.
use crate::age_cmd::{find_in_path, AgeTool};
use crate::bail;
use crate::bridge::audit;
use crate::bridge::config::{BridgeConfig, Paths, REGION};
use crate::bridge::doctor::capture;
use crate::commands::Tag;
use crate::container;
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::{validate_key_name, write_atomic, Keystore};
use crate::wire::redact::{register_secret, scrub, Secret};
use crate::wire::time::unix_now;
use serde::Deserialize;
use std::io::{ErrorKind, IsTerminal as _, Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use zeroize::Zeroizing;

/// Largest stdin accepted (the create-access-key JSON is about 250 bytes).
pub const MAX_INPUT: usize = 64 * 1024;
/// IAM allows two access keys per user: a rotation must delete one first.
pub const IAM_MAX_KEYS: usize = 2;
/// Long-term IAM user keys; `ASIA…` ids are temporary STS credentials.
const KEY_ID_PREFIX: &str = "AKIA";
const KEY_ID_LEN: usize = 20;
const SECRET_LEN: usize = 40;
/// Budget of the one `aws iam list-access-keys` call of `--check`.
const AWS_TIMEOUT: Duration = Duration::from_secs(30);
const USER_CHARS: &str = "1-64 of A-Z a-z 0-9 + = , . @ _ -";

/// A long-term access key read from `aws iam create-access-key`. `Debug`
/// shows the user and id; the secret renders as `[redacted:len=40]` and is
/// zeroized on drop.
#[derive(Debug)]
pub struct AccessKey {
    pub user: String,
    /// `AKIA` + 16 of `[0-9A-Z]` (validated, so ASCII).
    pub id: String,
    pub secret: Secret<String>,
}

impl AccessKey {
    /// The last four characters of the id: all of it that stdout and the
    /// audit row ever show.
    #[must_use]
    pub fn id_tail(&self) -> &str {
        &self.id[self.id.len().saturating_sub(4)..]
    }
}

// ---- input ------------------------------------------------------------------------

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "AccessKey")]
    access_key: Option<RawKey>,
}

/// Every field optional so a missing one gets our message, never serde's.
/// `CreateDate` and unknown fields are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawKey {
    user_name: Option<String>,
    access_key_id: Option<String>,
    status: Option<String>,
    secret_access_key: Option<Secret<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// Not the JSON of an active long-term key (exit 1).
    Malformed,
    /// A well-formed key of another IAM user (exit 9).
    ForeignUser,
}

#[derive(Debug)]
struct InputError {
    fault: Fault,
    message: String,
    /// `(user, id)` once both were well-formed: enough for the cleanup command.
    key: Option<(String, String)>,
}

impl InputError {
    /// The CLI error: the reason, then what to do about a key that exists in
    /// IAM but was not stored.
    fn into_cli(self, expected_user: &str) -> CliError {
        let note = match &self.key {
            Some((user, id)) => not_stored_note(user, id),
            None => unknown_key_note(expected_user),
        };
        let message = format!("{}\n{note}", self.message);
        match self.fault {
            Fault::Malformed => CliError::Msg(message),
            Fault::ForeignUser => CliError::Policy(message),
        }
    }
}

/// An IAM user name: 1..=64 of `[A-Za-z0-9+=,.@_-]`.
#[must_use]
pub fn valid_user_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
}

fn valid_key_id(id: &str) -> bool {
    key_id_fault(id).is_none()
}

/// Why `id` is not a long-term access key id; the value itself is never echoed.
/// The charset is checked before the length, so a length is only reported for
/// ASCII input, where bytes and characters agree.
fn key_id_fault(id: &str) -> Option<String> {
    if !id.starts_with(KEY_ID_PREFIX) {
        return Some(if id.starts_with("ASIA") {
            "is a temporary STS key id (ASIA…): seal a long-term IAM user key (AKIA…)".into()
        } else {
            format!("does not start with {KEY_ID_PREFIX}")
        });
    }
    if !id.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()) {
        return Some("has a character outside 0-9 A-Z".into());
    }
    if id.len() != KEY_ID_LEN {
        return Some(format!("has {} characters, expected {KEY_ID_LEN}", id.len()));
    }
    None
}

/// Why `secret` is not a secret access key; the value itself is never echoed.
/// Charset before length, as in [`key_id_fault`].
fn secret_fault(secret: &str) -> Option<String> {
    if !secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'+') {
        return Some("has a character outside A-Z a-z 0-9 / +".into());
    }
    if secret.len() != SECRET_LEN {
        return Some(format!("has {} characters, expected {SECRET_LEN}", secret.len()));
    }
    None
}

/// serde_json's own messages can quote input values, so only the category
/// and the position are reported.
fn json_fault(e: &serde_json::Error) -> &'static str {
    use serde_json::error::Category;
    match e.classify() {
        Category::Syntax => "syntax error",
        Category::Eof => "unexpected end of input",
        Category::Data => "unexpected structure or a duplicated field",
        Category::Io => "read error",
    }
}

fn parse_input(json: &[u8], expected_user: &str) -> std::result::Result<AccessKey, InputError> {
    let malformed = |message: String| InputError { fault: Fault::Malformed, message, key: None };
    if json.len() > MAX_INPUT {
        return Err(malformed(format!("stdin holds more than {} KiB: not the JSON of aws iam create-access-key", MAX_INPUT / 1024)));
    }
    if json.iter().all(u8::is_ascii_whitespace) {
        return Err(malformed("stdin is empty: pipe the JSON of `aws iam create-access-key --user-name <user> --output json` into this command".into()));
    }
    // serde_json copies an escaped string through a scratch buffer it does not
    // wipe; the AWS CLI never escapes the secret's alphabet, so none is made.
    let envelope: Envelope = serde_json::from_slice(json)
        .map_err(|e| malformed(format!("stdin is not the JSON of aws iam create-access-key ({} at line {} column {})", json_fault(&e), e.line(), e.column())))?;
    let raw = envelope.access_key.ok_or_else(|| malformed("the JSON has no AccessKey object (expected the output of aws iam create-access-key --output json)".into()))?;
    let RawKey { user_name, access_key_id, status, secret_access_key } = raw;
    let secret = secret_access_key.ok_or_else(|| malformed("AccessKey.SecretAccessKey is missing".into()))?;
    register_secret(secret.expose());
    let user = user_name.ok_or_else(|| malformed("AccessKey.UserName is missing".into()))?;
    if !valid_user_name(&user) {
        return Err(malformed(format!("AccessKey.UserName is not an IAM user name ({USER_CHARS})")));
    }
    let id = access_key_id.ok_or_else(|| malformed("AccessKey.AccessKeyId is missing".into()))?;
    if let Some(fault) = key_id_fault(&id) {
        return Err(malformed(format!("AccessKey.AccessKeyId {fault}")));
    }
    // From here on the key is identifiable: every refusal carries the cleanup.
    let refuse = |fault: Fault, message: String| InputError { fault, message: scrub(&message).into_owned(), key: Some((user.clone(), id.clone())) };
    if user != expected_user {
        return Err(refuse(Fault::ForeignUser, format!("the access key belongs to IAM user {user:?}, not {expected_user:?}: refusing to seal another principal's key")));
    }
    match status.as_deref() {
        Some("Active") => {}
        Some(other) if other.len() <= 16 && other.bytes().all(|b| b.is_ascii_alphanumeric()) => {
            return Err(refuse(Fault::Malformed, format!("AccessKey.Status is {other:?}, not \"Active\"")));
        }
        Some(_) => return Err(refuse(Fault::Malformed, "AccessKey.Status is not \"Active\"".into())),
        None => return Err(refuse(Fault::Malformed, "AccessKey.Status is missing".into())),
    }
    if let Some(fault) = secret_fault(secret.expose()) {
        return Err(refuse(Fault::Malformed, format!("AccessKey.SecretAccessKey {fault}")));
    }
    Ok(AccessKey { user, id, secret })
}

/// Parse the JSON of `aws iam create-access-key --user-name <u> --output json`
/// (at most [`MAX_INPUT`] bytes): the key must belong to `expected_user`, be
/// `Active`, carry an `AKIA` id and a 40-character secret. The secret is
/// registered with the scrubber as soon as it is read. Errors name fields and
/// user names, never a value of the id or the secret.
pub fn parse_key_input(json: &[u8], expected_user: &str) -> std::result::Result<AccessKey, String> {
    parse_input(json, expected_user).map_err(|e| e.message)
}

/// The plaintext sealed into `aws.env`: the two variables and nothing else.
#[must_use]
pub fn render_env(key: &AccessKey) -> Zeroizing<String> {
    const ID: &str = "AWS_ACCESS_KEY_ID=";
    const SECRET: &str = "AWS_SECRET_ACCESS_KEY=";
    let secret = key.secret.expose();
    // Sized up front so the buffer never reallocates (a reallocation would
    // leave a partial copy of the secret in freed heap).
    let mut out = Zeroizing::new(String::with_capacity(ID.len() + key.id.len() + SECRET.len() + secret.len() + 2));
    for part in [ID, key.id.as_str(), "\n", SECRET, secret.as_str(), "\n"] {
        out.push_str(part);
    }
    out
}

/// Stdin into one zeroizing buffer allocated once: at most [`MAX_INPUT`]
/// bytes, one more is an error. Each read asks for the whole remaining space
/// (over 8 KiB for any real input), so std's stdin buffer is bypassed and the
/// bytes land only here.
fn read_input(r: &mut impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; MAX_INPUT + 1]);
    let mut n = 0;
    while n <= MAX_INPUT {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => bail!("cannot read stdin: {e}"),
        }
    }
    if n > MAX_INPUT {
        bail!("stdin holds more than {} KiB: not the JSON of aws iam create-access-key", MAX_INPUT / 1024);
    }
    buf.truncate(n);
    Ok(buf)
}

/// Sealing reads the key from a pipe only: a terminal on stdin means the JSON
/// would be pasted, leaving the secret in the terminal's scrollback.
fn refuse_tty(stdin_is_tty: bool) -> Result<()> {
    if stdin_is_tty {
        return Err(CliError::Usage(
            "stdin is a terminal: pipe the JSON of aws iam create-access-key into this command (make runtime-key does); never paste it".into(),
        ));
    }
    Ok(())
}

// ---- cleanup notes -------------------------------------------------------------------

fn not_stored_note(user: &str, id: &str) -> String {
    let tail = &id[id.len().saturating_sub(4)..];
    scrub(&format!(
        "the access key ...{tail} of IAM user {user} was NOT stored; if you just created it, delete it:\n  aws iam delete-access-key --user-name {user} --access-key-id {id} --region {REGION}"
    ))
    .into_owned()
}

fn unknown_key_note(user: &str) -> String {
    format!(
        "no access key was stored; if aws iam create-access-key succeeded, find the new key and delete it:\n  aws iam list-access-keys --user-name {user} --region {REGION}\n  aws iam delete-access-key --user-name {user} --access-key-id <id> --region {REGION}"
    )
}

/// `e` with `note` appended, keeping its exit class. A broken pipe (exit 0)
/// becomes exit 1: a failure to store a key must never look like success.
fn with_note(e: CliError, note: &str) -> CliError {
    let add = |m: String| format!("{m}\n{note}");
    match e {
        CliError::Msg(m) => CliError::Msg(add(m)),
        CliError::Usage(m) => CliError::Usage(add(m)),
        CliError::NoKey(m) => CliError::NoKey(add(m)),
        CliError::AuthUnavailable(m) => CliError::AuthUnavailable(add(m)),
        CliError::Corrupt(m) => CliError::Corrupt(add(m)),
        CliError::Aws(m) => CliError::Aws(add(m)),
        CliError::VmLost(m) => CliError::VmLost(add(m)),
        CliError::Policy(m) => CliError::Policy(add(m)),
        CliError::BrokenPipe => CliError::Msg(add("broken pipe".into())),
        CliError::Cancelled => {
            eprintln!("{note}");
            CliError::Cancelled
        }
    }
}

// ---- preflight ----------------------------------------------------------------------

/// One preflight row: `Ok(text)` prints `[ok ] text`, `Err(e)` prints
/// `[NO ] e` and carries the exit class of that failure.
type Check = Result<String>;

fn check_key(store: &Keystore, name: &str) -> Check {
    validate_key_name(name).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    if store.key_exists(name) {
        Ok(format!("keystore key {name} ({})", store.key_dir(name).display()))
    } else {
        Err(CliError::AuthUnavailable(format!("keystore key {name:?} does not exist: run `ai-env keygen {name}` (with a recovery identity), then re-run")))
    }
}

fn check_recovery(store: &Keystore, name: &str, force: bool) -> Check {
    if validate_key_name(name).is_err() || !store.key_exists(name) {
        return Err(CliError::AuthUnavailable(format!("recovery recipient of key {name:?}: not checked (no such key)")));
    }
    match store.recovery_recipient_of(name)? {
        Some(_) => Ok(format!("key {name} has a recovery recipient")),
        None if force => Ok(format!("key {name} has NO recovery recipient (accepted by --force)")),
        None => Err(CliError::Policy(format!(
            "key {name:?} has no recovery recipient: if this Mac's Secure Enclave key is lost, the sealed AWS key goes with it; use a key created with a recovery identity, or pass --force to accept that"
        ))),
    }
}

fn check_age() -> (Check, Option<AgeTool>) {
    match AgeTool::probe() {
        Ok(age) => {
            let (a, b, c) = age.version;
            (Ok(format!("age v{a}.{b}.{c}")), Some(age))
        }
        Err(e) => (Err(e), None),
    }
}

/// `access(2)` for write and search: what the effective user can create in `dir`.
fn writable(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call; access(2) only reads it.
    unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
}

/// Largest `credentials/aws.env` read to classify it: a sealed access key is
/// about 1 KiB, and a container's payload is capped at 128 KiB anyway.
const MAX_SEALED: u64 = 256 * 1024;

/// What sits at `credentials/aws.env`, as [`aws_env_state`] sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsEnvState {
    /// Nothing: no key sealed yet.
    Absent,
    /// A regular file holding an ai-env container.
    Sealed,
    /// Something else, and why (`is a symlink`, `is not an ai-env container`,
    /// …; a phrase that follows the path, never the file's contents).
    NotSealed(String),
}

/// Classify the file at `path` without following a symlink: `lstat` first
/// (a symlink or a non-regular file is never opened), then one
/// `O_NOFOLLOW|O_NONBLOCK` open that must still be a regular file, read up
/// to [`MAX_SEALED`] bytes and checked with [`container::detect`]. Shared by
/// `creds aws-set` (the target check before sealing) and doctor's runtime
/// credentials row, so the two never disagree about a plaintext key there.
#[must_use]
pub fn aws_env_state(path: &Path) -> AwsEnvState {
    use std::os::unix::fs::OpenOptionsExt as _;
    let not = |why: String| AwsEnvState::NotSealed(why);
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => return not("is a symlink".into()),
        Ok(m) if !m.is_file() => return not("is not a regular file".into()),
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => return AwsEnvState::Absent,
        Err(e) => return not(format!("cannot be inspected ({e})")),
    }
    let opened = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path);
    let file = match opened {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return not("is a symlink".into()),
        Err(e) => return not(format!("cannot be read ({e})")),
    };
    match file.metadata() {
        Ok(m) if m.is_file() => {}
        Ok(_) => return not("is not a regular file".into()),
        Err(e) => return not(format!("cannot be read ({e})")),
    }
    let mut bytes = Vec::new();
    if let Err(e) = file.take(MAX_SEALED + 1).read_to_end(&mut bytes) {
        return not(format!("cannot be read ({e})"));
    }
    if bytes.len() as u64 > MAX_SEALED {
        return not(format!("is larger than {} KiB, not a sealed access key", MAX_SEALED / 1024));
    }
    match std::str::from_utf8(&bytes) {
        Ok(text) if container::detect(text) => AwsEnvState::Sealed,
        _ => not("is not an ai-env container (plaintext?)".into()),
    }
}

/// The credentials dir must be a real, writable directory or creatable; the
/// target must be absent or a regular ai-env container ([`aws_env_state`]: a
/// plaintext file there would be copied into the backup and spread). Symlinks
/// are refused: the rename would replace the link and the backup would read
/// another file.
fn check_target(paths: &Paths) -> Check {
    let dir = paths.credentials();
    let target = paths.aws_env();
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.file_type().is_symlink() => Err(CliError::Msg(format!("{} is a symlink: refusing to seal credentials through it", dir.display()))),
        Ok(m) if !m.is_dir() => Err(CliError::Msg(format!("{} is not a directory", dir.display()))),
        Ok(_) if !writable(&dir) => Err(CliError::Msg(format!("{} is not writable", dir.display()))),
        Ok(_) => match aws_env_state(&target) {
            AwsEnvState::Sealed => Ok(format!("{} exists: backed up before it is replaced", target.display())),
            AwsEnvState::Absent => Ok(format!("{} (new)", target.display())),
            AwsEnvState::NotSealed(why) => Err(CliError::Msg(format!("{} exists but {why}: move it away (and rotate whatever it holds) before sealing", target.display()))),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let base = dir.ancestors().skip(1).map(|a| if a.as_os_str().is_empty() { Path::new(".") } else { a }).find(|a| a.exists());
            match base {
                Some(b) if b.is_dir() && writable(b) => Ok(format!("{} (new; its directory is created 0700)", target.display())),
                Some(b) => Err(CliError::Msg(format!("cannot create {}: {} is not a writable directory", dir.display(), b.display()))),
                None => Err(CliError::Msg(format!("cannot create {}: no existing parent", dir.display()))),
            }
        }
        Err(e) => Err(CliError::Msg(format!("cannot stat {}: {e}", dir.display()))),
    }
}

/// The verdict on `aws iam list-access-keys` output: fewer than
/// [`IAM_MAX_KEYS`] keys passes; at the maximum the check fails naming the
/// existing ids (not secret) because the next create-access-key would fail.
fn keys_verdict(user: &str, json: &str) -> Check {
    #[derive(Deserialize)]
    struct List {
        #[serde(rename = "AccessKeyMetadata")]
        keys: Vec<Listed>,
    }
    #[derive(Deserialize)]
    struct Listed {
        #[serde(rename = "AccessKeyId", default)]
        id: String,
    }
    let list: List = serde_json::from_str(json).map_err(|e| CliError::Aws(format!("aws iam list-access-keys printed unexpected output ({})", json_fault(&e))))?;
    let n = list.keys.len();
    if n >= IAM_MAX_KEYS {
        let ids: Vec<&str> = list.keys.iter().map(|k| if valid_key_id(&k.id) { k.id.as_str() } else { "(unexpected id)" }).collect();
        return Err(CliError::Policy(format!(
            "IAM user {user} already has {n} access keys ({}), the IAM maximum: delete one first (aws iam delete-access-key --user-name {user} --access-key-id <id> --region {REGION})",
            ids.join(", ")
        )));
    }
    Ok(format!("IAM user {user} has {n} access key(s), below the maximum of {IAM_MAX_KEYS}"))
}

/// `aws` is looked up on `PATH` only (not `effective_path`): the Homebrew
/// fallback exists for age's plugin lookup, while `make runtime-key` calls
/// `aws` from this same `PATH`, and the tests must be able to hide it.
fn check_iam_keys(user: &str) -> Check {
    let path = std::env::var("PATH").unwrap_or_default();
    let Some(aws) = find_in_path("aws", &path) else {
        return Err(CliError::Msg(format!("aws CLI not found on PATH (needed to count the access keys of {user}): brew install awscli")));
    };
    let mut cmd = Command::new(&aws);
    cmd.args(["iam", "list-access-keys", "--user-name", user, "--region", REGION, "--output", "json"])
        .env_remove("CLAUDE_CODE_OAUTH_TOKEN")
        .env("AWS_PAGER", "");
    let out = capture(cmd, None, AWS_TIMEOUT).map_err(CliError::Aws)?;
    if !out.success {
        // Until `make deploy` the user does not exist: name that, not the API
        // error. Still a failure: runtime-key cannot create a key without it.
        if out.stderr.contains("(NoSuchEntity)") {
            return Err(CliError::Aws(format!("IAM user {user} does not exist yet (make deploy creates it)")));
        }
        let first = out.stderr.trim().lines().next().unwrap_or("").to_string();
        let why = if first.is_empty() { format!("exit {}", out.code.map_or_else(|| "signal".into(), |c| c.to_string())) } else { scrub(&first).into_owned() };
        return Err(CliError::Aws(format!("aws iam list-access-keys --user-name {user}: {why}")));
    }
    keys_verdict(user, &out.stdout)
}

/// The rows both modes share: keystore key, recovery recipient, age, target.
fn preflight(store: &Keystore, paths: &Paths, key_name: &str, force: bool) -> (Vec<Check>, Option<AgeTool>) {
    let (age_row, age) = check_age();
    (vec![check_key(store, key_name), check_recovery(store, key_name, force), age_row, check_target(paths)], age)
}

fn key_name(paths: &Paths) -> Result<String> {
    Ok(BridgeConfig::load(paths)?.unwrap_or_default().creds.key)
}

// ---- sealing --------------------------------------------------------------------------

/// Make `dir` a real 0700 directory: created (parents too) when absent,
/// refused when it is a symlink or not a directory, tightened when wider.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => bail!("{} is a symlink: refusing to seal credentials through it", dir.display()),
        Ok(m) if !m.is_dir() => bail!("{} is not a directory", dir.display()),
        Ok(m) => {
            if m.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| CliError::Msg(format!("cannot chmod {}: {e}", dir.display())))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| CliError::Msg(format!("cannot create {}: {e}", dir.display())))
        }
        Err(e) => bail!("cannot stat {}: {e}", dir.display()),
    }
}

/// Copy the current container to `<name>.<unix seconds>.bak` (0600, never
/// clobbering, the source opened without following a symlink).
fn backup_existing(target: &Path) -> Result<PathBuf> {
    backup_existing_at(target, unix_now())
}

/// [`backup_existing`] named by `unix`: a second backup in the same second
/// finds the name taken and fails before writing anything.
fn backup_existing_at(target: &Path, unix: u64) -> Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let name = target.file_name().and_then(|n| n.to_str()).ok_or_else(|| CliError::Msg("invalid credentials file name".into()))?;
    let bak = target.with_file_name(format!("{name}.{unix}.bak"));
    let mut old = Vec::new();
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(target)
        .and_then(|mut f| f.read_to_end(&mut old))
        .map_err(|e| CliError::Msg(format!("cannot read {}: {e}", target.display())))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&bak)
        .map_err(|e| CliError::Msg(format!("cannot create backup {}: {e}", bak.display())))?;
    f.write_all(&old)?;
    f.sync_all()?;
    Ok(bak)
}

/// What sealing left on disk.
struct Sealed {
    path: PathBuf,
    backup: Option<PathBuf>,
}

/// Preflight, encrypt [`render_env`] to the key's recipients, sanity-check the
/// ciphertext, back up an existing container, write the new one atomically.
fn seal(store: &Keystore, paths: &Paths, key_name: &str, key: &AccessKey, force: bool) -> Result<Sealed> {
    let (rows, age) = preflight(store, paths, key_name, force);
    if let Some(e) = rows.into_iter().find_map(std::result::Result::err) {
        return Err(e);
    }
    let Some(age) = age else { bail!("age is not available") };
    let ciphertext = {
        let plaintext = render_env(key);
        age.encrypt(&store.recipients_path(key_name), plaintext.as_bytes())?
    };
    let secret = key.secret.expose().as_bytes();
    if ciphertext.windows(secret.len()).any(|w| w == secret) {
        bail!("age returned the secret in the clear (is the `age` on PATH the real tool?): nothing written");
    }
    let text = container::write(&ciphertext);
    container::read(&text).map_err(|e| CliError::Msg(format!("age output is not an age file ({e}): nothing written")))?;
    ensure_private_dir(&paths.credentials())?;
    let target = paths.aws_env();
    let backup = match std::fs::symlink_metadata(&target) {
        Ok(m) if m.file_type().is_symlink() => bail!("{} is a symlink: refusing to replace it", target.display()),
        Ok(m) if !m.is_file() => bail!("{} is not a regular file", target.display()),
        Ok(_) => Some(backup_existing(&target)?),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => bail!("cannot stat {}: {e}", target.display()),
    };
    // write_atomic: 0600 temp file in the same directory, fsync, rename.
    write_atomic(&target, text.as_bytes())?;
    Ok(Sealed { path: target, backup })
}

/// `--check`: every row printed, exit 0 only when all pass, else the class of
/// the first failure. Never reads stdin. The verdict does not depend on the
/// printing: a closed stdout (`--check | head -1`) must not turn a failing
/// check into the broken-pipe exit 0, so a write error counts only when every
/// row passed (and a broken pipe is then success, as everywhere).
fn run_check(store: &Keystore, user: &str, force: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let name = key_name(&paths)?;
    let (mut rows, _age) = preflight(store, &paths, &name, force);
    rows.push(check_iam_keys(user));
    let mut write_error = None;
    for row in &rows {
        let printed = match row {
            Ok(text) => crate::commands::outln(format_args!("{} {text}", Tag::Ok.bracket())),
            Err(e) => crate::commands::outln(format_args!("{} {e}", Tag::No.bracket())),
        };
        if let Err(e) = printed {
            write_error.get_or_insert(e);
        }
    }
    if let Some(e) = rows.into_iter().find_map(std::result::Result::err) {
        return Err(e);
    }
    match write_error {
        None | Some(CliError::BrokenPipe) => Ok(()),
        Some(e) => Err(e),
    }
}

/// `ai-env creds aws-set [--user U] [--check] [--force]`.
pub fn cmd_aws_set(store: &Keystore, user: &str, check: bool, force: bool) -> Result<()> {
    if !valid_user_name(user) {
        return Err(CliError::Usage(format!("--user {user:?} is not an IAM user name ({USER_CHARS})")));
    }
    if check {
        return run_check(store, user, force);
    }
    refuse_tty(std::io::stdin().is_terminal())?;
    let input = read_input(&mut std::io::stdin().lock()).map_err(|e| with_note(e, &unknown_key_note(user)))?;
    let key = parse_input(&input, user).map_err(|e| e.into_cli(user))?;
    drop(input);
    let not_stored = |e: CliError| with_note(e, &not_stored_note(&key.user, &key.id));
    let paths = Paths::resolve().map_err(|e| not_stored(e.into()))?;
    let name = key_name(&paths).map_err(not_stored)?;
    let sealed = seal(store, &paths, &name, &key, force).map_err(not_stored)?;
    // The key is stored from here on: a failed audit write is a warning, not a
    // failure that would send the operator to delete a working key.
    let row = audit::AuditRow::new(
        "creds_aws_set",
        None,
        audit::detail(&[
            ("user", key.user.clone()),
            ("key_id_last4", key.id_tail().to_string()),
            ("key", name.clone()),
            ("rotated", sealed.backup.is_some().to_string()),
        ]),
    );
    if let Err(e) = audit::append(&paths.audit(), &row) {
        eprintln!("warning: the key is sealed but the audit row was not written: {e}");
    }
    outln!("sealed {} access key ...{} into {} (key {name})", key.user, key.id_tail(), sealed.path.display());
    if let Some(bak) = &sealed.backup {
        outln!("previous container kept as {}", bak.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "ai-env-runtime";

    /// `AKIA` + 16: built at run time, never a literal.
    fn id(tail: &str) -> String {
        format!("{KEY_ID_PREFIX}{}{tail}", "UNIT".repeat(3))
    }

    /// 40 characters of the secret alphabet, built at run time.
    fn secret(block: &str) -> String {
        format!("{}{}", block.repeat(9), "cD4+")
    }

    /// The shape `aws iam create-access-key --output json` prints.
    fn json(user: &str, id: &str, secret: &str, status: &str) -> String {
        format!(
            "{{\n    \"AccessKey\": {{\n        \"UserName\": \"{user}\",\n        \"AccessKeyId\": \"{id}\",\n        \"Status\": \"{status}\",\n        \"SecretAccessKey\": \"{secret}\",\n        \"CreateDate\": \"2026-09-29T10:00:00+00:00\"\n    }}\n}}\n"
        )
    }

    fn fault(json: &str) -> (Fault, String, Option<(String, String)>) {
        let e = parse_input(json.as_bytes(), USER).expect_err("must be refused");
        (e.fault, e.message, e.key)
    }

    #[test]
    fn parse_accepts_the_create_access_key_output() {
        let (i, s) = (id("7Q2Z"), secret("aB3/"));
        let key = parse_key_input(json(USER, &i, &s, "Active").as_bytes(), USER).unwrap();
        assert_eq!(key.user, USER);
        assert_eq!(key.id, i);
        assert_eq!(key.id_tail(), "7Q2Z");
        assert!(key.secret.ct_eq(s.as_bytes()));
        let dbg = format!("{key:?}");
        assert!(!dbg.contains(&s) && dbg.contains("[redacted:len=40]"), "{dbg}");
        // Registered with the scrubber the moment it was parsed.
        assert!(!scrub(&format!("x {s} y")).contains(&s));
    }

    #[test]
    fn parse_rejects_every_malformed_field() {
        let (i, s) = (id("8R3Y"), secret("eF5/"));
        // Drops one field's line; CreateDate stays last, so the commas hold.
        let without = |field: &str| json(USER, &i, &s, "Active").lines().filter(|l| !l.contains(&format!("\"{field}\""))).collect::<Vec<_>>().join("\n");
        let cases: Vec<(String, &str)> = vec![
            (String::new(), "stdin is empty"),
            ("  \n".into(), "stdin is empty"),
            ("not json".into(), "syntax error"),
            ("{\"AccessKey\": {".into(), "unexpected end of input"),
            ("[]".into(), "unexpected structure"),
            ("{}".into(), "no AccessKey object"),
            ("{\"AccessKey\": null}".into(), "no AccessKey object"),
            ("{\"AccessKey\": 7}".into(), "unexpected structure"),
            (format!("{{\"AccessKey\": {{\"UserName\": 5, \"SecretAccessKey\": \"{s}\"}}}}"), "unexpected structure"),
            (without("SecretAccessKey"), "SecretAccessKey is missing"),
            (without("UserName"), "UserName is missing"),
            (json("bad user", &i, &s, "Active"), "UserName is not an IAM user name"),
            (json(&"u".repeat(65), &i, &s, "Active"), "UserName is not an IAM user name"),
            (without("AccessKeyId"), "AccessKeyId is missing"),
            (json(USER, &format!("ASIA{}", &i[4..]), &s, "Active"), "temporary STS key id"),
            (json(USER, &format!("AKIB{}", &i[4..]), &s, "Active"), "does not start with AKIA"),
            (json(USER, &i[..19], &s, "Active"), "has 19 characters, expected 20"),
            (json(USER, &format!("{}a", &i[..19]), &s, "Active"), "outside 0-9 A-Z"),
            (without("Status"), "Status is missing"),
            (json(USER, &i, &s, "Inactive"), "Status is \"Inactive\", not \"Active\""),
            (json(USER, &i, &s, "Act ive\\n"), "Status is not \"Active\""),
            (json(USER, &i, &s[..39], "Active"), "has 39 characters, expected 40"),
            (json(USER, &i, &format!("{s}Q"), "Active"), "has 41 characters, expected 40"),
            (json(USER, &i, &format!("{}-", &s[..39]), "Active"), "outside A-Z a-z 0-9 / +"),
            // Multibyte: 20 characters in 21 bytes, 40 in 41. The charset is
            // reported, never a length that contradicts the expected one.
            (json(USER, &format!("{}é", &i[..19]), &s, "Active"), "outside 0-9 A-Z"),
            (json(USER, &i, &format!("{}é", &s[..39]), "Active"), "outside A-Z a-z 0-9 / +"),
        ];
        for (input, want) in &cases {
            let (f, message, _) = fault(input);
            assert_eq!(f, Fault::Malformed, "{input:?} -> {message}");
            assert!(message.contains(want), "{input:?}: want {want:?} in {message:?}");
            assert!(!message.contains(&s) && !message.contains(&s[..39]), "the secret leaked: {message}");
            assert!(!message.contains(&i[4..]), "an input id leaked: {message}");
            assert_eq!(parse_key_input(input.as_bytes(), USER).unwrap_err(), message);
        }
        // Duplicate fields are refused, not resolved last-wins.
        let dup = json(USER, &i, &s, "Active").replace("\"Status\": \"Active\",", "\"Status\": \"Active\", \"Status\": \"Active\",");
        assert!(fault(&dup).1.contains("unexpected structure"));
    }

    #[test]
    fn parse_errors_after_the_id_carry_the_cleanup_key() {
        let (i, s) = (id("9S4X"), secret("gH6+"));
        // Before the id is known: no cleanup key.
        assert_eq!(fault(&json(USER, "nope", &s, "Active")).2, None);
        // After: the (user, id) the delete command needs.
        assert_eq!(fault(&json(USER, &i, &s, "Inactive")).2, Some((USER.to_string(), i.clone())));
        assert_eq!(fault(&json(USER, &i, &s[..30], "Active")).2, Some((USER.to_string(), i.clone())));
        let (f, message, key) = fault(&json("rust", &i, &s, "Active"));
        assert_eq!(f, Fault::ForeignUser);
        assert!(message.contains("\"rust\"") && message.contains(&format!("\"{USER}\"")), "{message}");
        assert_eq!(key, Some(("rust".to_string(), i.clone())));
        let e = parse_input(json("rust", &i, &s, "Active").as_bytes(), USER).unwrap_err().into_cli(USER);
        assert_eq!(e.exit_code(), 9);
        let text = e.to_string();
        assert!(text.contains(&format!("aws iam delete-access-key --user-name rust --access-key-id {i} --region eu-central-1")), "{text}");
        assert!(text.contains("was NOT stored") && !text.contains(&s), "{text}");
        let e = parse_input(b"{}", USER).unwrap_err().into_cli(USER);
        assert_eq!(e.exit_code(), 1);
        assert!(e.to_string().contains(&format!("aws iam list-access-keys --user-name {USER} --region eu-central-1")), "{e}");
    }

    #[test]
    fn parse_caps_the_input_at_64_kib() {
        let (i, s) = (id("1T5W"), secret("iJ7/"));
        let mut big = json(USER, &i, &s, "Active");
        big.push_str(&" ".repeat(MAX_INPUT + 1 - big.len()));
        assert!(parse_key_input(big.as_bytes(), USER).unwrap_err().contains("more than 64 KiB"));
        big.pop();
        assert!(parse_key_input(big.as_bytes(), USER).is_ok(), "exactly 64 KiB is accepted");

        let exact = vec![b' '; MAX_INPUT];
        assert_eq!(read_input(&mut exact.as_slice()).unwrap().len(), MAX_INPUT);
        let over = vec![b' '; MAX_INPUT + 1];
        assert!(read_input(&mut over.as_slice()).unwrap_err().to_string().contains("more than 64 KiB"));
        assert_eq!(read_input(&mut b"{}".as_slice()).unwrap().as_slice(), b"{}");
    }

    #[test]
    fn render_env_is_the_two_variables_and_nothing_else() {
        let (i, s) = (id("2U6V"), secret("kL8+"));
        let key = parse_key_input(json(USER, &i, &s, "Active").as_bytes(), USER).unwrap();
        let env = render_env(&key);
        assert_eq!(env.as_str(), format!("AWS_ACCESS_KEY_ID={i}\nAWS_SECRET_ACCESS_KEY={s}\n"));
        assert_eq!(env.capacity(), env.len(), "sized once, never reallocated");
        let vars = crate::dotenv::parse(&env).expect("a dotenv file ai-env run can inject");
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn refuse_tty_is_a_usage_error() {
        // The predicate alone; tests/infra/creds.rs
        // (`creds_refuses_a_tty_or_a_foreign_user`) runs the binary with a
        // pseudo-terminal on stdin.
        let e = refuse_tty(true).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e.to_string().contains("pipe the JSON of aws iam create-access-key into this command"), "{e}");
        assert!(refuse_tty(false).is_ok());
    }

    #[test]
    fn keys_verdict_counts_against_the_iam_maximum() {
        let listed = |n: usize| {
            let rows: Vec<String> = (0..n).map(|k| format!("{{\"UserName\": \"{USER}\", \"AccessKeyId\": \"{}\", \"Status\": \"Active\"}}", id(&format!("000{k}")))).collect();
            format!("{{\"AccessKeyMetadata\": [{}]}}", rows.join(", "))
        };
        assert!(keys_verdict(USER, &listed(0)).unwrap().contains("has 0 access key(s)"));
        assert!(keys_verdict(USER, &listed(1)).unwrap().contains("has 1 access key(s)"));
        let e = keys_verdict(USER, &listed(2)).unwrap_err();
        assert_eq!(e.exit_code(), 9);
        let text = e.to_string();
        assert!(text.contains("already has 2 access keys") && text.contains(&id("0000")) && text.contains(&id("0001")), "{text}");
        assert!(text.contains("delete one first"), "{text}");
        let odd = "{\"AccessKeyMetadata\": [{\"AccessKeyId\": \"x\\u001b[31m\"}, {}]}";
        let text = keys_verdict(USER, odd).unwrap_err().to_string();
        assert!(text.contains("(unexpected id), (unexpected id)") && !text.contains('\u{1b}'), "{text}");
        assert_eq!(keys_verdict(USER, "garbage").unwrap_err().exit_code(), 7);
    }

    #[test]
    fn user_names_follow_iam() {
        for ok in ["ai-env-runtime", "a", "x+y=z,w.v@u_t-s", &"u".repeat(64)] {
            assert!(valid_user_name(ok), "{ok}");
        }
        for bad in ["", "a b", "a/b", "a\nb", "é", &"u".repeat(65)] {
            assert!(!valid_user_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn target_check_refuses_symlinks_and_plaintext() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        // Absent: creatable under the writable temp dir.
        assert!(check_target(&paths).unwrap().contains("(new; "), "{:?}", check_target(&paths));
        // A symlinked credentials dir.
        std::fs::create_dir_all(&paths.root).unwrap();
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        symlink(&elsewhere, paths.credentials()).unwrap();
        assert!(check_target(&paths).unwrap_err().to_string().contains("is a symlink"));
        std::fs::remove_file(paths.credentials()).unwrap();
        // A symlinked target inside a real dir.
        std::fs::create_dir_all(paths.credentials()).unwrap();
        symlink(elsewhere.join("x"), paths.aws_env()).unwrap();
        assert!(check_target(&paths).unwrap_err().to_string().contains("is a symlink"));
        std::fs::remove_file(paths.aws_env()).unwrap();
        // A plaintext file where the container goes.
        std::fs::write(paths.aws_env(), "AWS_ACCESS_KEY_ID=x\n").unwrap();
        assert!(check_target(&paths).unwrap_err().to_string().contains("not an ai-env container"));
        // An existing container is the rotation path.
        std::fs::write(paths.aws_env(), container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
        assert!(check_target(&paths).unwrap().contains("backed up"));
        // And the sealing side refuses the symlinked dir too.
        std::fs::remove_dir_all(paths.credentials()).unwrap();
        symlink(&elsewhere, paths.credentials()).unwrap();
        assert!(ensure_private_dir(&paths.credentials()).unwrap_err().to_string().contains("is a symlink"));
    }

    /// The one classification doctor and the target check share: never
    /// through a symlink, never blocking on a FIFO, never reading more than
    /// [`MAX_SEALED`] bytes.
    #[test]
    fn aws_env_state_classifies_without_following_or_blocking() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("aws.env");
        let not = |why: &str| AwsEnvState::NotSealed(why.to_string());
        assert_eq!(aws_env_state(&p), AwsEnvState::Absent);
        let sealed = container::write(b"age-encryption.org/v1\n-> x\n--- y\n");
        std::fs::write(&p, &sealed).unwrap();
        assert_eq!(aws_env_state(&p), AwsEnvState::Sealed);
        std::fs::write(&p, "AWS_ACCESS_KEY_ID=example\n").unwrap();
        assert_eq!(aws_env_state(&p), not("is not an ai-env container (plaintext?)"));
        std::fs::write(&p, b"\xff\xfe").unwrap();
        assert_eq!(aws_env_state(&p), not("is not an ai-env container (plaintext?)"), "not UTF-8");
        // A container padded past the cap is refused unread beyond it.
        std::fs::write(&p, format!("{}{sealed}", "#\n".repeat(usize::try_from(MAX_SEALED).unwrap()))).unwrap();
        assert_eq!(aws_env_state(&p), not("is larger than 256 KiB, not a sealed access key"));
        std::fs::remove_file(&p).unwrap();
        // A symlink, even to a container.
        let elsewhere = d.path().join("elsewhere.env");
        std::fs::write(&elsewhere, &sealed).unwrap();
        symlink(&elsewhere, &p).unwrap();
        assert_eq!(aws_env_state(&p), not("is a symlink"));
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        assert_eq!(aws_env_state(&p), not("is not a regular file"));
        std::fs::remove_dir(&p).unwrap();
        // A FIFO without a writer: a plain open would block forever.
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let q = p.clone();
        std::thread::spawn(move || {
            let _ = tx.send(aws_env_state(&q));
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).expect("aws_env_state blocked on a FIFO"), not("is not a regular file"));
    }

    #[test]
    fn backup_is_private_and_never_clobbers() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("aws.env");
        std::fs::write(&target, "old").unwrap();
        let bak = backup_existing(&target).unwrap();
        let name = bak.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("aws.env.") && name.ends_with(".bak") && name[8..name.len() - 4].bytes().all(|b| b.is_ascii_digit()), "{name}");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "old");
        assert_eq!(std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_file(&bak).unwrap();

        // Two backups in one (fixed) second: the second is refused and
        // nothing changes, neither the first backup nor the target.
        const SECOND: u64 = 1_000_000_000;
        let first = backup_existing_at(&target, SECOND).unwrap();
        assert_eq!(first, d.path().join(format!("aws.env.{SECOND}.bak")));
        std::fs::write(&target, "newer").unwrap();
        let e = backup_existing_at(&target, SECOND).unwrap_err();
        assert!(e.to_string().contains("cannot create backup") && e.to_string().contains("exists"), "{e}");
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "old");
        assert_eq!(std::fs::metadata(&first).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "newer");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 2, "no other file appeared");
    }

    #[test]
    fn with_note_keeps_the_exit_class_and_never_reports_success() {
        for e in [CliError::Msg("m".into()), CliError::AuthUnavailable("a".into()), CliError::Policy("p".into()), CliError::Aws("w".into())] {
            let code = e.exit_code();
            let out = with_note(e, "NOTE");
            assert_eq!(out.exit_code(), code);
            assert!(out.to_string().ends_with("\nNOTE"), "{out}");
        }
        let out = with_note(CliError::BrokenPipe, "NOTE");
        assert_eq!(out.exit_code(), 1);
        assert!(out.to_string().contains("NOTE"));
    }
}
