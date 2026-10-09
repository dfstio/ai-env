//! `ai-env creds setup-token | status | forget` (S7, Tier A): the Claude
//! setup-token sealed into `credentials/setup-token.env`, and the derived
//! `credentials/combined.env` (D4).
//!
//! Custody: the token is read once — a hidden paste on the terminal, one line
//! from a pipe (`--stdin`), or `CLAUDE_CODE_OAUTH_TOKEN` (`--from-env`) — into
//! zeroizing memory, reaches `age` only on its stdin, and exists on disk only
//! inside encrypted containers. Nothing prints it: rows, errors and the audit
//! row carry its kind prefix (`sk-ant-oat01-`, never more) and its length.
//! Under `--from-env` it is also in ai-env's own environment, as the shell
//! exec'd it, which ai-env cannot undo (the reminder says to unset it there);
//! `age`, its plugin and `age-keygen` never inherit it
//! (`age_cmd::CHILD_ENV_REMOVED`).
//!
//! `combined.env` holds the runtime AWS key and the token in one container,
//! so a credentialed command in container mode costs one Touch ID, not two.
//! It is derived: `creds setup-token` and `creds aws-set` rebuild it (each
//! unseals the other file once) and it records the sha256 of the two source
//! texts it was built from (the one the command sealed, the one it
//! unsealed); it is used only while both files still match, else the two
//! files are unsealed separately. The old one is removed before the
//! rebuild's Touch ID, so a rebuild that fails, is dismissed or is
//! interrupted never leaves a stale copy of a replaced token on disk, and
//! one whose source another command sealed anew (or forgot) while it waited
//! builds none from the replaced one.
use crate::age_cmd::AgeTool;
use crate::bridge::audit;
use crate::bridge::config::{BridgeConfig, CredentialsSource, Paths};
use crate::bridge::creds::{aws_env_state, key_name, preflight_for, seal_file, AwsEnvState};
use crate::bridge::errors::BridgeError;
use crate::commands::Tag;
use crate::container;
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::{validate_key_name, Keystore};
use crate::wire::redact::{forget_secret, register_secret, scrub, Secret};
use crate::wire::time::{parse_rfc3339_utc, rfc3339_utc, unix_now};
use std::fmt;
use std::io::{ErrorKind, IsTerminal as _, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The variable the token is sealed under, delivered under, and read from
/// by `--from-env`.
pub const TOKEN_VAR: &str = "CLAUDE_CODE_OAUTH_TOKEN";
const MIN_CHARS: usize = 20;
/// The most a token may hold: what the shim's fd 3 carries.
pub const MAX_CHARS: usize = 4096;
const ANTHROPIC: &str = "sk-ant-";
/// Kinds that are API keys, never what `claude setup-token` prints.
const API_KINDS: [&str; 2] = ["api", "admin"];
/// Anthropic's stated life of a setup-token.
pub const TOKEN_LIFE_DAYS: u64 = 365;
/// `creds status` warns when fewer days than this are left (sealed over 330
/// days ago).
const WARN_DAYS_LEFT: i64 = 35;
/// The most `--stdin` reads (one line is expected).
const MAX_STDIN: usize = 8 * 1024;

// ---- the token ----------------------------------------------------------------------

/// The setup-token in this process. No `Clone`, `Copy`, `Serialize` or
/// `Display`; `Debug` shows the length; the value is zeroized on drop.
pub struct SetupToken {
    value: Secret<String>,
    /// [`parse_token`] registered the value with the scrubber (a shape its
    /// rules do not mask whole), so the drop forgets it.
    registered: bool,
}

impl fmt::Debug for SetupToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SetupToken([redacted:len={}])", self.len())
    }
}

impl Drop for SetupToken {
    /// The registry's copy goes with the handle (when no other handle holds
    /// the value), so it never outlives the token as a plain copy; the
    /// value itself is zeroized by `Secret`'s drop right after.
    fn drop(&mut self) {
        if self.registered {
            forget_secret(self.value.expose());
        }
    }
}

impl SetupToken {
    #[must_use]
    pub fn len(&self) -> usize {
        self.value.expose().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.expose().is_empty()
    }

    /// The kind prefix (`sk-ant-oat01-`) of a token of the shape the
    /// scrubber masks whole; `None` for any other shape.
    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        known_prefix(self.value.expose())
    }

    /// A copy for one wire frame (`credential.secret`), zeroized with it.
    #[must_use]
    pub fn frame_secret(&self) -> Secret<String> {
        Secret::new(self.value.expose().clone())
    }

    /// The value, for the plaintext it is sealed in (call sites are
    /// auditable by grep).
    pub(crate) fn expose(&self) -> &str {
        self.value.expose()
    }
}

/// `sk-ant-<kind>-` when `value` has the shape the scrubber masks whole:
/// `sk-ant-`, a kind of lowercase letters and digits (`oat01`), a dash, and
/// at least 8 more of `[A-Za-z0-9_.-]`.
fn known_prefix(value: &str) -> Option<&str> {
    let rest = value.strip_prefix(ANTHROPIC)?;
    let (kind, tail) = rest.split_once('-')?;
    let kind_ok = (2..=16).contains(&kind.len()) && kind.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) && kind.bytes().any(|c| c.is_ascii_lowercase());
    let tail_ok = tail.len() >= 8 && tail.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'));
    (kind_ok && tail_ok).then(|| &value[..ANTHROPIC.len() + kind.len() + 1])
}

/// Why an input is not a setup-token; the value is never in the text.
#[derive(Debug)]
pub struct TokenFault {
    /// A well-formed credential of the wrong kind (an API key): exit 9.
    pub policy: bool,
    pub message: String,
}

impl TokenFault {
    fn new(message: impl Into<String>) -> TokenFault {
        TokenFault { policy: false, message: message.into() }
    }

    #[must_use]
    pub fn into_cli(self) -> CliError {
        if self.policy {
            CliError::Policy(self.message)
        } else {
            CliError::Msg(self.message)
        }
    }
}

/// Parse a pasted, piped or inherited setup-token: trimmed; an `export ` and
/// a `CLAUDE_CODE_OAUTH_TOKEN=` before it are dropped (a line copied from a
/// shell profile); then 20–4096 printable ASCII bytes without space, quote,
/// backtick, `$` or backslash (it is sealed as a dotenv line that a recovery
/// may `source`). An Anthropic API key is refused: it is billed per token
/// and is not what `claude setup-token` prints. A token whose shape the
/// scrubber does not mask whole is registered with it while the handle
/// lives: the drop forgets it, so a line quoting it afterwards is masked by
/// the scrubber's key rules only. That holds for the copies that outlive
/// the handle too: `vm exec`'s frame copy (`prepare` drops the handle before
/// the frame is sent) and a `local-scratch` child's (the wrapper drops its
/// handle once no spawn can need it). A holder that needs the value masked
/// longer registers it itself: the registry counts holders.
pub fn parse_token(raw: &str) -> std::result::Result<SetupToken, TokenFault> {
    let mut v = raw.trim();
    if let Some(rest) = v.strip_prefix("export ") {
        v = rest.trim_start();
    }
    if let Some(rest) = v.strip_prefix(TOKEN_VAR).and_then(|r| r.strip_prefix('=')) {
        v = rest;
    }
    if v.is_empty() {
        return Err(TokenFault::new("no token was given: run `claude setup-token` and paste what it prints"));
    }
    if let Some(bad) = v.bytes().find(|c| !(0x21..=0x7e).contains(c) || matches!(c, b'"' | b'\'' | b'`' | b'$' | b'\\')) {
        let what = match bad {
            b' ' | b'\t' | b'\n' | b'\r' => "whitespace (one line, one token expected)",
            b'"' | b'\'' | b'`' => "a quote (paste the token without quotes)",
            b'$' => "a `$`",
            b'\\' => "a backslash",
            _ => "a byte that is not printable ASCII",
        };
        return Err(TokenFault::new(format!("the token holds {what}: not a setup-token")));
    }
    if v.strip_prefix(ANTHROPIC).is_some_and(|rest| API_KINDS.iter().any(|k| rest.starts_with(k))) {
        return Err(TokenFault {
            policy: true,
            message: "that is an Anthropic API key (sk-ant-api…), not a setup-token: an API key is billed per token; run `claude setup-token` and seal what it prints".into(),
        });
    }
    if !(MIN_CHARS..=MAX_CHARS).contains(&v.len()) {
        return Err(TokenFault::new(format!("the token has {} characters, expected {MIN_CHARS} to {MAX_CHARS}: not a setup-token", v.len())));
    }
    let registered = known_prefix(v).is_none();
    if registered {
        register_secret(v);
    }
    Ok(SetupToken { value: Secret::new(v.to_string()), registered })
}

/// The plaintext sealed into `setup-token.env`: one dotenv line, sized once.
#[must_use]
pub fn render_token_env(token: &SetupToken) -> Zeroizing<String> {
    let v = token.expose();
    let mut out = Zeroizing::new(String::with_capacity(TOKEN_VAR.len() + v.len() + 2));
    for part in [TOKEN_VAR, "=", v, "\n"] {
        out.push_str(part);
    }
    out
}

/// Parse what `setup-token.env` unsealed to: exactly one
/// `CLAUDE_CODE_OAUTH_TOKEN=<token>` line, with an optional final newline,
/// the token passing [`parse_token`]'s rules again. Any other shape is exit 5
/// naming the problem, never a value.
pub fn parse_token_env(plain: &[u8]) -> std::result::Result<SetupToken, BridgeError> {
    let bad = |why: &str| BridgeError::CredentialsUnavailable(format!("credentials/setup-token.env: {why} (re-seal it with `ai-env creds setup-token`)"));
    let text = std::str::from_utf8(plain).map_err(|_| bad("the unsealed plaintext is not UTF-8"))?;
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.contains('\n') {
        return Err(bad("the unsealed plaintext is not one line"));
    }
    let value = body.strip_prefix(TOKEN_VAR).and_then(|r| r.strip_prefix('=')).ok_or_else(|| bad(&format!("the unsealed line is not {TOKEN_VAR}=…")))?;
    parse_token(value).map_err(|f| bad(&f.message))
}

/// The plaintext sealed into `combined.env`: the runtime key's two lines as
/// `aws.env` holds them, then the token's line; sized once.
#[must_use]
pub fn render_combined(key_id: &str, secret: &str, token: &SetupToken) -> Zeroizing<String> {
    const ID: &str = "AWS_ACCESS_KEY_ID=";
    const SECRET: &str = "AWS_SECRET_ACCESS_KEY=";
    let v = token.expose();
    let mut out = Zeroizing::new(String::with_capacity(ID.len() + key_id.len() + SECRET.len() + secret.len() + TOKEN_VAR.len() + v.len() + 4));
    for part in [ID, key_id, "\n", SECRET, secret, "\n", TOKEN_VAR, "=", v, "\n"] {
        out.push_str(part);
    }
    out
}

/// The runtime key's id and secret.
pub type RuntimeKey = (String, Zeroizing<String>);

/// Split what `combined.env` unsealed to: the token's line, and the rest,
/// which must be exactly what `aws.env` holds. Exit 5 naming the problem.
pub fn parse_combined(plain: &[u8]) -> std::result::Result<(RuntimeKey, SetupToken), BridgeError> {
    let bad = |why: &str| BridgeError::CredentialsUnavailable(format!("credentials/combined.env: {why} (rebuild it with `ai-env creds setup-token`)"));
    let text = std::str::from_utf8(plain).map_err(|_| bad("the unsealed plaintext is not UTF-8"))?;
    let body = text.strip_suffix('\n').unwrap_or(text);
    let mut token = None;
    let mut rest = Zeroizing::new(String::with_capacity(body.len()));
    for line in body.split('\n') {
        if let Some(value) = line.strip_prefix(TOKEN_VAR).and_then(|r| r.strip_prefix('=')) {
            if token.replace(value).is_some() {
                return Err(bad(&format!("{TOKEN_VAR} appears twice")));
            }
        } else {
            rest.push_str(line);
            rest.push('\n');
        }
    }
    let value = token.ok_or_else(|| bad(&format!("{TOKEN_VAR} is missing")))?;
    let token = parse_token(value).map_err(|f| bad(&f.message))?;
    let key = crate::bridge::vm::client::parse_runtime_env(rest.as_bytes()).map_err(|_| bad("the runtime key's lines do not parse"))?;
    Ok((key, token))
}

// ---- what is on disk, without a Touch ID ----------------------------------------------

/// `hex(sha256(file))` of a credentials file read without following a
/// symlink; `None` when it is absent or unreadable.
fn file_sha256(path: &Path) -> Option<String> {
    let text = crate::bridge::registry::read_regular_file(path).ok()??;
    Some(text_sha256(&text))
}

/// `hex(sha256(text))`: what `combined.env` records of a source text.
fn text_sha256(text: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}

/// The state of `combined.env` against its sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CombinedState {
    Absent,
    /// Both recorded source hashes match the files there now.
    Current,
    /// Built from other files than those there now: not used until rebuilt.
    Stale(String),
    /// Something other than an ai-env container (why).
    NotSealed(String),
}

impl CombinedState {
    /// A short phrase for rows and `--json`.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            CombinedState::Absent => "absent",
            CombinedState::Current => "current",
            CombinedState::Stale(_) => "stale",
            CombinedState::NotSealed(_) => "not-sealed",
        }
    }
}

/// Is `combined.env` usable in place of the two files? Reads three files and
/// decrypts nothing.
#[must_use]
pub fn combined_state(paths: &Paths) -> CombinedState {
    let path = paths.combined_env();
    match aws_env_state(&path) {
        AwsEnvState::Absent => return CombinedState::Absent,
        AwsEnvState::NotSealed(why) => return CombinedState::NotSealed(why),
        AwsEnvState::Sealed => {}
    }
    let Some(text) = crate::bridge::registry::read_regular_file(&path).ok().flatten() else {
        return CombinedState::NotSealed("cannot be read".into());
    };
    let meta = container::meta(&text);
    for (key, source, name) in [("aws_file_sha256", paths.aws_env(), "aws.env"), ("token_file_sha256", paths.setup_token_env(), "setup-token.env")] {
        let Some(recorded) = meta.get(key) else {
            return CombinedState::Stale(format!("it records no hash of {name}"));
        };
        match file_sha256(&source) {
            Some(now) if now == *recorded => {}
            Some(_) => return CombinedState::Stale(format!("{name} changed since it was built")),
            None => return CombinedState::Stale(format!("{name} is gone")),
        }
    }
    CombinedState::Current
}

/// What `creds setup-token` recorded in the container's metadata line —
/// recorded at sealing, not authenticated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recorded {
    pub prefix: Option<String>,
    pub chars: Option<usize>,
    pub sealed_at: Option<u64>,
}

impl Recorded {
    fn of(text: &str) -> Recorded {
        let meta = container::meta(text);
        Recorded {
            prefix: meta.get("prefix").filter(|p| p.starts_with(ANTHROPIC) || *p == "unrecognised").cloned(),
            chars: meta.get("chars").and_then(|c| c.parse().ok()),
            sealed_at: meta.get("sealed").and_then(|s| parse_rfc3339_utc(s)),
        }
    }

    /// Days left of the token's one-year life, counted from the sealing (a
    /// token minted earlier has fewer).
    #[must_use]
    pub fn days_left(&self, now: u64) -> Option<i64> {
        let sealed = i64::try_from(self.sealed_at?).ok()?;
        let now = i64::try_from(now).ok()?;
        Some(i64::try_from(TOKEN_LIFE_DAYS).unwrap_or(365) - (now - sealed).div_euclid(86_400))
    }

    /// `sk-ant-oat01-… (108 chars)`, or what is known of it.
    #[must_use]
    pub fn describe(&self) -> String {
        let prefix = self.prefix.as_deref().map_or_else(|| "a token".to_string(), |p| if p == "unrecognised" { "a token of an unrecognised shape".into() } else { format!("{p}…") });
        match self.chars {
            Some(n) => format!("{prefix} ({n} chars)"),
            None => prefix,
        }
    }
}

/// Why the keystore key that opens a file is not known.
#[derive(Debug, Clone)]
pub enum OpenFault {
    /// No keystore key matches its recipients: an unseal fails (exit 4).
    NoKey(String),
    /// Its header could not be read to match recipients (no prompt is tried).
    Unknown(String),
}

/// One sealed file: its state, which keystore key opens it (by recipient
/// tag, no prompt), and its recorded metadata.
#[derive(Debug, Clone)]
pub struct FileFacts {
    pub path: PathBuf,
    pub state: AwsEnvState,
    pub opens_with: Option<std::result::Result<String, OpenFault>>,
    pub recorded: Recorded,
}

fn file_facts(store: &Keystore, path: PathBuf) -> FileFacts {
    let state = aws_env_state(&path);
    let (mut opens_with, mut recorded) = (None, Recorded::default());
    if state == AwsEnvState::Sealed {
        if let Some(text) = crate::bridge::registry::read_regular_file(&path).ok().flatten() {
            recorded = Recorded::of(&text);
            opens_with = Some(match container::read(&text).and_then(|c| crate::select::resolve_for_decrypt(store, None, &c)) {
                Ok(k) => Ok(k),
                Err(e @ CliError::NoKey(_)) => Err(OpenFault::NoKey(e.to_string())),
                Err(e) => Err(OpenFault::Unknown(e.to_string())),
            });
        }
    }
    FileFacts { path, state, opens_with, recorded }
}

/// The backups a sealing command left beside `file` (`<name>.<unix>.bak`).
fn backups_of(paths: &Paths, file: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(paths.credentials()) else { return Vec::new() };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.strip_prefix(file).and_then(|r| r.strip_prefix('.')).and_then(|r| r.strip_suffix(".bak")).is_some_and(|ts| !ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

/// A VM the token was delivered to and that is not known to be terminated:
/// its memory, children and snapshots may hold the token.
#[derive(Debug, Clone)]
pub struct Holder {
    pub id: String,
    pub status: &'static str,
    pub credential_at: u64,
}

/// The holders the readable rows name, and the rows that cannot be read
/// (`<path>: <error>`, the path once), each of whose VMs may hold the token unlisted; or
/// why the registry could not be listed at all. Never an empty list in place
/// of an error, since this is the list `creds forget` acts on: `creds status`
/// and `creds forget` print every unreadable row beside the holders, on
/// stdout and in `--json`, so the list never reads none while one exists.
fn holders(paths: &Paths) -> std::result::Result<(Vec<Holder>, Vec<String>), String> {
    use crate::bridge::vm::registry::{list_rows_reporting, RowStatus};
    let (rows, unread) = list_rows_reporting(paths).map_err(|e| e.to_string())?;
    let held: Vec<Holder> = rows
        .into_iter()
        .filter(|r| !r.id.is_empty() && r.status != RowStatus::Terminated && r.terminated_at.is_none())
        .filter_map(|r| Some(Holder { credential_at: r.credential_at?, status: r.status.as_str(), id: r.id }))
        .collect();
    Ok((held, unread))
}

/// What `creds status` and `creds forget` say of a registry row that cannot
/// be read, before the row's `<path>: <error>`.
const UNREADABLE_ROW: &str = "a VM registry row cannot be read, so its VM may hold the token unlisted";

// ---- unsealing --------------------------------------------------------------------------

/// Read and classify a sealed credentials file, and find its key: exit 5 when
/// it is absent or not a container (`hint` says how to seal it).
pub(crate) fn sealed_text(path: &Path, hint: &str) -> Result<String> {
    match aws_env_state(path) {
        AwsEnvState::Sealed => {}
        AwsEnvState::Absent => return Err(CliError::AuthUnavailable(format!("{} does not exist: {hint}", path.display()))),
        AwsEnvState::NotSealed(why) => return Err(CliError::AuthUnavailable(format!("{} {why}: move it away, then {hint}", path.display()))),
    }
    crate::bridge::registry::read_regular_file(path)?.ok_or_else(|| CliError::AuthUnavailable(format!("{} vanished while it was read: {hint}", path.display())))
}

/// Decrypt one sealed credentials file (one Touch ID) with `[creds].key`.
fn decrypt_file(store: &Keystore, path: &Path, key_name: &str, hint: &str) -> Result<Zeroizing<Vec<u8>>> {
    Ok(decrypt_file_hashed(store, path, key_name, hint)?.0)
}

/// [`decrypt_file`], and `hex(sha256)` of the sealed text it read once,
/// before the Touch ID, and decrypted: what a `combined.env` built from the
/// plaintext records of that source (F2), never a second read of a file
/// another command may have sealed anew while the dialog waited.
fn decrypt_file_hashed(store: &Keystore, path: &Path, key_name: &str, hint: &str) -> Result<(Zeroizing<Vec<u8>>, String)> {
    validate_key_name(key_name).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    let text = sealed_text(path, hint)?;
    Ok((decrypt_text(store, &text, key_name)?, text_sha256(&text)))
}

/// Decrypt a sealed text already read (one Touch ID) with `key_name`, which
/// the caller validated: what the caller said of those bytes is said of the
/// plaintext, never of a second read of their file.
fn decrypt_text(store: &Keystore, text: &str, key_name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cont = container::read(text)?;
    let key = crate::select::resolve_for_decrypt(store, Some(key_name), &cont)?;
    let age = AgeTool::probe()?;
    age.decrypt_to_bytes(&store.identity_path(&key), &cont.data)
}

/// The sealed setup-token (one Touch ID).
pub fn unseal_setup_token(store: &Keystore, paths: &Paths, key_name: &str) -> Result<SetupToken> {
    let plain = decrypt_file(store, &paths.setup_token_env(), key_name, "seal it with `ai-env creds setup-token`")?;
    Ok(parse_token_env(&plain)?)
}

/// The setup-token in `sealed`, a `setup-token.env` text the caller read
/// once and checked (one Touch ID): the token unsealed is the one whose seal
/// id was checked, never a second read of a file sealed anew meanwhile (F11,
/// as `vm exec`'s M38).
pub(crate) fn unseal_setup_token_text(store: &Keystore, sealed: &str, key_name: &str) -> Result<SetupToken> {
    validate_key_name(key_name).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    let plain = decrypt_text(store, sealed, key_name)?;
    Ok(parse_token_env(&plain)?)
}

/// Both credentials from `combined.env` (one Touch ID); the caller checked
/// [`combined_state`] is `Current`.
pub fn unseal_combined(store: &Keystore, paths: &Paths, key_name: &str) -> Result<(RuntimeKey, SetupToken)> {
    let plain = decrypt_file(store, &paths.combined_env(), key_name, "rebuild it with `ai-env creds setup-token`")?;
    Ok(parse_combined(&plain)?)
}

// ---- combined.env -----------------------------------------------------------------------

/// What became of `combined.env` after a sealing command.
#[derive(Debug)]
pub enum CombinedOutcome {
    Built(PathBuf),
    /// Nothing to build (why); `removed` when an out-of-date one was deleted.
    Skipped { why: String, removed: bool },
    /// The other source could not be unsealed or the seal failed (why); an
    /// out-of-date one was deleted, so readers fall back to two prompts.
    Failed { why: String, removed: bool },
}

impl CombinedOutcome {
    fn word(&self) -> &'static str {
        match self {
            CombinedOutcome::Built(_) => "built",
            CombinedOutcome::Skipped { .. } => "skipped",
            CombinedOutcome::Failed { .. } => "failed",
        }
    }
}

/// Delete `combined.env` (or a link in its place); whether there was one.
/// Its sources keep their own backups, so a derived copy is never kept.
fn remove_combined(paths: &Paths) -> bool {
    let path = paths.combined_env();
    match std::fs::symlink_metadata(&path) {
        Ok(_) => match std::fs::remove_file(&path) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("warning: cannot remove the out-of-date {}: {e}", path.display());
                false
            }
        },
        Err(_) => false,
    }
}

/// Seal both credentials into `combined.env`, recording `aws_sha` and
/// `token_sha`: the hashes of the two source texts the runtime key and the
/// token came from (the one the command sealed, the one it unsealed), never
/// of a read after the rebuild's Touch ID, when another command may have
/// sealed either anew (F2). It is built, and kept, only while both files
/// still are those texts: otherwise none is built from the replaced one, and
/// the one there is removed unless it matches its sources (another command
/// built it meanwhile). An existing one is removed first, never backed up.
#[allow(clippy::too_many_arguments)]
fn seal_combined(store: &Keystore, paths: &Paths, key_name: &str, key_id: &str, secret: &str, token: &SetupToken, aws_sha: &str, token_sha: &str, force: bool) -> Result<PathBuf> {
    // The sources sealed anew (or removed) since: none when both still are the texts this pairs.
    let changed = || [(paths.aws_env(), aws_sha, "aws.env"), (paths.setup_token_env(), token_sha, "setup-token.env")].into_iter().filter(|(p, sha, _)| file_sha256(p).as_deref() != Some(*sha)).map(|(_, _, name)| name).collect::<Vec<_>>();
    let superseded = |names: Vec<&str>| {
        if combined_state(paths) != CombinedState::Current {
            remove_combined(paths);
        }
        let were = if names.len() == 1 { "was" } else { "were" };
        CliError::Msg(format!("{} {were} sealed anew or removed while this command waited: none is built from what that replaced", names.join(" and ")))
    };
    let names = changed();
    if !names.is_empty() {
        return Err(superseded(names));
    }
    remove_combined(paths);
    let plaintext = render_combined(key_id, secret, token);
    let sealed_at = rfc3339_utc(unix_now());
    let notes = [("kind", "combined"), ("parts", "aws,setup-token"), ("aws_file_sha256", aws_sha), ("token_file_sha256", token_sha), ("sealed", sealed_at.as_str())];
    let sealed = seal_file(store, paths, key_name, &paths.combined_env(), plaintext.as_bytes(), &[secret.as_bytes(), token.expose().as_bytes()], &notes, force)?;
    // Sealed anew while this one was written: what it wrote pairs a replaced source, and goes.
    let names = changed();
    if !names.is_empty() {
        return Err(superseded(names));
    }
    Ok(sealed.path)
}

/// Is `[aws].credentials` the sealed container (the only mode with a
/// `combined.env`)? `Err(why)` otherwise.
fn container_mode(paths: &Paths) -> std::result::Result<(), String> {
    let cfg = BridgeConfig::load(paths).map_err(|e| e.to_string())?.unwrap_or_default();
    match CredentialsSource::parse(&cfg.aws.credentials) {
        Ok(CredentialsSource::Container) => Ok(()),
        Ok(CredentialsSource::Profile(name)) => Err(format!("[aws].credentials is profile:{name}, so the runtime key is not sealed here")),
        Err(e) => Err(e.to_string()),
    }
}

/// Will `creds setup-token` rebuild `combined.env` (one Touch ID)? `Err(why)`
/// when it will not: not in container mode, or no runtime key sealed yet.
/// Decided before the seal is recorded, so its audit row says which.
fn rebuild_planned(paths: &Paths) -> std::result::Result<(), String> {
    container_mode(paths)?;
    if aws_env_state(&paths.aws_env()) != AwsEnvState::Sealed {
        return Err("no runtime key is sealed yet (`make runtime-key` builds it)".into());
    }
    Ok(())
}

/// After `creds setup-token` sealed `token`, when [`rebuild_planned`]:
/// rebuild `combined.env` from the runtime key (one Touch ID), recording
/// `token_sha` (the setup-token.env text the command sealed,
/// `Sealed::sha256`) and the aws.env text that prompt decrypted
/// ([`seal_combined`]). The old one
/// holds the replaced token, so the caller removed it before anything that
/// may end the command (`removed`: whether there was one): a Ctrl-C or a
/// closed terminal while Touch ID is asked for (no handler runs then) leaves
/// none.
fn rebuild_with_token(store: &Keystore, paths: &Paths, key_name: &str, token: &SetupToken, token_sha: &str, force: bool, removed: bool) -> CombinedOutcome {
    let built = (|| -> Result<PathBuf> {
        // An aws.env in the clear since `rebuild_planned` found it sealed may hold the key: rotated too, as
        // `unseal_runtime_key` says.
        if let AwsEnvState::NotSealed(why) = aws_env_state(&paths.aws_env()) {
            return Err(CliError::AuthUnavailable(format!("{} {why}: move it away (and rotate the key it holds), then seal the runtime key with `make runtime-key`", paths.aws_env().display())));
        }
        let (plain, aws_sha) = decrypt_file_hashed(store, &paths.aws_env(), key_name, "seal the runtime key with `make runtime-key`")?;
        let (id, secret) = crate::bridge::vm::client::parse_runtime_env(&plain)?;
        drop(plain);
        seal_combined(store, paths, key_name, &id, &secret, token, &aws_sha, token_sha, force)
    })();
    match built {
        Ok(path) => CombinedOutcome::Built(path),
        Err(e) => CombinedOutcome::Failed { why: scrub(&e.to_string()).into_owned(), removed },
    }
}

/// After `creds aws-set` sealed a new runtime key: rebuild `combined.env`
/// from the sealed token (one Touch ID), when one is sealed; else delete an
/// old one. It records `aws_sha`, the hash of the aws.env text the command
/// sealed (`Sealed::sha256`), and the setup-token.env text that prompt
/// decrypted ([`seal_combined`]): a second `creds aws-set` that sealed
/// anew before this one got here (after its seal's audit row and stdout
/// lines) leaves no `combined.env` pairing this command's key with that text.
/// The old one, holding the replaced key, goes before
/// the prompt, as in [`rebuild_with_token`]. Prints and audits what happened
/// ([`report_combined`]), and nothing when there is no token.
pub fn after_aws_set(store: &Keystore, paths: &Paths, key_name: &str, key_id: &str, secret: &str, aws_sha: &str, force: bool) {
    let removed = remove_combined(paths);
    let outcome = if let Err(why) = container_mode(paths) {
        CombinedOutcome::Skipped { why, removed }
    } else if aws_env_state(&paths.setup_token_env()) != AwsEnvState::Sealed {
        CombinedOutcome::Skipped { why: String::new(), removed }
    } else {
        let built = (|| -> Result<PathBuf> {
            let (plain, token_sha) = decrypt_file_hashed(store, &paths.setup_token_env(), key_name, "seal it with `ai-env creds setup-token`")?;
            let token = parse_token_env(&plain)?;
            drop(plain);
            seal_combined(store, paths, key_name, key_id, secret, &token, aws_sha, &token_sha, force)
        })();
        match built {
            Ok(path) => CombinedOutcome::Built(path),
            Err(e) => CombinedOutcome::Failed { why: scrub(&e.to_string()).into_owned(), removed },
        }
    };
    report_combined(paths, &outcome, "aws-set");
}

/// One line on what became of `combined.env` after the sealing command `by`
/// (`setup-token` or `aws-set`), and the audit row `creds_combined` with its
/// outcome; nothing when there was nothing to do. The sealing command's own
/// row comes before the rebuild's Touch ID, so this one records how it ended.
fn report_combined(paths: &Paths, outcome: &CombinedOutcome, by: &str) {
    if matches!(outcome, CombinedOutcome::Skipped { why, removed: false } if why.is_empty()) {
        return;
    }
    let removed = matches!(outcome, CombinedOutcome::Skipped { removed: true, .. } | CombinedOutcome::Failed { removed: true, .. });
    let row = audit::AuditRow::new("creds_combined", None, audit::detail(&[("by", by.to_string()), ("outcome", outcome.word().into()), ("removed", removed.to_string())]));
    if let Err(e) = audit::append(&paths.audit(), &row) {
        eprintln!("warning: the audit row creds_combined was not written: {e}");
    }
    match outcome {
        CombinedOutcome::Built(path) => {
            let _ = crate::commands::outln(format_args!("rebuilt {}: a credentialed command asks for Touch ID once", path.display()));
        }
        CombinedOutcome::Skipped { why, removed } => {
            if *removed {
                eprintln!("removed the out-of-date combined.env{}", if why.is_empty() { String::new() } else { format!(" ({why})") });
            } else if !why.is_empty() {
                let _ = crate::commands::outln(format_args!("combined.env not built: {why}"));
            }
        }
        CombinedOutcome::Failed { why, removed } => {
            let gone = if *removed { "; the out-of-date one was removed" } else { "" };
            // Current now only when another sealing command built it while this one waited (F2): that one is used.
            let then = if combined_state(paths) == CombinedState::Current {
                "the combined.env there now, which another command built, matches its sources"
            } else {
                "a credentialed command asks for Touch ID twice until `ai-env creds setup-token` or `make runtime-key` rebuilds it"
            };
            eprintln!("warning: combined.env not built ({why}){gone}: {then}");
        }
    }
}

// ---- creds setup-token ------------------------------------------------------------------

/// Where the token came from (for the audit row and the reminder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Paste,
    Stdin,
    Env,
}

impl Source {
    fn word(self) -> &'static str {
        match self {
            Source::Paste => "paste",
            Source::Stdin => "stdin",
            Source::Env => "env",
        }
    }
}

/// `creds setup-token`'s flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct SetupTokenOpts {
    pub stdin: bool,
    pub from_env: bool,
    pub no_combined: bool,
    pub force: bool,
}

/// At most `max` bytes of `f` into one zeroizing buffer allocated once. A
/// `File` (a dup of fd 0), never a `Stdin`: std's process-wide stdin
/// buffer, which is never zeroized, would keep any later piece of a token
/// written in two parts for the rest of the process.
fn read_bounded(f: &mut std::fs::File, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; max + 1]);
    let mut n = 0;
    while n <= max {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(CliError::Msg(format!("cannot read stdin: {e}"))),
        }
    }
    if n > max {
        return Err(CliError::Msg(format!("stdin holds more than {} KiB: not one setup-token", max / 1024)));
    }
    buf.truncate(n);
    Ok(buf)
}

/// The token's raw text, from the source the flags name.
fn read_token_input(o: SetupTokenOpts) -> Result<(Zeroizing<String>, Source)> {
    if o.from_env {
        let v = std::env::var(TOKEN_VAR).map_err(|_| CliError::Usage(format!("--from-env: {TOKEN_VAR} is not set (or not UTF-8)")))?;
        return Ok((Zeroizing::new(v), Source::Env));
    }
    if o.stdin {
        if std::io::stdin().is_terminal() {
            return Err(CliError::Usage("--stdin reads a pipe and stdin is a terminal: run without --stdin to paste it hidden".into()));
        }
        // The whole pipe: a second line (a token wrapped in two) is refused by the parse, never cut off.
        let bytes = read_bounded(&mut crate::ceremony::stdin_file()?, MAX_STDIN)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| CliError::Msg("stdin is not UTF-8: not a setup-token".into()))?;
        return Ok((Zeroizing::new(text.to_string()), Source::Stdin));
    }
    let v = crate::ceremony::read_secret_from_tty("Paste the token `claude setup-token` printed (input hidden): ")?;
    Ok((v, Source::Paste))
}

/// `ai-env creds setup-token [--stdin|--from-env] [--no-combined] [--force]`.
pub fn cmd_setup_token(store: &Keystore, o: SetupTokenOpts) -> Result<()> {
    let paths = Paths::resolve()?;
    let key = key_name(&paths)?;
    let target = paths.setup_token_env();
    // Everything that can refuse without the token, before it is asked for.
    let (rows, _) = preflight_for(store, &paths, &key, &target, o.force);
    if let Some(e) = rows.into_iter().find_map(std::result::Result::err) {
        return Err(e);
    }
    let (raw, source) = read_token_input(o)?;
    let token = parse_token(&raw).map_err(TokenFault::into_cli)?;
    drop(raw);
    let prefix = token.prefix().unwrap_or("unrecognised").to_string();
    let chars = token.len().to_string();
    let sealed_at = rfc3339_utc(unix_now());
    let sealed = {
        let plaintext = render_token_env(&token);
        let notes = [("kind", "setup-token"), ("prefix", prefix.as_str()), ("chars", chars.as_str()), ("sealed", sealed_at.as_str())];
        seal_file(store, &paths, &key, &target, plaintext.as_bytes(), &[token.expose().as_bytes()], &notes, o.force)?
    };
    // The hash of the text just sealed (`Sealed::sha256`): what the rebuild records of the token's source (F2),
    // never a read of the file, which another command may have sealed anew since.
    let token_sha = sealed.sha256.as_str();
    // The token is sealed from here on. The old combined.env holds the replaced token: it goes first. What
    // records the seal (the audit row, the probe row, the "sealed" lines) and the reminder to clear where the
    // token came through come before the rebuild's Touch ID, which a Ctrl-C or a closed terminal may end with
    // no handler run (M47); the rebuild's outcome follows it.
    let removed = remove_combined(&paths);
    let rebuild = if o.no_combined { Err("--no-combined (a credentialed command asks for Touch ID twice)".to_string()) } else { rebuild_planned(&paths) };
    // A failed audit write is a warning.
    let row = audit::AuditRow::new(
        "creds_setup_token",
        None,
        audit::detail(&[
            ("key", key.clone()),
            ("prefix", prefix.clone()),
            ("chars", chars.clone()),
            ("source", source.word().into()),
            ("rotated", sealed.backup.is_some().to_string()),
            ("combined", if rebuild.is_ok() { "rebuild" } else { "skipped" }.into()),
        ]),
    );
    if let Err(e) = audit::append(&paths.audit(), &row) {
        eprintln!("warning: the token is sealed but the audit row was not written: {e}");
    }
    let shown = if prefix == "unrecognised" { "of an unrecognised shape".to_string() } else { format!("{prefix}…") };
    outln!("sealed setup-token {shown} ({chars} chars) into {} (key {key})", sealed.path.display());
    if let Some(bak) = &sealed.backup {
        outln!("previous container kept as {}", bak.display());
    }
    // The setup-token-prefix probe (S7): the kind marker as observed, never validated.
    if let Some(spec) = crate::bridge::probes::spec("setup-token-prefix") {
        let row = crate::bridge::probes::stamped(&paths, spec, &prefix, Some(format!("chars={chars}, sealed {sealed_at}")));
        if let Err(e) = crate::bridge::probes::record(&paths, &row) {
            eprintln!("warning: the token is sealed but the setup-token-prefix probe row was not written: {e}");
        }
    }
    match source {
        Source::Paste => eprintln!("now clear the terminal's scrollback and the clipboard (pbcopy </dev/null)"),
        Source::Env => eprintln!("now unset {TOKEN_VAR} in the shell that held it"),
        // `pbpaste | …` leaves it in the clipboard, `echo … |` in the shell's history.
        Source::Stdin => eprintln!("now clear the clipboard if the token came from it (pbcopy </dev/null), and any file or shell history line that holds it"),
    }
    let combined = match rebuild {
        Ok(()) => rebuild_with_token(store, &paths, &key, &token, token_sha, o.force, removed),
        Err(why) => CombinedOutcome::Skipped { why, removed },
    };
    drop(token);
    report_combined(&paths, &combined, "setup-token");
    Ok(())
}

// ---- creds status -----------------------------------------------------------------------

fn state_text(f: &FileFacts) -> (Tag, String) {
    let name = f.path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    match &f.state {
        AwsEnvState::Absent => (Tag::Skip, format!("{name}: absent")),
        AwsEnvState::NotSealed(why) => (Tag::No, format!("{name} {why}")),
        AwsEnvState::Sealed => match &f.opens_with {
            Some(Ok(k)) => (Tag::Ok, format!("{name}: sealed, opens with key {k}")),
            Some(Err(OpenFault::NoKey(e))) => (Tag::No, format!("{name}: sealed, but {e}")),
            Some(Err(OpenFault::Unknown(e))) => (Tag::Warn, format!("{name}: sealed; which key opens it is unknown ({e})")),
            None => (Tag::Warn, format!("{name}: sealed, unreadable")),
        },
    }
}

fn combined_text(paths: &Paths, mode: &std::result::Result<(), String>, token_sealed: bool) -> (Tag, String) {
    combined_line(&combined_state(paths), mode, token_sealed)
}

/// The `combined.env` row's tag and text for `state`, shared by `creds
/// status` and doctor.
#[must_use]
pub fn combined_line(state: &CombinedState, mode: &std::result::Result<(), String>, token_sealed: bool) -> (Tag, String) {
    match (state, mode) {
        (CombinedState::Absent, Err(why)) => (Tag::Skip, format!("combined.env: not used ({why})")),
        (CombinedState::Absent, Ok(())) if !token_sealed => (Tag::Skip, "combined.env: not needed (no setup-token is sealed)".into()),
        (_, Err(why)) => (Tag::Warn, format!("combined.env: {} but not used ({why}): `ai-env creds forget` removes it", state.word())),
        (CombinedState::Current, Ok(())) => (Tag::Ok, "combined.env: matches its sources (a credentialed command asks for Touch ID once)".into()),
        (CombinedState::Absent, Ok(())) => (Tag::Warn, "combined.env: absent (two Touch IDs per credentialed command until `ai-env creds setup-token` builds it)".into()),
        (CombinedState::Stale(why), Ok(())) => (Tag::Warn, format!("combined.env: out of date, {why} (two Touch IDs until `ai-env creds setup-token` rebuilds it)")),
        (CombinedState::NotSealed(why), Ok(())) => (Tag::No, format!("combined.env {why}")),
    }
}

/// The credential gate's local preconditions for a fresh `vpc` VM of the
/// image version new VMs run: doctor's row, judged from what is on disk (no
/// AWS call, no Touch ID).
fn gate_line(paths: &Paths, cfg: &BridgeConfig, now: u64) -> (Tag, String) {
    let state = crate::bridge::infra::read_infra_state(paths);
    let verified = crate::bridge::egress::EgressVerified::load(paths);
    let newest = crate::bridge::egress::newest_dns_path_row(paths).map(|r| r.map(|(verdict, _)| verdict));
    match crate::bridge::doctor::row_credential_gate(cfg, &state, &verified, &newest, now) {
        crate::commands::DoctorLine::Row { tag, text } => (tag, text),
        crate::commands::DoctorLine::Plain(text) => (Tag::Skip, text),
    }
}

/// `ai-env creds status [--json] [--unseal]`: no Touch ID unless `--unseal`.
pub fn cmd_status(store: &Keystore, json: bool, unseal: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let cfg = BridgeConfig::load(&paths)?.unwrap_or_default();
    let now = unix_now();
    let aws = file_facts(store, paths.aws_env());
    let token = file_facts(store, paths.setup_token_env());
    // As `vm exec` reads it (M53): a store that cannot be read is shown as such, never as no refusal.
    let rejected = crate::bridge::agent::credential::seal_tag(&token.path).map_or(Ok(None), |tag| crate::bridge::agent::credential::read_rejection(&paths, &tag));
    let mode = container_mode(&paths);
    let combined = combined_state(&paths);
    let backups: Vec<(String, usize)> = ["aws.env", "setup-token.env", "combined.env"].iter().map(|f| ((*f).to_string(), backups_of(&paths, f).len())).collect();
    let (gate_tag, gate_text) = gate_line(&paths, &cfg, now);
    let held = holders(&paths);
    let creds_ok = cfg.creds.validate().map_err(|e| e.to_string());
    let timed = if unseal {
        let started = std::time::Instant::now();
        let t = unseal_setup_token(store, &paths, &cfg.creds.key)?;
        let ms = started.elapsed().as_millis();
        let (prefix, chars) = (t.prefix().unwrap_or("unrecognised").to_string(), t.len());
        drop(t);
        Some((ms, prefix, chars))
    } else {
        None
    };
    if json {
        let file = |f: &FileFacts| {
            serde_json::json!({
                "path": f.path.display().to_string(),
                "state": match &f.state { AwsEnvState::Absent => "absent".to_string(), AwsEnvState::Sealed => "sealed".to_string(), AwsEnvState::NotSealed(w) => format!("not-sealed: {w}") },
                "opens_with": f.opens_with.as_ref().and_then(|r| r.as_ref().ok()),
                "recorded": { "prefix": f.recorded.prefix, "chars": f.recorded.chars, "sealed_at": f.recorded.sealed_at.map(rfc3339_utc), "days_left": f.recorded.days_left(now) },
            })
        };
        let doc = serde_json::json!({
            "creds": { "key": cfg.creds.key, "mode": cfg.creds.mode, "deliver": cfg.creds.deliver, "unseal_timeout_s": cfg.creds.unseal_timeout_s, "valid": creds_ok.as_ref().err() },
            "aws_credentials": cfg.aws.credentials,
            "aws_env": file(&aws),
            "setup_token_env": file(&token),
            "rejected": rejected.as_ref().ok().and_then(Option::as_ref).map(|r| serde_json::json!({"at": r.at, "vm": r.vm})),
            "rejected_error": rejected.as_ref().err(),
            "combined_env": { "state": combined.word(), "used": mode.is_ok() },
            "backups": backups.iter().map(|(f, n)| (f.clone(), serde_json::json!(n))).collect::<serde_json::Map<_, _>>(),
            "credential_gate": { "tag": gate_tag.json_name(), "text": gate_text },
            "holders": held.as_ref().ok().map(|(held, _)| held.iter().map(|h| serde_json::json!({"id": h.id, "status": h.status, "credential_at": rfc3339_utc(h.credential_at)})).collect::<Vec<_>>()),
            "holders_unreadable": held.as_ref().ok().map(|(_, unread)| unread),
            "holders_error": held.as_ref().err(),
            "unseal": timed.as_ref().map(|(ms, p, n)| serde_json::json!({"ms": ms, "prefix": p, "chars": n})),
        });
        outln!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return Ok(());
    }
    let row = |tag: Tag, text: String| crate::commands::outln(format_args!("{} {text}", tag.bracket()));
    row(
        if creds_ok.is_ok() { Tag::Ok } else { Tag::No },
        match &creds_ok {
            Ok(()) => format!("[creds] key {}, mode {}, deliver {}, Touch ID budget {} s", cfg.creds.key, cfg.creds.mode, cfg.creds.deliver, cfg.creds.unseal_timeout_s),
            Err(e) => e.clone(),
        },
    )?;
    row(Tag::Ok, format!("[aws].credentials {}", cfg.aws.credentials))?;
    let (tag, text) = state_text(&aws);
    row(tag, text)?;
    let (tag, mut text) = state_text(&token);
    if token.state == AwsEnvState::Sealed {
        let r = &token.recorded;
        text.push_str(&format!("; recorded at sealing, not authenticated: {}", r.describe()));
        if let (Some(at), Some(left)) = (r.sealed_at, r.days_left(now)) {
            text.push_str(&format!(", sealed {} (about {left} days left of its one-year life)", &rfc3339_utc(at)[..10]));
        }
    }
    let token_tag = match token.recorded.days_left(now) {
        Some(left) if tag == Tag::Ok && left < WARN_DAYS_LEFT => Tag::Warn,
        _ => tag,
    };
    row(token_tag, text)?;
    match &rejected {
        Ok(Some(r)) => row(Tag::No, format!("the sealed setup-token was refused by Anthropic on {} ({}): credentialed commands refuse it until `ai-env creds setup-token` seals a fresh one", r.at, r.vm))?,
        Ok(None) => {}
        Err(e) => row(Tag::Warn, format!("refusals unknown: {e}: credentialed commands refuse every seal until it is repaired, or removed to forget every recorded refusal"))?,
    }
    let (tag, text) = combined_text(&paths, &mode, token.state == AwsEnvState::Sealed);
    row(tag, text)?;
    let listed: Vec<String> = backups.iter().filter(|(_, n)| *n > 0).map(|(f, n)| format!("{f} x{n}")).collect();
    row(Tag::Skip, if listed.is_empty() { "backups: none".into() } else { format!("backups: {}", listed.join(", ")) })?;
    row(gate_tag, gate_text)?;
    match &held {
        Err(e) => row(Tag::Warn, format!("VMs that may hold the token: unknown, the VM registry cannot be read ({e})"))?,
        Ok((held, unread)) if held.is_empty() && unread.is_empty() => row(Tag::Skip, "VMs that may hold the token: none".into())?,
        Ok((held, unread)) => {
            for h in held {
                row(Tag::Warn, format!("{} ({}) received the token at {}: it may hold it until terminated", h.id, h.status, rfc3339_utc(h.credential_at)))?;
            }
            for u in unread {
                row(Tag::Warn, format!("{UNREADABLE_ROW}: {u}"))?;
            }
        }
    }
    if let Some((ms, prefix, chars)) = timed {
        let shown = if prefix == "unrecognised" { "of an unrecognised shape".to_string() } else { format!("{prefix}…") };
        let matches = token.recorded.chars == Some(chars) && token.recorded.prefix.as_deref() == Some(prefix.as_str());
        row(Tag::Ok, format!("unsealed setup-token.env in {ms} ms: {shown} ({chars} chars){}", if matches { ", as recorded" } else { ", NOT as recorded" }))?;
    }
    Ok(())
}

// ---- doctor ------------------------------------------------------------------------------

/// doctor's setup-token row: absent (`[-  ]`, how to seal one), not sealed
/// (`[NO ]`: a plaintext or a link where the container goes), refused by
/// Anthropic against its seal (`[NO ]`), or sealed with what was recorded
/// then (`[!! ]` past 330 days of its one-year life).
#[must_use]
pub fn row_setup_token(state: &AwsEnvState, path: &Path, recorded: &Recorded, rejected: Option<&crate::bridge::agent::credential::Rejection>, now: u64) -> crate::commands::DoctorLine {
    use crate::commands::DoctorLine;
    match state {
        AwsEnvState::Absent => DoctorLine::row(Tag::Skip, format!("setup-token absent ({})  <- claude setup-token, then ai-env creds setup-token", path.display())),
        AwsEnvState::NotSealed(why) => DoctorLine::row(Tag::No, format!("setup-token NOT sealed: {} {why}  <- move it away (and revoke what it holds), then ai-env creds setup-token", path.display())),
        AwsEnvState::Sealed => {
            if let Some(r) = rejected {
                return DoctorLine::row(Tag::No, format!("setup-token refused by Anthropic on {} ({})  <- claude setup-token, then ai-env creds setup-token", r.at, r.vm));
            }
            let left = recorded.days_left(now);
            let mut text = format!("setup-token sealed: {}", recorded.describe());
            if let (Some(at), Some(left)) = (recorded.sealed_at, left) {
                text.push_str(&format!(", sealed {} (about {left} days left of its one-year life)", &rfc3339_utc(at)[..10]));
            }
            let tag = if left.is_some_and(|l| l < WARN_DAYS_LEFT) { Tag::Warn } else { Tag::Ok };
            DoctorLine::row(tag, text)
        }
    }
}

/// doctor's credential rows (S7), from what is on disk, with no Touch ID:
/// the setup-token, a `[!! ]` row when `state/creds.toml` cannot be read
/// (which seals Anthropic refused is then unknown, and credentialed commands
/// refuse every seal: never shown as no refusal), and `combined.env`
/// against its sources.
#[must_use]
pub fn doctor_rows(paths: &Paths, now: u64) -> Vec<crate::commands::DoctorLine> {
    use crate::commands::DoctorLine;
    let path = paths.setup_token_env();
    let state = aws_env_state(&path);
    let text = (state == AwsEnvState::Sealed).then(|| crate::bridge::registry::read_regular_file(&path).ok().flatten()).flatten();
    let recorded = text.as_deref().map(Recorded::of).unwrap_or_default();
    let rejected = crate::bridge::agent::credential::seal_tag(&path).map_or(Ok(None), |tag| crate::bridge::agent::credential::read_rejection(paths, &tag));
    let (tag, line) = combined_line(&combined_state(paths), &container_mode(paths), state == AwsEnvState::Sealed);
    let mut rows = vec![row_setup_token(&state, &path, &recorded, rejected.as_ref().ok().and_then(Option::as_ref), now)];
    if let Err(e) = &rejected {
        rows.push(DoctorLine::row(Tag::Warn, format!("setup-token refusals unknown: {e}  <- repair it, or remove it to forget every recorded refusal (credentialed commands refuse every seal meanwhile)")));
    }
    rows.push(DoctorLine::row(tag, line));
    rows
}

// ---- creds forget -----------------------------------------------------------------------

/// `ai-env creds forget [--yes]`: a dry run without `--yes`.
pub fn cmd_forget(yes: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let mut files: Vec<PathBuf> = [paths.setup_token_env(), paths.combined_env()].into_iter().filter(|p| std::fs::symlink_metadata(p).is_ok()).collect();
    files.extend(backups_of(&paths, "setup-token.env"));
    files.extend(backups_of(&paths, "combined.env"));
    let (held, unread) = holders(&paths).unwrap_or_else(|e| {
        eprintln!("warning: the VM registry cannot be read ({e}): VMs that received the token are not listed; `ai-env vm list` shows them");
        (Vec::new(), Vec::new())
    });
    let verb = if yes { "deleting" } else { "would delete" };
    if files.is_empty() {
        outln!("nothing to delete: no setup-token, combined.env or backup of them under {}", paths.credentials().display());
    }
    for f in &files {
        outln!("{verb} {}", f.display());
    }
    for h in &held {
        outln!("{} ({}) received the token at {}: only terminating it clears its copies: ai-env vm terminate {}", h.id, h.status, rfc3339_utc(h.credential_at), h.id);
    }
    for u in &unread {
        outln!("{UNREADABLE_ROW}: {u}; only terminating its VM clears its copies (`ai-env vm list` shows the VMs)");
    }
    outln!("ai-env cannot revoke the token: revoke it on Anthropic's side (README, Credentials)");
    if !yes {
        outln!("dry run: nothing deleted; pass --yes to delete");
        return Ok(());
    }
    let mut failed = Vec::new();
    for f in &files {
        if let Err(e) = std::fs::remove_file(f) {
            if e.kind() != ErrorKind::NotFound {
                failed.push(format!("{}: {e}", f.display()));
            }
        }
    }
    let row = audit::AuditRow::new(
        "creds_forget",
        None,
        audit::detail(&[("files", files.len().to_string()), ("holders", held.len().to_string()), ("holders_unreadable", unread.len().to_string()), ("failed", failed.len().to_string())]),
    );
    if let Err(e) = audit::append(&paths.audit(), &row) {
        eprintln!("warning: the audit row was not written: {e}");
    }
    if !failed.is_empty() {
        return Err(CliError::Msg(format!("could not delete: {}", failed.join("; "))));
    }
    outln!("deleted {} file(s)", files.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token of the setup-token shape, built at run time with `tail`.
    fn shaped(tail: &str) -> String {
        format!("{ANTHROPIC}oat01-{}{tail}", "Zx9_".repeat(20))
    }

    /// Every shape a token arrives in (padded, a dotenv line, after `export`)
    /// parses to the token itself; `Debug` shows its length only.
    #[test]
    fn parse_accepts_the_shapes_a_token_arrives_in() {
        let t = shaped("Ab");
        for raw in [t.clone(), format!("  {t}\n"), format!("{TOKEN_VAR}={t}"), format!("export {TOKEN_VAR}={t}\n"), format!("export   {t}")] {
            let tok = parse_token(&raw).unwrap_or_else(|f| panic!("{}: {}", raw.len(), f.message));
            assert!(tok.expose() == t, "{} bytes in: {} bytes parsed, {} expected", raw.len(), tok.len(), t.len());
            assert_eq!(tok.prefix(), Some("sk-ant-oat01-"));
        }
        let dbg = format!("{:?}", parse_token(&t).unwrap());
        assert!(dbg == format!("SetupToken([redacted:len={}])", t.len()), "{}", scrub(&dbg));
    }

    /// Each refusal names what is wrong, with the exit class its kind gets
    /// (an API key 9, anything else 1), and never the input; the length
    /// bounds are inclusive.
    #[test]
    fn parse_refuses_what_is_not_a_setup_token_and_never_echoes_it() {
        let t = shaped("Cd");
        let api = format!("{ANTHROPIC}api03-{}", "Q".repeat(40));
        let cases: Vec<(String, &str, bool)> = vec![
            (String::new(), "no token was given", false),
            ("   \n".into(), "no token was given", false),
            (format!("{t} {t}"), "whitespace", false),
            (format!("{t}\n{t}"), "whitespace", false),
            (format!("\"{t}\""), "a quote", false),
            (format!("{t}$x"), "a `$`", false),
            (format!("{t}\\"), "a backslash", false),
            (format!("{t}\u{e9}"), "not printable ASCII", false),
            ("short-value".into(), "11 characters, expected 20 to 4096", false),
            ("x".repeat(MAX_CHARS + 1), "4097 characters", false),
            (api.clone(), "an Anthropic API key", true),
            (format!("{ANTHROPIC}admin01-{}", "Q".repeat(40)), "an Anthropic API key", true),
        ];
        for (raw, want, policy) in cases {
            let f = parse_token(&raw).expect_err("refused");
            assert!(f.message.contains(want), "{}: want {want:?} in {:?}", raw.len(), scrub(&f.message));
            assert_eq!(f.policy, policy, "{want}");
            assert!(raw.len() < 8 || !f.message.contains(&raw), "the input leaked into {:?}", scrub(&f.message));
            assert!(!f.message.contains(&t) && !f.message.contains(&api[12..]), "a value leaked into {:?}", scrub(&f.message));
        }
        assert_eq!(parse_token(&api).unwrap_err().into_cli().exit_code(), 9);
        assert_eq!(parse_token("").unwrap_err().into_cli().exit_code(), 1);
        // Exactly the bounds. Of an unrecognised shape, so registered with the
        // process-wide scrubber, but only while the handle lives: the
        // temporary is gone at the end of its statement, and its value with it.
        for n in [MIN_CHARS, MAX_CHARS] {
            let bound = format!("bound-{}", "7".repeat(n - 6));
            assert!(parse_token(&bound).is_ok(), "{n}");
            assert!(!crate::wire::redact::forget_secret(&bound), "{n}: forgotten with its handle");
        }
    }

    /// The recorded prefix is the kind marker and nothing of the random part.
    /// Another shape is unrecognised and registered with the scrubber while a
    /// handle holds it: masked until the last handle of that value drops, then
    /// forgotten, so the registry never keeps a copy past the token.
    #[test]
    fn the_prefix_is_the_kind_only_and_odd_shapes_are_registered() {
        let t = parse_token(&shaped("Ef")).unwrap();
        assert_eq!(t.prefix(), Some("sk-ant-oat01-"));
        assert_eq!(known_prefix(&format!("{ANTHROPIC}oat01-short")), None, "a tail under 8");
        assert_eq!(known_prefix(&format!("{ANTHROPIC}01-{}", "Q".repeat(20))), None, "a kind without a letter");
        assert_eq!(known_prefix(&format!("{ANTHROPIC}oat01-{}+", "Q".repeat(20))), None, "a char the scrubber does not mask");
        let odd = format!("odd-shape-{}", "W7".repeat(15));
        let masked = || !scrub(&format!("x {odd} y")).contains(&odd);
        let tok = parse_token(&odd).unwrap();
        assert_eq!(tok.prefix(), None);
        assert!(masked(), "an unrecognised token is masked by registration");
        let again = parse_token(&odd).unwrap();
        drop(tok);
        assert!(masked(), "still masked while another handle holds the value");
        drop(again);
        assert!(!masked(), "forgotten with the last handle");
        assert!(!crate::wire::redact::forget_secret(&odd), "the registry's copy is gone");
        // A recognised one is masked by the shape rule alone, never registered.
        let shaped_value = shaped("Gh");
        let held = parse_token(&shaped_value).unwrap();
        assert!(!scrub(&format!("x {shaped_value} y")).contains(&shaped_value[13..]));
        assert!(!crate::wire::redact::forget_secret(held.expose()), "a recognised shape is not registered");
    }

    /// The setup-token.env plaintext is one dotenv line, sized once, that
    /// parses back to the token; any other plaintext is exit 5 naming the
    /// problem and the re-seal, never the value.
    #[test]
    fn the_token_plaintext_round_trips_and_nothing_else_parses() {
        let t = parse_token(&shaped("Ij")).unwrap();
        let env = render_token_env(&t);
        assert!(env.as_str() == format!("{TOKEN_VAR}={}\n", t.expose()), "{} bytes rendered", env.len());
        assert_eq!(env.capacity(), env.len(), "sized once, never reallocated");
        for plain in [env.as_str(), env.trim_end()] {
            let back = parse_token_env(plain.as_bytes()).unwrap();
            assert!(back.expose() == t.expose(), "{} bytes parsed back, {} expected", back.len(), t.len());
        }
        let vars = crate::dotenv::parse(&env).expect("a dotenv file ai-env run can inject");
        assert_eq!(vars.len(), 1);
        for (plain, want) in [
            (b"\xff".to_vec(), "not UTF-8"),
            (format!("{}{}", env.as_str(), env.as_str()).into_bytes(), "not one line"),
            (format!("OTHER={}\n", t.expose()).into_bytes(), "is not CLAUDE_CODE_OAUTH_TOKEN="),
            (format!("{TOKEN_VAR}=\n").into_bytes(), "no token was given"),
        ] {
            let e = parse_token_env(&plain).unwrap_err();
            let text = e.to_string();
            assert_eq!(CliError::from(e).exit_code(), 5);
            assert!(text.contains(want) && text.contains("ai-env creds setup-token") && !text.contains(t.expose()), "{}", scrub(&text));
        }
    }

    /// F11: `unseal_setup_token_text` unseals the text it is handed, never
    /// `setup-token.env`: with no such file it still goes on to the keystore
    /// (which lacks the key here, so `age` is never started); a bad
    /// `[creds].key` is refused before that.
    #[test]
    fn the_token_text_is_unsealed_without_reading_its_file() {
        let d = tempfile::tempdir().unwrap();
        let store = Keystore::resolve(Some(d.path().join("keys"))).unwrap();
        let text = container::write(b"age-encryption.org/v1\n-> x\n--- y\n");
        let why = |key: &str| unseal_setup_token_text(&store, &text, key).map(|_| ()).unwrap_err().to_string();
        assert!(why("ai-env-bridge").starts_with("key \"ai-env-bridge\" does not exist"), "{}", why("ai-env-bridge"));
        assert!(why("Bad Key").starts_with("[creds].key: "), "{}", why("Bad Key"));
    }

    /// The combined.env plaintext is aws.env's two lines then the token's,
    /// sized once, and splits back into both; a doubled, missing or keyless
    /// token line is refused without the value.
    #[test]
    fn the_combined_plaintext_carries_both_and_parses_back() {
        let t = parse_token(&shaped("Kl")).unwrap();
        let (id, secret) = (format!("AKIA{}", "COMB".repeat(4)), format!("{}{}", "Tq8+".repeat(9), "comb"));
        let plain = render_combined(&id, &secret, &t);
        assert!(plain.as_str() == format!("AWS_ACCESS_KEY_ID={id}\nAWS_SECRET_ACCESS_KEY={secret}\n{TOKEN_VAR}={}\n", t.expose()), "{} bytes rendered", plain.len());
        assert_eq!(plain.capacity(), plain.len());
        let ((pid, psecret), ptok) = parse_combined(plain.as_bytes()).unwrap();
        assert!((pid.as_str(), psecret.as_str(), ptok.expose()) == (id.as_str(), secret.as_str(), t.expose()), "parsed back as {}, {} and {} bytes", pid.len(), psecret.len(), ptok.len());
        let doubled = format!("{}{TOKEN_VAR}={}\n", plain.as_str(), t.expose());
        assert!(parse_combined(doubled.as_bytes()).unwrap_err().to_string().contains("appears twice"));
        let no_token = format!("AWS_ACCESS_KEY_ID={id}\nAWS_SECRET_ACCESS_KEY={secret}\n");
        assert!(parse_combined(no_token.as_bytes()).unwrap_err().to_string().contains("is missing"));
        let no_key = format!("{TOKEN_VAR}={}\n", t.expose());
        let e = parse_combined(no_key.as_bytes()).unwrap_err().to_string();
        assert!(e.contains("runtime key's lines do not parse") && !e.contains(t.expose()), "{}", scrub(&e));
    }

    #[test]
    fn recorded_metadata_is_read_and_aged() {
        let blob = b"age-encryption.org/v1\n-> x\n--- y\n";
        let text = container::write_annotated(blob, &[("kind", "setup-token"), ("prefix", "sk-ant-oat01-"), ("chars", "108"), ("sealed", "2026-10-07T00:00:00Z")]).unwrap();
        let r = Recorded::of(&text);
        assert_eq!((r.prefix.as_deref(), r.chars), (Some("sk-ant-oat01-"), Some(108)));
        let sealed = r.sealed_at.unwrap();
        assert_eq!(r.days_left(sealed), Some(365));
        assert_eq!(r.days_left(sealed + 86_400 * 30 + 5), Some(335));
        assert_eq!(r.days_left(sealed + 86_400 * 400), Some(-35));
        assert_eq!(r.describe(), "sk-ant-oat01-… (108 chars)");
        // A hand-edited prefix that is not one is not shown.
        let edited = text.replace("prefix=sk-ant-oat01-", "prefix=sk-live-12345");
        assert_eq!(Recorded::of(&edited).prefix, None);
        assert_eq!(Recorded::of(&container::write(blob)), Recorded::default());
    }

    /// `combined.env` is current only while both recorded hashes match.
    #[test]
    fn combined_state_follows_its_sources() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.credentials()).unwrap();
        assert_eq!(combined_state(&paths), CombinedState::Absent);
        let blob = b"age-encryption.org/v1\n-> x\n--- y\n";
        let (aws, token) = (container::write(blob), container::write_annotated(blob, &[("kind", "setup-token")]).unwrap());
        std::fs::write(paths.aws_env(), &aws).unwrap();
        std::fs::write(paths.setup_token_env(), &token).unwrap();
        let sha = |s: &str| {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(s.as_bytes()))
        };
        let (aws_sha, token_sha) = (sha(&aws), sha(&token));
        let combined = container::write_annotated(blob, &[("aws_file_sha256", &aws_sha), ("token_file_sha256", &token_sha)]).unwrap();
        std::fs::write(paths.combined_env(), &combined).unwrap();
        assert_eq!(combined_state(&paths), CombinedState::Current);
        std::fs::write(paths.setup_token_env(), container::write_annotated(blob, &[("kind", "setup-token"), ("chars", "1")]).unwrap()).unwrap();
        assert_eq!(combined_state(&paths), CombinedState::Stale("setup-token.env changed since it was built".into()));
        std::fs::write(paths.setup_token_env(), &token).unwrap();
        std::fs::remove_file(paths.aws_env()).unwrap();
        assert_eq!(combined_state(&paths), CombinedState::Stale("aws.env is gone".into()));
        std::fs::write(paths.aws_env(), &aws).unwrap();
        std::fs::write(paths.combined_env(), container::write(blob)).unwrap();
        assert_eq!(combined_state(&paths), CombinedState::Stale("it records no hash of aws.env".into()));
        std::fs::write(paths.combined_env(), "AWS_ACCESS_KEY_ID=x\n").unwrap();
        assert!(matches!(combined_state(&paths), CombinedState::NotSealed(_)));
        assert!(remove_combined(&paths) && !paths.combined_env().exists() && !remove_combined(&paths));
    }

    #[test]
    fn the_doctor_row_reads_the_recorded_facts_and_a_refusal() {
        use crate::commands::DoctorLine;
        let text = |l: DoctorLine| match l {
            DoctorLine::Row { tag, text } => (tag, text),
            DoctorLine::Plain(t) => panic!("{t}"),
        };
        let p = Path::new("/b/credentials/setup-token.env");
        let rec = Recorded { prefix: Some("sk-ant-oat01-".into()), chars: Some(108), sealed_at: Some(1_790_000_000) };
        let (tag, t) = text(row_setup_token(&AwsEnvState::Absent, p, &Recorded::default(), None, 1_790_000_000));
        assert!(tag == Tag::Skip && t.contains("<- claude setup-token, then ai-env creds setup-token"), "{t}");
        let (tag, t) = text(row_setup_token(&AwsEnvState::NotSealed("is a symlink".into()), p, &Recorded::default(), None, 0));
        assert!(tag == Tag::No && t.contains("is a symlink"), "{t}");
        let (tag, t) = text(row_setup_token(&AwsEnvState::Sealed, p, &rec, None, 1_790_000_000 + 86_400));
        assert_eq!((tag, t.as_str()), (Tag::Ok, "setup-token sealed: sk-ant-oat01-… (108 chars), sealed 2026-09-21 (about 364 days left of its one-year life)"));
        let (tag, _) = text(row_setup_token(&AwsEnvState::Sealed, p, &rec, None, 1_790_000_000 + 86_400 * 331));
        assert_eq!(tag, Tag::Warn, "past 330 days");
        let r = crate::bridge::agent::credential::Rejection { tag: "seal".into(), at: "2026-10-07T12:00:00Z".into(), vm: "microvm-1".into() };
        let (tag, t) = text(row_setup_token(&AwsEnvState::Sealed, p, &rec, Some(&r), 1_790_000_000));
        assert!(tag == Tag::No && t.contains("refused by Anthropic on 2026-10-07T12:00:00Z (microvm-1)"), "{t}");
        assert_eq!(combined_line(&CombinedState::Current, &Ok(()), true).0, Tag::Ok);
        assert_eq!(combined_line(&CombinedState::Absent, &Ok(()), false).0, Tag::Skip, "no token: nothing to combine");
        assert_eq!(combined_line(&CombinedState::Stale("aws.env changed since it was built".into()), &Ok(()), true).0, Tag::Warn);
        assert_eq!(combined_line(&CombinedState::Absent, &Err("profile".into()), true).0, Tag::Skip);
    }

    /// M53: doctor reads the refusals as `vm exec` does. A `state/creds.toml`
    /// that cannot be read is a `[!! ]` row naming it (credentialed commands
    /// refuse every seal meanwhile), between the setup-token's row, which
    /// then claims no refusal it cannot know, and combined.env's; a readable
    /// store adds no row.
    #[test]
    fn doctor_says_when_the_refusals_cannot_be_read() {
        use crate::commands::DoctorLine;
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.credentials()).unwrap();
        std::fs::write(paths.setup_token_env(), container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
        let rows = |paths: &Paths| doctor_rows(paths, 1_790_000_000).into_iter().map(|l| match l {
            DoctorLine::Row { tag, text } => (tag, text),
            DoctorLine::Plain(t) => panic!("{t}"),
        });
        assert_eq!(rows(&paths).count(), 2, "no store: the setup-token and combined.env");
        std::fs::create_dir_all(paths.creds_state().parent().unwrap()).unwrap();
        std::fs::write(paths.creds_state(), "[[rejected]\n").unwrap();
        let all: Vec<(Tag, String)> = rows(&paths).collect();
        assert_eq!(all.len(), 3, "{all:?}");
        let (tag, text) = &all[1];
        assert!(*tag == Tag::Warn && text.starts_with(&format!("setup-token refusals unknown: {} cannot be parsed (", paths.creds_state().display())), "{text}");
        assert!(all[0].1.starts_with("setup-token sealed") && all[2].1.starts_with("combined.env"), "{all:?}");
        std::fs::write(paths.creds_state(), "").unwrap();
        assert_eq!(rows(&paths).count(), 2, "a readable store adds no row");
    }

    #[test]
    fn backups_are_found_by_their_exact_name() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.credentials()).unwrap();
        for name in ["setup-token.env", "setup-token.env.1700000000.bak", "setup-token.env.1700000001.bak", "setup-token.env.x.bak", "setup-token.envy.1.bak", "combined.env.1700000002.bak", "aws.env.1700000003.bak"] {
            std::fs::write(paths.credentials().join(name), "x").unwrap();
        }
        let names = |f: &str| backups_of(&paths, f).iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        assert_eq!(names("setup-token.env"), ["setup-token.env.1700000000.bak", "setup-token.env.1700000001.bak"]);
        assert_eq!(names("combined.env"), ["combined.env.1700000002.bak"]);
    }

    /// `creds setup-token`'s rebuild that finds aws.env in the clear (it
    /// was sealed when the command chose to rebuild) builds nothing and
    /// says, as `unseal_runtime_key` does, to rotate the key it may hold: it
    /// reads aws.env with its own hashed decrypt since F2, whose generic
    /// advice left that out. Neither the key nor the token is in what it says.
    #[test]
    fn a_rebuild_that_finds_the_runtime_key_in_the_clear_says_to_rotate_it() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.credentials()).unwrap();
        let (id, secret) = (format!("AKIA{}", "RQ7Z".repeat(4)), format!("{}rq7z", "Rq7+".repeat(9)));
        std::fs::write(paths.aws_env(), format!("AWS_ACCESS_KEY_ID={id}\nAWS_SECRET_ACCESS_KEY={secret}\n")).unwrap();
        let t = shaped("Rq");
        let token = parse_token(&t).unwrap();
        let store = Keystore::resolve(Some(d.path().join("keys"))).unwrap();
        let CombinedOutcome::Failed { why, removed: false } = rebuild_with_token(&store, &paths, "rq7", &token, &"0".repeat(64), false, false) else {
            panic!("the rebuild was not refused");
        };
        assert!(![&id, &secret, &t].iter().any(|s| why.contains(s.as_str())), "the line holds a credential ({} bytes)", why.len());
        let says = format!("{} is not an ai-env container (plaintext?): move it away (and rotate the key it holds), then seal the runtime key with `make runtime-key`", paths.aws_env().display());
        assert_eq!(why, says);
        assert!(!paths.combined_env().exists(), "nothing built");
    }
}
