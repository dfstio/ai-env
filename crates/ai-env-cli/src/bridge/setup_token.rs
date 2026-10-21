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
//!
//! S8 operators: `creds status` also shows the ops key (`credentials/ops.env`,
//! with what its notes recorded at sealing, read without a Touch ID) and the
//! deployer `state/infra.toml` records (its key lives in Strongbox only);
//! `creds forget --ops` removes `ops.env` and its backups, and nothing else,
//! and says how to delete the key in IAM, which ai-env cannot do.
//!
//! A1 (several Claude accounts, `bridge::accounts`): a token is sealed into
//! its account's `credentials/accounts/<name>.env` ([`seal_account`]: `creds
//! setup-token` the active account's, `creds account add` any), and the
//! active account is installed by byte copy as `setup-token.env`. Each
//! account has its own combined container, `accounts/<name>.combined.env`,
//! judged against its own file ([`combined_state_of`], C2) and installed as
//! `combined.env` beside its token only while that token is the installed
//! one ([`install_built`]). `creds aws-set` rebuilds every account's, one
//! Touch ID each ([`after_aws_set`]). `creds status` and doctor name the
//! accounts, and `creds forget` forgets them too.
use crate::age_cmd::AgeTool;
use crate::bridge::accounts::{self, AccountFile, AccountsState};
use crate::bridge::audit;
use crate::bridge::config::{BridgeConfig, CredentialsSource, Paths};
use crate::bridge::creds::{aws_env_state, check_target_file, key_name, preflight_for, seal_file, AwsEnvState};
use crate::bridge::errors::BridgeError;
use crate::bridge::identity::{KeyNotes, OPS_USER};
use crate::commands::Tag;
use crate::container;
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::{validate_key_name, Keystore};
use crate::wire::redact::{forget_secret, register_secret, scrub, Secret};
use crate::wire::time::{parse_rfc3339_utc, rfc3339_utc, unix_now};
use std::collections::BTreeMap;
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
pub(crate) fn file_sha256(path: &Path) -> Option<String> {
    let text = crate::bridge::registry::read_regular_file(path).ok()??;
    Some(text_sha256(&text))
}

/// `hex(sha256(text))`: what `combined.env` records of a source text.
pub(crate) fn text_sha256(text: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}

/// A1: the seal id of the installed `setup-token.env` when it holds a
/// container (none for nothing installed, a link or a plaintext file): the
/// Claude account installed, by `accounts::tag_index`.
pub(crate) fn installed_seal(paths: &Paths) -> Option<String> {
    let token = paths.setup_token_env();
    if aws_env_state(&token) == AwsEnvState::Sealed {
        crate::bridge::agent::credential::seal_tag(&token)
    } else {
        None
    }
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
/// decrypts nothing ([`combined_state_of`] of the installed pair).
#[must_use]
pub fn combined_state(paths: &Paths) -> CombinedState {
    combined_state_of(&paths.combined_env(), &paths.aws_env(), &paths.setup_token_env())
}

/// A1: Claude account `name`'s own combined container against its own
/// sources, `accounts/<name>.env` and aws.env, never the installed copy,
/// which may be another account's (C2).
#[must_use]
pub fn account_combined_state(paths: &Paths, name: &str) -> CombinedState {
    combined_state_of(&paths.account_combined_env(name), &paths.aws_env(), &paths.account_env(name))
}

/// Is the combined container at `combined` usable in place of the runtime
/// key at `aws` and the setup-token at `token`: do the two hashes its notes
/// record name those files' texts now? Reads three files and decrypts
/// nothing.
#[must_use]
pub fn combined_state_of(combined: &Path, aws: &Path, token: &Path) -> CombinedState {
    match aws_env_state(combined) {
        AwsEnvState::Absent => return CombinedState::Absent,
        AwsEnvState::NotSealed(why) => return CombinedState::NotSealed(why),
        AwsEnvState::Sealed => {}
    }
    let Some(text) = crate::bridge::registry::read_regular_file(combined).ok().flatten() else {
        return CombinedState::NotSealed("cannot be read".into());
    };
    combined_judged(&text, file_sha256(aws).as_deref(), file_sha256(token).as_deref(), &source_name(token))
}

/// [`combined_state_of`]'s verdict on a combined container's text already
/// read, against the hashes of its sources' texts (`None`: that source is
/// gone); `token_name` names the token's file in a stale verdict. An install
/// judges an account's combined copy so against the very bytes it installs
/// (`accounts::install`), never a second read of the account's file.
#[must_use]
pub(crate) fn combined_judged(text: &str, aws_sha: Option<&str>, token_sha: Option<&str>, token_name: &str) -> CombinedState {
    let meta = container::meta(text);
    for (key, now, name) in [("aws_file_sha256", aws_sha, "aws.env"), ("token_file_sha256", token_sha, token_name)] {
        let Some(recorded) = meta.get(key) else {
            return CombinedState::Stale(format!("it records no hash of {name}"));
        };
        match now {
            Some(now) if recorded == now => {}
            Some(_) => return CombinedState::Stale(format!("{name} changed since it was built")),
            None => return CombinedState::Stale(format!("{name} is gone")),
        }
    }
    CombinedState::Current
}

/// How a line names a token's file: `setup-token.env`, or (A1) an
/// account's as `accounts/<name>.env`.
fn source_name(path: &Path) -> String {
    let file = path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    match path.parent().and_then(Path::file_name) {
        Some(dir) if dir == "accounts" => format!("accounts/{file}"),
        _ => file,
    }
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
    pub(crate) fn of(text: &str) -> Recorded {
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
/// tag, no prompt), and its recorded metadata: a setup-token's
/// ([`Recorded`]) and a sealed AWS key's ([`KeyNotes`], S8 operators).
#[derive(Debug, Clone)]
pub struct FileFacts {
    pub path: PathBuf,
    pub state: AwsEnvState,
    pub opens_with: Option<std::result::Result<String, OpenFault>>,
    pub recorded: Recorded,
    pub key_notes: KeyNotes,
}

fn file_facts(store: &Keystore, path: PathBuf) -> FileFacts {
    let state = aws_env_state(&path);
    let (mut opens_with, mut recorded, mut key_notes) = (None, Recorded::default(), KeyNotes::default());
    if state == AwsEnvState::Sealed {
        if let Some(text) = crate::bridge::registry::read_regular_file(&path).ok().flatten() {
            recorded = Recorded::of(&text);
            key_notes = KeyNotes::of(&text);
            opens_with = Some(match container::read(&text).and_then(|c| crate::select::resolve_for_decrypt(store, None, &c)) {
                Ok(k) => Ok(k),
                Err(e @ CliError::NoKey(_)) => Err(OpenFault::NoKey(e.to_string())),
                Err(e) => Err(OpenFault::Unknown(e.to_string())),
            });
        }
    }
    FileFacts { path, state, opens_with, recorded, key_notes }
}

/// The backups a sealing command left beside `file` in `dir`
/// (`<file>.<unix>.bak`): `credentials/`, or (A1) `credentials/accounts/`.
pub(crate) fn backups_in(dir: &Path, file: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
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

/// A1: the backups of the Claude accounts' files in `credentials/accounts/`
/// (`<name>.env.<unix>.bak`, older seals; `<name>.combined.env.<unix>.bak`,
/// what a rebuild racing another kept), counted per file as
/// `accounts/<name>.env`, by name; an account forgotten by hand counts too.
/// None through a link in the directory's place ([`accounts_dir_real`]).
fn account_backups(paths: &Paths) -> Vec<(String, usize)> {
    if !accounts_dir_real(paths) {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(paths.accounts_dir()) else { return Vec::new() };
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((file, rest)) = name.split_once(".env.").map(|(stem, rest)| (format!("{stem}.env"), rest)) else { continue };
        let account = file.strip_suffix(".combined.env").or_else(|| file.strip_suffix(".env")).unwrap_or_default();
        if accounts::valid_name(account) && rest.strip_suffix(".bak").is_some_and(|ts| !ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit())) {
            *counts.entry(format!("accounts/{file}")).or_default() += 1;
        }
    }
    counts.into_iter().collect()
}

/// Is `credentials/accounts/` a real directory? A link in its place is never
/// listed through, as everywhere (`accounts::account_files` refuses it): what
/// it points at is no account's.
fn accounts_dir_real(paths: &Paths) -> bool {
    std::fs::symlink_metadata(paths.accounts_dir()).is_ok_and(|m| m.is_dir())
}

/// A VM the token was delivered to and that is not known to be terminated:
/// its memory, children and snapshots may hold the token.
#[derive(Debug, Clone)]
pub struct Holder {
    pub id: String,
    pub status: &'static str,
    pub credential_at: u64,
    /// A1: the seal it received, when its row records one: which Claude
    /// account it holds ([`received`]).
    pub tag: Option<String>,
}

/// Every seal a Claude account holds or held, to its name and whether it is
/// current (`accounts::tag_index`), or why the accounts cannot be read.
type SealIndex = std::result::Result<BTreeMap<String, (String, bool)>, String>;

/// What a holder received, for its line, by `index` (every seal a Claude
/// account holds or held, `accounts::tag_index`; `None` in a tree with no
/// account, `Err` while the accounts cannot be read): `the token` in a tree
/// with no account (or for a row that records no seal); else `Claude
/// account work's token (seal T)`, `a token no Claude account holds (seal
/// T)`, or, while the accounts cannot be read, `a token of an unknown Claude
/// account (seal T)`.
fn received(h: &Holder, index: Option<&SealIndex>) -> String {
    match (index, h.tag.as_deref()) {
        (Some(Ok(index)), Some(tag)) => match index.get(tag) {
            Some((name, _)) => format!("Claude account {name}'s token (seal {tag})"),
            None => format!("a token no Claude account holds (seal {tag})"),
        },
        (Some(Err(_)), Some(tag)) => format!("a token of an unknown Claude account (seal {tag})"),
        _ => "the token".to_string(),
    }
}

/// The account [`received`] names for `h`, for `--json`: none in a tree
/// with no account, [`accounts::UNKNOWN`] for a seal it cannot name.
fn holder_account(h: &Holder, index: Option<&SealIndex>) -> Option<String> {
    match (index, h.tag.as_deref()) {
        (Some(Ok(index)), Some(tag)) => Some(index.get(tag).map_or_else(|| accounts::UNKNOWN.to_string(), |(name, _)| name.clone())),
        (Some(Err(_)), Some(_)) => Some(accounts::UNKNOWN.to_string()),
        _ => None,
    }
}

/// The holders the readable rows name, and the rows that cannot be read
/// (`<path>: <error>`, the path once), each of whose VMs may hold the token unlisted; or
/// why the registry could not be listed at all. Never an empty list in place
/// of an error, since this is the list `creds forget` acts on: `creds status`
/// and `creds forget` print every unreadable row beside the holders, on
/// stdout and in `--json`, so the list never reads none while one exists.
pub(crate) fn holders(paths: &Paths) -> std::result::Result<(Vec<Holder>, Vec<String>), String> {
    use crate::bridge::vm::registry::{list_rows_reporting, RowStatus};
    let (rows, unread) = list_rows_reporting(paths).map_err(|e| e.to_string())?;
    let held: Vec<Holder> = rows
        .into_iter()
        .filter(|r| !r.id.is_empty() && r.status != RowStatus::Terminated && r.terminated_at.is_none())
        .filter_map(|r| Some(Holder { credential_at: r.credential_at?, status: r.status.as_str(), id: r.id, tag: r.credential_tag }))
        .collect();
    Ok((held, unread))
}

/// What `creds status` and `creds forget` say of a registry row that cannot
/// be read, before the row's `<path>: <error>`.
pub(crate) const UNREADABLE_ROW: &str = "a VM registry row cannot be read, so its VM may hold the token unlisted";

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
    remove_derived(&paths.combined_env())
}

/// Delete the derived container at `path` (or a link in its place): the
/// installed `combined.env` or (A1) an account's own; whether there was one.
fn remove_derived(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(_) => match std::fs::remove_file(path) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("warning: cannot remove the out-of-date {}: {e}", path.display());
                false
            }
        },
        Err(_) => false,
    }
}

/// A1: delete every account's own combined container
/// (`credentials/accounts/<name>.combined.env`, a link in its place too):
/// the names of those there were. A directory that cannot be listed removes
/// none (its accounts cannot be read either), nor does a link in its place,
/// which is never followed ([`accounts_dir_real`]).
fn remove_account_combineds(paths: &Paths) -> Vec<String> {
    if !accounts_dir_real(paths) {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(paths.accounts_dir()) else { return Vec::new() };
    let mut removed: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let file = e.file_name().to_string_lossy().into_owned();
            let name = file.strip_suffix(".combined.env").filter(|n| accounts::valid_name(n))?.to_string();
            remove_derived(&e.path()).then_some(name)
        })
        .collect();
    removed.sort();
    removed
}

/// What one combined container is built for (A1): the account's sealed
/// token it pairs and records (`credentials/accounts/<name>.env`), where it
/// goes (`credentials/accounts/<name>.combined.env`), and the account, which
/// its notes name. It is installed as `combined.env` only beside that very
/// token ([`install_built`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CombinedFor {
    pub(crate) token_src: PathBuf,
    pub(crate) out: PathBuf,
    pub(crate) account: String,
}

impl CombinedFor {
    /// Claude account `name`'s.
    pub(crate) fn account(paths: &Paths, name: &str) -> CombinedFor {
        CombinedFor { token_src: paths.account_env(name), out: paths.account_combined_env(name), account: name.to_string() }
    }

    /// Its state against its own sources ([`combined_state_of`]).
    fn state(&self, paths: &Paths) -> CombinedState {
        combined_state_of(&self.out, &paths.aws_env(), &self.token_src)
    }

    /// Is its account's token the installed one: does `setup-token.env` hold
    /// the bytes of its file now?
    fn installed(&self, paths: &Paths) -> bool {
        file_sha256(&paths.setup_token_env()).is_some_and(|now| file_sha256(&self.token_src).as_deref() == Some(now.as_str()))
    }
}

/// Seal both credentials into `target`'s container (an account's own
/// combined, A1), recording `aws_sha` and `token_sha`: the hashes of the two
/// source texts the runtime key and the token came from (the one the command
/// sealed, the one it unsealed), never of a read after the rebuild's Touch
/// ID, when another command may have sealed either anew (F2). It is built,
/// and kept, only while both files (aws.env and the account's own) still are
/// those texts: otherwise none is built from the replaced one, and the one
/// there is removed unless it matches its sources (another command built it
/// meanwhile). An existing one is removed first, never backed up.
#[allow(clippy::too_many_arguments)]
fn seal_combined(store: &Keystore, paths: &Paths, key_name: &str, key_id: &str, secret: &str, token: &SetupToken, aws_sha: &str, token_sha: &str, force: bool, target: &CombinedFor) -> Result<PathBuf> {
    let token_name = source_name(&target.token_src);
    // The sources sealed anew (or removed) since: none when both still are the texts this pairs.
    let changed = || {
        [(paths.aws_env(), aws_sha, "aws.env"), (target.token_src.clone(), token_sha, token_name.as_str())]
            .into_iter()
            .filter(|(p, sha, _)| file_sha256(p).as_deref() != Some(*sha))
            .map(|(_, _, name)| name.to_string())
            .collect::<Vec<_>>()
    };
    let superseded = |names: Vec<String>| {
        if target.state(paths) != CombinedState::Current {
            remove_derived(&target.out);
        }
        let were = if names.len() == 1 { "was" } else { "were" };
        CliError::Msg(format!("{} {were} sealed anew or removed while this command waited: none is built from what that replaced", names.join(" and ")))
    };
    let names = changed();
    if !names.is_empty() {
        return Err(superseded(names));
    }
    remove_derived(&target.out);
    let plaintext = render_combined(key_id, secret, token);
    let sealed_at = rfc3339_utc(unix_now());
    let notes = [("kind", "combined"), ("parts", "aws,setup-token"), ("aws_file_sha256", aws_sha), ("token_file_sha256", token_sha), ("sealed", sealed_at.as_str()), ("account", target.account.as_str())];
    let sealed = seal_file(store, paths, key_name, &target.out, plaintext.as_bytes(), &[secret.as_bytes(), token.expose().as_bytes()], &notes, force)?;
    // Sealed anew while this one was written: what it wrote pairs a replaced source, and goes.
    let names = changed();
    if !names.is_empty() {
        return Err(superseded(names));
    }
    Ok(sealed.path)
}

/// A1: install `target`'s container, just built from the token sealed as
/// the text whose hash is `token_sha`, as `combined.env`, under the store's
/// lock (where every install runs, C11): only while `setup-token.env` holds
/// that very text (its account is the installed one, sealed as it was) and
/// the container is current for it and aws.env now, so the pair a reader
/// takes is always of one account's token. A leftover `.combined.env.tmp`
/// is cleared first: only a holder of the lock writes `combined.env`.
/// `Ok(false)`: not installed (another account is, or it was sealed anew).
fn install_built(paths: &Paths, target: &CombinedFor, token_sha: &str) -> std::result::Result<bool, String> {
    let _held = accounts::lock(paths)?;
    if file_sha256(&paths.setup_token_env()).as_deref() != Some(token_sha) || aws_env_state(&target.out) != AwsEnvState::Sealed {
        return Ok(false);
    }
    let Some(text) = crate::bridge::registry::read_regular_file(&target.out).map_err(|e| e.to_string())? else { return Ok(false) };
    if combined_judged(&text, file_sha256(&paths.aws_env()).as_deref(), Some(token_sha), &source_name(&target.token_src)) != CombinedState::Current {
        return Ok(false);
    }
    crate::bridge::registry::remove_if_present(&paths.credentials().join(".combined.env.tmp")).map_err(|e| e.to_string())?;
    crate::store::write_atomic(&paths.combined_env(), text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Is `[aws].credentials` the sealed container (the only mode with a
/// `combined.env`)? `Err(why)` otherwise.
pub(crate) fn container_mode(paths: &Paths) -> std::result::Result<(), String> {
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

/// After [`seal_account`] sealed `token`, when [`rebuild_planned`]: rebuild
/// the account's combined container (`target`) from the runtime key (one
/// Touch ID), recording `token_sha` (the account file's text the command
/// sealed, `Sealed::sha256`) and the aws.env text that prompt decrypted
/// ([`seal_combined`]). The old one holds the replaced token, so the caller
/// removed it (and the installed `combined.env`, when the account is
/// installed) before anything that may end the command (`removed`: whether
/// there was one): a Ctrl-C or a closed terminal while Touch ID is asked for
/// (no handler runs then) leaves none.
#[allow(clippy::too_many_arguments)]
fn rebuild_with_token(store: &Keystore, paths: &Paths, key_name: &str, token: &SetupToken, token_sha: &str, force: bool, removed: bool, target: &CombinedFor) -> CombinedOutcome {
    let built = (|| -> Result<PathBuf> {
        // An aws.env in the clear since `rebuild_planned` found it sealed may hold the key: rotated too, as
        // `unseal_runtime_key` says.
        if let AwsEnvState::NotSealed(why) = aws_env_state(&paths.aws_env()) {
            return Err(CliError::AuthUnavailable(format!("{} {why}: move it away (and rotate the key it holds), then seal the runtime key with `make runtime-key`", paths.aws_env().display())));
        }
        let (plain, aws_sha) = decrypt_file_hashed(store, &paths.aws_env(), key_name, "seal the runtime key with `make runtime-key`")?;
        let (id, secret) = crate::bridge::vm::client::parse_runtime_env(&plain)?;
        drop(plain);
        seal_combined(store, paths, key_name, &id, &secret, token, &aws_sha, token_sha, force, target)
    })();
    match built {
        Ok(path) => CombinedOutcome::Built(path),
        Err(e) => CombinedOutcome::Failed { why: scrub(&e.to_string()).into_owned(), removed },
    }
}

/// [`install_built`] after a build, `false` for anything else; a failure is
/// a warning (the container stays the account's own, and an install copies
/// it later while it is current).
fn put_built(paths: &Paths, outcome: &CombinedOutcome, target: &CombinedFor, token_sha: &str) -> bool {
    if !matches!(outcome, CombinedOutcome::Built(_)) {
        return false;
    }
    install_built(paths, target, token_sha).unwrap_or_else(|e| {
        eprintln!("warning: {} was built but not installed as combined.env ({e}): a credentialed command asks for Touch ID twice until `ai-env creds account use {}` installs it", target.out.display(), target.account);
        false
    })
}

/// After `creds aws-set` sealed a new runtime key (`make runtime-key`):
/// every Claude account's combined container rebuilt from its sealed token,
/// one Touch ID each (A1). Every combined container pairs the replaced key,
/// so all go first, before any prompt: the installed `combined.env` and each
/// account's own. Then a legacy `setup-token.env` is adopted (C10; a store
/// that cannot be read builds nothing, said as a warning: the key stays
/// sealed), and the accounts are rebuilt one after the other, the active one
/// first, one token in memory at a time: its file's text read once, its hash
/// recorded (F2), the token unsealed from that text, the container sealed,
/// the token dropped, and the container installed as `combined.env` when the
/// account is the installed one ([`install_built`]). Each records `aws_sha`,
/// the hash of the aws.env text the command sealed (`Sealed::sha256`): a
/// second `creds aws-set` that sealed anew before this one got there leaves
/// no container pairing this command's key with that text, and an account
/// sealed anew or forgotten meanwhile gets none built from what it held. A
/// failed account (a dismissed dialog, its file gone) is reported in a
/// `creds_combined` row of its own, and the next one goes on. Prints and
/// audits what happened ([`report_combined`]), and nothing when there is no
/// account.
pub fn after_aws_set(store: &Keystore, paths: &Paths, key_name: &str, key_id: &str, secret: &str, aws_sha: &str, force: bool) {
    let removed_installed = remove_combined(paths);
    let removed = remove_account_combineds(paths);
    let removed_any = removed_installed || !removed.is_empty();
    if let Err(why) = container_mode(paths) {
        report_combined(paths, &CombinedOutcome::Skipped { why, removed: removed_any }, "aws-set", None, false);
        return;
    }
    let view = match accounts::reconcile(paths) {
        Ok(view) => view,
        Err(e) => {
            let why = format!("the Claude accounts cannot be read: {e}");
            report_combined(paths, &CombinedOutcome::Failed { why: scrub(&why).into_owned(), removed: removed_any }, "aws-set", None, false);
            return;
        }
    };
    if view.files.is_empty() {
        report_combined(paths, &CombinedOutcome::Skipped { why: String::new(), removed: removed_any }, "aws-set", None, false);
        return;
    }
    let active = view.state.active.as_deref();
    let mut order: Vec<&AccountFile> = view.files.iter().collect();
    order.sort_by_key(|f| (Some(f.name.as_str()) != active, f.name.clone()));
    for file in order {
        let target = CombinedFor::account(paths, &file.name);
        let was = removed.contains(&file.name) || (removed_installed && view.installed.as_deref() == Some(file.tag.as_str()));
        let token_sha = text_sha256(&file.text);
        let built = (|| -> Result<PathBuf> {
            validate_key_name(key_name).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
            let plain = decrypt_text(store, &file.text, key_name)?;
            let token = parse_token_env(&plain)?;
            drop(plain);
            seal_combined(store, paths, key_name, key_id, secret, &token, aws_sha, &token_sha, force, &target)
        })();
        let outcome = match built {
            Ok(path) => CombinedOutcome::Built(path),
            Err(e) => CombinedOutcome::Failed { why: scrub(&e.to_string()).into_owned(), removed: was },
        };
        let installed = put_built(paths, &outcome, &target, &token_sha);
        report_combined(paths, &outcome, "aws-set", Some(&target), installed);
    }
}

/// One line on what became of a combined container after the sealing
/// command `by` (`setup-token`, `account-add` or `aws-set`), and the audit
/// row `creds_combined` with its outcome (and its account, A1); nothing when
/// there was nothing to do. The sealing command's own row comes before the
/// rebuild's Touch ID, so this one records how it ended. A line names
/// `combined.env` for the installed account (`installed`: this build was
/// installed), and the account's own container for another one.
fn report_combined(paths: &Paths, outcome: &CombinedOutcome, by: &str, target: Option<&CombinedFor>, installed: bool) {
    if matches!(outcome, CombinedOutcome::Skipped { why, removed: false } if why.is_empty()) {
        return;
    }
    let removed = matches!(outcome, CombinedOutcome::Skipped { removed: true, .. } | CombinedOutcome::Failed { removed: true, .. });
    let mut pairs = vec![("by", by.to_string()), ("outcome", outcome.word().into()), ("removed", removed.to_string())];
    if let Some(t) = target {
        pairs.push(("account", t.account.clone()));
    }
    let row = audit::AuditRow::new("creds_combined", None, audit::detail(&pairs));
    if let Err(e) = audit::append(&paths.audit(), &row) {
        eprintln!("warning: the audit row creds_combined was not written: {e}");
    }
    // The installed account's container is shown as combined.env, as before accounts; another one's by its own name.
    let ours = target.is_none_or(|t| installed || t.installed(paths));
    let name = match target {
        Some(t) if !ours => format!("accounts/{}.combined.env", t.account),
        _ => "combined.env".to_string(),
    };
    match outcome {
        CombinedOutcome::Built(path) => {
            let _ = match target {
                Some(t) if !installed => crate::commands::outln(format_args!(
                    "rebuilt {}: Claude account {} is not the installed one (`ai-env creds account use {}` installs it with this)",
                    path.display(),
                    t.account,
                    t.account
                )),
                _ => crate::commands::outln(format_args!("rebuilt {}: a credentialed command asks for Touch ID once", paths.combined_env().display())),
            };
        }
        CombinedOutcome::Skipped { why, removed } => {
            if *removed {
                eprintln!("removed the out-of-date {name}{}", if why.is_empty() { String::new() } else { format!(" ({why})") });
            } else if !why.is_empty() {
                let _ = crate::commands::outln(format_args!("{name} not built: {why}"));
            }
        }
        CombinedOutcome::Failed { why, removed } => {
            let gone = if *removed { "; the out-of-date one was removed" } else { "" };
            // Current now only when another sealing command built it while this one waited (F2): that one is used.
            let current = target.map_or_else(|| combined_state(paths), |t| t.state(paths)) == CombinedState::Current;
            let then = match target {
                _ if current => format!("the {name} there now, which another command built, matches its sources"),
                Some(t) if !ours => format!("Claude account {} asks for Touch ID twice per credentialed command once it is installed, until `make runtime-key` rebuilds its combined.env", t.account),
                _ => "a credentialed command asks for Touch ID twice until `ai-env creds setup-token` or `make runtime-key` rebuilds it".to_string(),
            };
            eprintln!("warning: {name} not built ({why}){gone}: {then}");
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

/// `ai-env creds setup-token [--stdin|--from-env] [--no-combined] [--force]`
/// (A1): seal anew the active Claude account, `credentials/accounts/<active>.env`,
/// and install it again ([`seal_account`]), unless another account was made
/// active while the token was asked for ([`Install::IfStill`]). A legacy
/// `setup-token.env` is adopted as `default` first (C10; a store that cannot
/// be read is never written: exit 1); with no account and nothing sealed it
/// seals `default`; with accounts but none active it refuses (exit 9) before
/// the token is asked for: which account the token is of would be a guess.
pub fn cmd_setup_token(store: &Keystore, o: SetupTokenOpts) -> Result<()> {
    let paths = Paths::resolve()?;
    let key = key_name(&paths)?;
    let view = accounts::reconcile(&paths)?;
    let name = match (&view.state.active, view.files.is_empty()) {
        (Some(active), _) => active.clone(),
        (None, true) => accounts::DEFAULT.to_string(),
        (None, false) => return Err(CliError::Policy(no_active_account(&paths, &view.files))),
    };
    let absent = aws_env_state(&paths.setup_token_env()) == AwsEnvState::Absent;
    seal_account(store, &paths, &key, &name, o, Install::IfStill { absent }, "setup-token").map(|_| ())
}

/// `creds setup-token`'s refusal while accounts exist and none is active
/// (exit 9): why none is, the accounts, and the two ways on.
fn no_active_account(paths: &Paths, files: &[AccountFile]) -> String {
    let why = match aws_env_state(&paths.setup_token_env()) {
        AwsEnvState::Absent => "credentials/setup-token.env is absent".to_string(),
        AwsEnvState::Sealed => "credentials/setup-token.env holds a seal no Claude account holds".to_string(),
        AwsEnvState::NotSealed(why) => format!("credentials/setup-token.env {why}"),
    };
    let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
    format!(
        "no Claude account is active ({why}; Claude accounts: {}): `ai-env creds account use NAME` makes one active, then `ai-env creds setup-token` seals it anew; or `ai-env creds account add NAME` seals another",
        names.join(", ")
    )
}

/// Whether [`seal_account`] installs the account it seals as
/// `setup-token.env`. Decided when the command starts, before the token is
/// asked for (minutes, at a paste), and judged again under the store's lock
/// once it is sealed (design §5): a `creds account use` made meanwhile in
/// another terminal is never undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Install {
    /// No: the store's row follows the file (`creds account add` of an
    /// account that is not the active one).
    No,
    /// Whatever is installed by then (`creds account add --use`: asked for).
    Always,
    /// Only while it still holds ([`still_installs`]): `setup-token.env`
    /// holds one of the account's seals (it is the active one: `creds
    /// setup-token`, `creds account add` of the active one), or, when it was
    /// absent at the start (`absent`: a first account, or none active), it is
    /// absent still.
    IfStill { absent: bool },
}

/// A1: seal a Claude account's setup-token (asked for hidden, `--stdin` or
/// `--from-env`) into `credentials/accounts/<name>.env`, its notes naming the
/// account (C1), a replaced seal kept as `<name>.env.<unix>.bak`; installed
/// as `setup-token.env` as `install` says ([`Install`], under the store's
/// lock: [`install_sealed`]), else the store's row follows the file
/// (`accounts::reconcile`: what was seen of an account sealed anew goes,
/// C9). Everything that can refuse without the token does before it is
/// asked for: the preflight of the account's file, and of
/// `setup-token.env`'s place when it may be installed (a link or a plaintext
/// file there is never replaced).
///
/// The token is sealed from then on. The account's combined container holds
/// the replaced token, so it goes first, and the installed `combined.env`
/// with an install. What records the seal (the audit row
/// `creds_setup_token` with `account` and `installed`, the probe row, the
/// lines) and the reminder to clear where the token came through come before
/// the rebuild's Touch ID, which a Ctrl-C or a closed terminal may end with
/// no handler run (M47). An install that failed (`setup-token.env` as it
/// was) then ends the command with its error, before any Touch ID; else the
/// account's container is rebuilt (one Touch ID, the runtime key) and, while
/// the account is the installed one, installed as `combined.env`
/// ([`install_built`]). `by` is the `creds_combined` row's: `setup-token` or
/// `account-add`. Returns the install, when one was made.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_account(store: &Keystore, paths: &Paths, key: &str, name: &str, o: SetupTokenOpts, install: Install, by: &str) -> Result<Option<accounts::Installed>> {
    accounts::check_name(name)?;
    let target = paths.account_env(name);
    // Everything that can refuse without the token, before it is asked for.
    let (rows, _) = preflight_for(store, paths, key, &target, o.force);
    if let Some(e) = rows.into_iter().find_map(std::result::Result::err) {
        return Err(e);
    }
    if install != Install::No {
        check_target_file(paths, &paths.setup_token_env())?;
    }
    let (raw, source) = read_token_input(o)?;
    let token = parse_token(&raw).map_err(TokenFault::into_cli)?;
    drop(raw);
    let prefix = token.prefix().unwrap_or("unrecognised").to_string();
    let chars = token.len().to_string();
    let sealed_at = rfc3339_utc(unix_now());
    let sealed = {
        let plaintext = render_token_env(&token);
        let notes = [("kind", "setup-token"), ("prefix", prefix.as_str()), ("chars", chars.as_str()), ("sealed", sealed_at.as_str()), ("account", name)];
        seal_file(store, paths, key, &target, plaintext.as_bytes(), &[token.expose().as_bytes()], &notes, o.force)?
    };
    // The hash of the text just sealed (`Sealed::sha256`): what the rebuild records of the token's source (F2),
    // never a read of the file, which another command may have sealed anew since.
    let token_sha = sealed.sha256.as_str();
    // The token is sealed from here on. The account's own combined container holds the replaced token: it goes
    // first, and the installed combined.env with an install (which writes none: the account has none now).
    let own = CombinedFor::account(paths, name);
    let mut removed = remove_derived(&own.out);
    let had = std::fs::symlink_metadata(paths.combined_env()).is_ok();
    let installed = install_sealed(paths, name, install);
    let active = if installed.is_some() {
        removed |= had && std::fs::symlink_metadata(paths.combined_env()).is_err();
        None
    } else {
        // Not installed (not asked, or another account was installed meanwhile): the store's row follows the file.
        accounts::reconcile(paths).map(|v| v.state.active).unwrap_or_else(|e| {
            crate::bridge::voice::warn(&format!("Claude account {name} is sealed, but the store is not updated ({e})"));
            None
        })
    };
    let rebuild = if o.no_combined { Err("--no-combined (a credentialed command asks for Touch ID twice)".to_string()) } else { rebuild_planned(paths) };
    // A failed audit write is a warning.
    let installed_word = match &installed {
        None => "false",
        Some(Ok(_)) => "true",
        Some(Err(_)) => "failed",
    };
    let row = audit::AuditRow::new(
        "creds_setup_token",
        None,
        audit::detail(&[
            ("key", key.to_string()),
            ("prefix", prefix.clone()),
            ("chars", chars.clone()),
            ("source", source.word().into()),
            ("rotated", sealed.backup.is_some().to_string()),
            ("combined", if rebuild.is_ok() { "rebuild" } else { "skipped" }.into()),
            ("account", name.to_string()),
            ("installed", installed_word.into()),
        ]),
    );
    if let Err(e) = audit::append(&paths.audit(), &row) {
        eprintln!("warning: the token is sealed but the audit row was not written: {e}");
    }
    let shown = if prefix == "unrecognised" { "of an unrecognised shape".to_string() } else { format!("{prefix}…") };
    outln!("sealed setup-token {shown} ({chars} chars) into {} (key {key}) as Claude account {name}", sealed.path.display());
    if let Some(bak) = &sealed.backup {
        outln!("previous container kept as {}", bak.display());
    }
    match &installed {
        Some(Ok(done)) => {
            for w in &done.warnings {
                crate::bridge::voice::warn(w);
            }
            if let Some(bak) = &done.backup {
                outln!("the replaced setup-token.env, a seal no Claude account holds, kept as {}", bak.display());
            }
            let now = match done.from.as_deref() {
                Some(from) if from == name => "stays the active one".to_string(),
                Some(from) => format!("is the active one now, in place of {from}"),
                None => "is the active one".to_string(),
            };
            outln!("installed as {}: Claude account {name} {now}", paths.setup_token_env().display());
        }
        Some(Err(_)) => {}
        None => outln!("Claude account {name} is not the active one ({} is): `ai-env creds account use {name}` makes it active", active.as_deref().unwrap_or("none")),
    }
    // The setup-token-prefix probe (S7): the kind marker as observed, never validated.
    if let Some(spec) = crate::bridge::probes::spec("setup-token-prefix") {
        let row = crate::bridge::probes::stamped(paths, spec, &prefix, Some(format!("chars={chars}, sealed {sealed_at}")));
        if let Err(e) = crate::bridge::probes::record(paths, &row) {
            eprintln!("warning: the token is sealed but the setup-token-prefix probe row was not written: {e}");
        }
    }
    match source {
        Source::Paste => eprintln!("now clear the terminal's scrollback and the clipboard (pbcopy </dev/null)"),
        Source::Env => eprintln!("now unset {TOKEN_VAR} in the shell that held it"),
        // `pbpaste | …` leaves it in the clipboard, `echo … |` in the shell's history.
        Source::Stdin => eprintln!("now clear the clipboard if the token came from it (pbcopy </dev/null), and any file or shell history line that holds it"),
    }
    let installed = installed.transpose()?;
    let combined = match rebuild {
        Ok(()) => rebuild_with_token(store, paths, key, &token, token_sha, o.force, removed, &own),
        Err(why) => CombinedOutcome::Skipped { why, removed },
    };
    drop(token);
    let put = put_built(paths, &combined, &own, token_sha);
    report_combined(paths, &combined, by, Some(&own), put);
    Ok(installed)
}

/// [`seal_account`]'s install of `name` as `setup-token.env`, the store's
/// lock held from the judgement to the copy (`accounts::install_held`):
/// `None` when `install` does not call for one there ([`Install::No`], or
/// [`still_installs`] says another account was installed meanwhile), else
/// what the install did.
fn install_sealed(paths: &Paths, name: &str, install: Install) -> Option<Result<accounts::Installed>> {
    if install == Install::No {
        return None;
    }
    let held = match accounts::lock(paths) {
        Ok(held) => held,
        Err(e) => return Some(Err(CliError::Msg(e))),
    };
    if let Install::IfStill { absent } = install {
        match still_installs(paths, name, absent) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => return Some(Err(e)),
        }
    }
    Some(accounts::install_held(paths, &held, name))
}

/// [`Install::IfStill`]'s judgement, the store's lock held: does
/// `setup-token.env` hold one of `name`'s seals now (`accounts::tag_index`:
/// its file's, its row's, its backups'; an account just sealed anew has its
/// replaced seal in its backup), or is it absent, as it was at the start
/// (`absent`)? Something other than a container there goes to the install,
/// which refuses it saying why; accounts that cannot be read are an error.
fn still_installs(paths: &Paths, name: &str, absent: bool) -> Result<bool> {
    match aws_env_state(&paths.setup_token_env()) {
        AwsEnvState::Absent => Ok(absent),
        AwsEnvState::NotSealed(_) => Ok(true),
        AwsEnvState::Sealed => {
            let Some(tag) = installed_seal(paths) else { return Ok(absent) };
            let index = accounts::tag_index(paths).map_err(CliError::Msg)?;
            Ok(index.get(&tag).is_some_and(|(holder, _)| holder == name))
        }
    }
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

/// The ops key's row (S8 operators): its state as `aws.env`'s (the same key
/// faults), and for a sealed one what its notes recorded at sealing, read
/// without a Touch ID and not authenticated: `ai-env-ops ...WXYZ, sealed
/// 2026-10-14` (the UTC day).
fn ops_text(f: &FileFacts) -> (Tag, String) {
    if f.state == AwsEnvState::Absent {
        return (Tag::Skip, format!("ops.env: absent (the {OPS_USER} key: ai-env as deployer -- make ops-key)"));
    }
    let (tag, mut text) = state_text(f);
    if f.state == AwsEnvState::Sealed {
        text.push_str(&format!("; recorded at sealing, not authenticated: {}", recorded_key(&f.key_notes)));
    }
    (tag, text)
}

/// `ai-env-ops ...WXYZ, sealed 2026-10-14`, or as much of it as the notes
/// hold (an older or hand-made container may hold none).
fn recorded_key(notes: &KeyNotes) -> String {
    let who = match (notes.user.as_deref(), notes.key_id_last4.as_deref()) {
        (Some(user), Some(tail)) => format!("{} ...{tail}", scrub(user)),
        (Some(user), None) => format!("{} (its last four not recorded)", scrub(user)),
        (None, Some(tail)) => format!("a key ...{tail} (its user not recorded)"),
        (None, None) => "nothing (no notes)".to_string(),
    };
    match notes.sealed_day() {
        Some(day) => format!("{who}, sealed {day}"),
        None if notes.user.is_some() || notes.key_id_last4.is_some() => format!("{who}, its sealing day not recorded"),
        None => who,
    }
}

/// The resource part of an ARN, after its fifth colon (`user/ai-env-deployer`):
/// a row shows no account.
fn arn_resource(arn: &str) -> &str {
    arn.splitn(6, ':').nth(5).unwrap_or(arn)
}

/// The deployer `state/infra.toml` records (S8 operators), from that file
/// only: its key lives in Strongbox, never under `credentials/`.
fn deployer_text(state: &std::result::Result<Option<crate::bridge::infra::InfraState>, BridgeError>) -> (Tag, String) {
    match state {
        Err(e) => (Tag::Warn, format!("deployer: state/infra.toml unreadable ({e})")),
        Ok(state) => match recorded_deployer(state.as_ref()) {
            Some(arn) => (Tag::Ok, format!("deployer {} (state/infra.toml): its key lives in Strongbox only (ai-env as deployer -- … asks for it)", arn_resource(arn))),
            None => (Tag::Skip, "deployer: none recorded in state/infra.toml (the bootstrap deploy, then make infra-status WRITE=1)".into()),
        },
    }
}

/// `deployer_user_arn` of the state, when it records one.
fn recorded_deployer(state: Option<&crate::bridge::infra::InfraState>) -> Option<&str> {
    state.and_then(|s| s.deployer_user_arn.as_deref()).map(str::trim).filter(|a| !a.is_empty())
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

// ---- the Claude accounts, as status, doctor and `creds account list` show them ---------------

/// What `creds status`, doctor and `creds account list` show of the Claude
/// accounts (A1), read without writing anything (no adoption, no repair):
/// the store, or why it cannot be read; the sealed account files, or why
/// `credentials/accounts/` cannot be read; the `<name>.env` files there
/// that are no container (no account, but maybe a token in the clear:
/// `accounts::unsealed_files`); and the seal of the installed
/// `setup-token.env`, when it holds a container.
pub(crate) struct AccountsSeen {
    pub(crate) store: std::result::Result<Option<AccountsState>, String>,
    pub(crate) files: std::result::Result<Vec<AccountFile>, String>,
    pub(crate) unsealed: Vec<(String, String)>,
    pub(crate) installed: Option<String>,
}

impl AccountsSeen {
    pub(crate) fn read(paths: &Paths) -> AccountsSeen {
        AccountsSeen { store: accounts::read(paths), files: accounts::account_files(paths), unsealed: accounts::unsealed_files(paths).unwrap_or_default(), installed: installed_seal(paths) }
    }

    /// Does any Claude account exist: a row in the store, or a sealed file?
    /// One that cannot be read counts (L-2: what it holds is unknown).
    pub(crate) fn any(&self) -> bool {
        let rows = self.store.as_ref().map_or(true, |s| s.as_ref().is_some_and(|s| !s.account.is_empty()));
        rows || self.files.as_ref().map_or(true, |f| !f.is_empty())
    }

    /// The account files read (none while `credentials/accounts/` cannot be).
    pub(crate) fn files(&self) -> &[AccountFile] {
        self.files.as_deref().unwrap_or_default()
    }

    /// The account whose file holds the installed seal: the store's
    /// `active` one among several, else the first by name.
    pub(crate) fn active(&self) -> Option<&AccountFile> {
        let tag = self.installed.as_deref()?;
        let was = self.store.as_ref().ok().and_then(Option::as_ref).and_then(|s| s.active.as_deref());
        let holders = || self.files().iter().filter(move |f| f.tag == tag);
        holders().find(|f| Some(f.name.as_str()) == was).or_else(|| holders().next())
    }

    /// What is wrong with the accounts as a whole, one line each (doctor's
    /// and `creds status`'s `[!! ]` rows, `creds account list`'s): a store
    /// that cannot be read (L-2: labels read `unknown`, nothing is blocked),
    /// a `credentials/accounts/` that cannot be, a `<name>.env` there that is
    /// no container (a plaintext file may hold a token in the clear: `[!! ]`,
    /// never `[NO ]`, which `make acceptance` refuses, C13), a seal installed
    /// that no account holds, and no account active (`setup-token.env`
    /// absent while accounts exist: new chats and moves refuse).
    pub(crate) fn problems(&self, paths: &Paths) -> Vec<String> {
        let mut out = Vec::new();
        if let Err(e) = &self.store {
            out.push(accounts::unreadable(e));
        }
        if let Err(e) = &self.files {
            out.push(format!("{e}: Claude account names are unknown"));
        }
        for (name, why) in &self.unsealed {
            out.push(format!("{} {why}: it is no Claude account; move it away (and revoke what it holds)", paths.account_env(name).display()));
        }
        if !self.any() || self.files.is_err() {
            return out;
        }
        match &self.installed {
            Some(tag) if self.active().is_none() => out.push(format!(
                "setup-token.env holds a seal no Claude account holds (seal {tag}): `ai-env creds account use NAME` installs an account in its place (that seal is kept as a backup)"
            )),
            None if aws_env_state(&paths.setup_token_env()) == AwsEnvState::Absent => out.push(accounts::NO_ACTIVE.to_string()),
            _ => {}
        }
        out
    }

    /// The store's raw usage entry of `name`, when the store can be read.
    pub(crate) fn usage(&self, name: &str) -> Option<&toml::Value> {
        self.store.as_ref().ok().and_then(Option::as_ref).and_then(|s| s.usage.get(name))
    }

    /// The note the store keeps for account `name` (L-8), if any.
    pub(crate) fn note(&self, name: &str) -> Option<&str> {
        self.store.as_ref().ok().and_then(Option::as_ref).and_then(|s| s.account.iter().find(|r| r.name == name)).and_then(|r| r.note.as_deref())
    }
}

/// One Claude account as `creds status` and `creds account list` show it,
/// with no Touch ID: its seal, what its notes recorded at sealing (not
/// authenticated), a refusal recorded against its seal (M53: one that
/// cannot be read is shown as such), and its own combined container.
pub(crate) struct AccountShown {
    pub(crate) name: String,
    pub(crate) tag: String,
    pub(crate) active: bool,
    pub(crate) recorded: Recorded,
    pub(crate) refused: std::result::Result<Option<crate::bridge::agent::credential::Rejection>, String>,
    pub(crate) combined: CombinedState,
    /// The user's note (L-8): shown after the title, never anywhere else.
    pub(crate) note: Option<String>,
}

impl AccountShown {
    /// `file` as shown. Its name is its file's, whatever its notes' `account=`
    /// says (the name it was sealed under, which a rename keeps): nothing
    /// compares the two, nor warns (L-8).
    pub(crate) fn of(paths: &Paths, file: &AccountFile, active: bool) -> AccountShown {
        AccountShown {
            name: file.name.clone(),
            tag: file.tag.clone(),
            active,
            recorded: Recorded::of(&file.text),
            refused: crate::bridge::agent::credential::read_rejection(paths, &file.tag),
            combined: account_combined_state(paths, &file.name),
            note: None,
        }
    }

    /// `work (active)`, then its note in brackets: `work (active) [mk's Max seat]`.
    pub(crate) fn title(&self) -> String {
        let note = self.note.as_deref().map(|n| format!(" [{n}]")).unwrap_or_default();
        format!("{}{}{note}", self.name, if self.active { " (active)" } else { "" })
    }

    /// Its row after its title: `seal T, sk-ant-oat01-… (108 chars), sealed
    /// 2026-10-21 (about 365 days left); combined.env current`, then a
    /// refusal. Also whether it warns (near the end of its year, refusals
    /// unknown, its combined container unusable while the runtime key is
    /// sealed in container mode) and whether Anthropic refused it (a row of
    /// its own: `[!! ]` in `creds status`, which `make acceptance` reads,
    /// never `[NO ]`, C13).
    pub(crate) fn text(&self, mode: &std::result::Result<(), String>, runtime_key: bool, now: u64) -> (String, bool, bool) {
        let r = &self.recorded;
        let mut text = format!("seal {}, {}", self.tag, r.describe());
        let left = r.days_left(now);
        if let (Some(at), Some(left)) = (r.sealed_at, left) {
            text.push_str(&format!(", sealed {} (about {left} days left)", &rfc3339_utc(at)[..10]));
        }
        let combined = match (mode, &self.combined) {
            (Err(why), _) => format!("combined.env not used ({why})"),
            (Ok(()), CombinedState::Stale(why)) => format!("combined.env out of date, {why}"),
            (Ok(()), CombinedState::NotSealed(why)) => format!("combined.env {why}"),
            (Ok(()), state) => format!("combined.env {}", state.word()),
        };
        text.push_str(&format!("; {combined}"));
        let mut warn = left.is_some_and(|l| l < WARN_DAYS_LEFT) || (mode.is_ok() && runtime_key && self.combined != CombinedState::Current);
        let refused = match &self.refused {
            Ok(Some(r)) => {
                text.push_str(&format!(
                    "; refused by Anthropic on {} ({}): seal a fresh token for it (`claude setup-token` logged in as that account, then `ai-env creds account add {}`)",
                    r.at, r.vm, self.name
                ));
                true
            }
            Ok(None) => false,
            Err(e) => {
                warn = true;
                text.push_str(&format!("; refusals unknown ({e})"));
                false
            }
        };
        (text, warn || refused, refused)
    }

    /// Its `--json` object; `usage`: the usage summary `creds account list`
    /// shows (slice B's `accounts::usage_summary`).
    pub(crate) fn json(&self, usage: Option<String>, now: u64) -> serde_json::Value {
        let r = &self.recorded;
        serde_json::json!({
            "name": self.name,
            "tag": self.tag,
            "active": self.active,
            "recorded": { "prefix": r.prefix, "chars": r.chars, "sealed_at": r.sealed_at.map(rfc3339_utc), "days_left": r.days_left(now) },
            "refused": self.refused.as_ref().ok().and_then(Option::as_ref).map(|r| serde_json::json!({"at": r.at, "vm": r.vm})),
            "refused_error": self.refused.as_ref().err(),
            "combined": self.combined.word(),
            "usage": usage,
            "note": self.note,
        })
    }
}

/// Every account [`AccountShown`], by name, the active one marked, with its note.
pub(crate) fn accounts_shown(paths: &Paths, seen: &AccountsSeen) -> Vec<AccountShown> {
    let active = seen.active().map(|f| f.name.clone());
    seen.files()
        .iter()
        .map(|f| AccountShown { note: seen.note(&f.name).map(str::to_string), ..AccountShown::of(paths, f, active.as_deref() == Some(f.name.as_str())) })
        .collect()
}

/// The accounts as one JSON document (`creds account list --json`, and
/// `creds status --json`'s `accounts`): `active`, `store` (`ok`, `absent`,
/// or `{"error": …}`), `installed` (the installed seal and the account it
/// is, none for a foreign one), `accounts` ([`AccountShown::json`], with the
/// usage summary at `now`), `problems` ([`AccountsSeen::problems`]).
pub(crate) fn accounts_json(paths: &Paths, seen: &AccountsSeen, shown: &[AccountShown], now: u64) -> serde_json::Value {
    let store = match &seen.store {
        Ok(Some(_)) => serde_json::json!("ok"),
        Ok(None) => serde_json::json!("absent"),
        Err(e) => serde_json::json!({ "error": e }),
    };
    let active = seen.active().map(|f| f.name.clone());
    serde_json::json!({
        "active": active,
        "store": store,
        "installed": seen.installed.as_ref().map(|tag| serde_json::json!({ "tag": tag, "account": active })),
        "accounts": shown.iter().map(|a| a.json(seen.usage(&a.name).and_then(|v| accounts::usage_summary(v, now)), now)).collect::<Vec<_>>(),
        "problems": seen.problems(paths),
    })
}

/// `ai-env creds status [--json] [--unseal]`: no Touch ID unless `--unseal`.
/// A1: it reads the Claude accounts, never writing (no adoption): the
/// installed copy's account after `setup-token.env`'s row (whose prefix
/// `make acceptance` greps), what is wrong with them as a whole, a row per
/// account (`[!! ]` at worst, C13), their backups, and which account each
/// holder received; `--json` adds `accounts` and the holders' `tag` and
/// `account`.
pub fn cmd_status(store: &Keystore, json: bool, unseal: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let cfg = BridgeConfig::load(&paths)?.unwrap_or_default();
    let now = unix_now();
    let aws = file_facts(store, paths.aws_env());
    let ops = file_facts(store, paths.ops_env());
    let infra = crate::bridge::infra::read_infra_state(&paths);
    let token = file_facts(store, paths.setup_token_env());
    // As `vm exec` reads it (M53): a store that cannot be read is shown as such, never as no refusal.
    let rejected = crate::bridge::agent::credential::seal_tag(&token.path).map_or(Ok(None), |tag| crate::bridge::agent::credential::read_rejection(&paths, &tag));
    let mode = container_mode(&paths);
    let combined = combined_state(&paths);
    let seen = AccountsSeen::read(&paths);
    let shown = accounts_shown(&paths, &seen);
    let index = seen.any().then(|| accounts::tag_index(&paths));
    let backups: Vec<(String, usize)> = ["aws.env", "ops.env", "setup-token.env", "combined.env"].iter().map(|f| ((*f).to_string(), backups_in(&paths.credentials(), f).len())).chain(account_backups(&paths)).collect();
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
        let state = |s: &AwsEnvState| match s {
            AwsEnvState::Absent => "absent".to_string(),
            AwsEnvState::Sealed => "sealed".to_string(),
            AwsEnvState::NotSealed(w) => format!("not-sealed: {w}"),
        };
        let file = |f: &FileFacts| {
            serde_json::json!({
                "path": f.path.display().to_string(),
                "state": state(&f.state),
                "opens_with": f.opens_with.as_ref().and_then(|r| r.as_ref().ok()),
                "recorded": { "prefix": f.recorded.prefix, "chars": f.recorded.chars, "sealed_at": f.recorded.sealed_at.map(rfc3339_utc), "days_left": f.recorded.days_left(now) },
            })
        };
        let n = &ops.key_notes;
        let holder = |h: &Holder| serde_json::json!({"id": h.id, "status": h.status, "credential_at": rfc3339_utc(h.credential_at), "tag": h.tag, "account": holder_account(h, index.as_ref())});
        let doc = serde_json::json!({
            "creds": { "key": cfg.creds.key, "mode": cfg.creds.mode, "deliver": cfg.creds.deliver, "unseal_timeout_s": cfg.creds.unseal_timeout_s, "valid": creds_ok.as_ref().err() },
            "aws_credentials": cfg.aws.credentials,
            "aws_env": file(&aws),
            "ops_env": {
                "path": ops.path.display().to_string(),
                "state": state(&ops.state),
                "opens_with": ops.opens_with.as_ref().and_then(|r| r.as_ref().ok()),
                "recorded": { "user": n.user, "key_id_last4": n.key_id_last4, "sealed_at": n.sealed_at.map(rfc3339_utc) },
            },
            "deployer_user_arn": infra.as_ref().ok().and_then(|s| recorded_deployer(s.as_ref())),
            "setup_token_env": file(&token),
            "rejected": rejected.as_ref().ok().and_then(Option::as_ref).map(|r| serde_json::json!({"at": r.at, "vm": r.vm})),
            "rejected_error": rejected.as_ref().err(),
            "combined_env": { "state": combined.word(), "used": mode.is_ok() },
            "accounts": accounts_json(&paths, &seen, &shown, now),
            "backups": backups.iter().map(|(f, n)| (f.clone(), serde_json::json!(n))).collect::<serde_json::Map<_, _>>(),
            "credential_gate": { "tag": gate_tag.json_name(), "text": gate_text },
            "holders": held.as_ref().ok().map(|(held, _)| held.iter().map(holder).collect::<Vec<_>>()),
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
    let (tag, text) = ops_text(&ops);
    row(tag, text)?;
    let (tag, text) = deployer_text(&infra);
    row(tag, text)?;
    let (tag, mut text) = state_text(&token);
    if token.state == AwsEnvState::Sealed {
        let r = &token.recorded;
        text.push_str(&format!("; recorded at sealing, not authenticated: {}", r.describe()));
        if let (Some(at), Some(left)) = (r.sealed_at, r.days_left(now)) {
            text.push_str(&format!(", sealed {} (about {left} days left of its one-year life)", &rfc3339_utc(at)[..10]));
        }
        if let Some(active) = seen.active() {
            text.push_str(&format!("; the installed copy of Claude account {}", active.name));
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
    for problem in seen.problems(&paths) {
        row(Tag::Warn, problem)?;
    }
    for a in &shown {
        let (text, warn, _) = a.text(&mode, aws.state == AwsEnvState::Sealed, now);
        row(if warn { Tag::Warn } else { Tag::Ok }, format!("Claude account {}: {text}", a.title()))?;
    }
    let listed: Vec<String> = backups.iter().filter(|(_, n)| *n > 0).map(|(f, n)| format!("{f} x{n}")).collect();
    row(Tag::Skip, if listed.is_empty() { "backups: none".into() } else { format!("backups: {}", listed.join(", ")) })?;
    row(gate_tag, gate_text)?;
    match &held {
        Err(e) => row(Tag::Warn, format!("VMs that may hold the token: unknown, the VM registry cannot be read ({e})"))?,
        Ok((held, unread)) if held.is_empty() && unread.is_empty() => row(Tag::Skip, "VMs that may hold the token: none".into())?,
        Ok((held, unread)) => {
            for h in held {
                row(Tag::Warn, format!("{} ({}) received {} at {}: it may hold it until terminated", h.id, h.status, received(h, index.as_ref()), rfc3339_utc(h.credential_at)))?;
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
/// then (`[!! ]` past 330 days of its one-year life). A1: `account` names
/// the Claude account the installed copy is (none in a tree with no
/// account, or for a seal no account holds, which a row of its own says).
#[must_use]
pub fn row_setup_token(state: &AwsEnvState, path: &Path, recorded: &Recorded, rejected: Option<&crate::bridge::agent::credential::Rejection>, account: Option<&str>, now: u64) -> crate::commands::DoctorLine {
    use crate::commands::DoctorLine;
    let of = account.map_or_else(String::new, |a| format!(" (Claude account {a})"));
    match state {
        AwsEnvState::Absent => DoctorLine::row(Tag::Skip, format!("setup-token absent ({})  <- claude setup-token, then ai-env creds setup-token", path.display())),
        AwsEnvState::NotSealed(why) => DoctorLine::row(Tag::No, format!("setup-token NOT sealed: {} {why}  <- move it away (and revoke what it holds), then ai-env creds setup-token", path.display())),
        AwsEnvState::Sealed => {
            if let Some(r) = rejected {
                return DoctorLine::row(Tag::No, format!("setup-token{of} refused by Anthropic on {} ({})  <- claude setup-token, then ai-env creds setup-token", r.at, r.vm));
            }
            let left = recorded.days_left(now);
            let mut text = format!("setup-token sealed{of}: {}", recorded.describe());
            if let (Some(at), Some(left)) = (recorded.sealed_at, left) {
                text.push_str(&format!(", sealed {} (about {left} days left of its one-year life)", &rfc3339_utc(at)[..10]));
            }
            let tag = if left.is_some_and(|l| l < WARN_DAYS_LEFT) { Tag::Warn } else { Tag::Ok };
            DoctorLine::row(tag, text)
        }
    }
}

/// doctor's credential rows (S7), from what is on disk, with no Touch ID:
/// the setup-token (A1: naming the Claude account it is), a `[!! ]` row when
/// `state/creds.toml` cannot be read (which seals Anthropic refused is then
/// unknown, and credentialed commands refuse every seal: never shown as no
/// refusal), a `[!! ]` row for each thing wrong with the accounts as a whole
/// ([`AccountsSeen::problems`]: none in a tree with no account and no
/// `credentials/accounts/<name>.env` in the clear), and
/// `combined.env` against its sources. Nothing is written.
#[must_use]
pub fn doctor_rows(paths: &Paths, now: u64) -> Vec<crate::commands::DoctorLine> {
    use crate::commands::DoctorLine;
    let path = paths.setup_token_env();
    let state = aws_env_state(&path);
    let text = (state == AwsEnvState::Sealed).then(|| crate::bridge::registry::read_regular_file(&path).ok().flatten()).flatten();
    let recorded = text.as_deref().map(Recorded::of).unwrap_or_default();
    let rejected = crate::bridge::agent::credential::seal_tag(&path).map_or(Ok(None), |tag| crate::bridge::agent::credential::read_rejection(paths, &tag));
    let (tag, line) = combined_line(&combined_state(paths), &container_mode(paths), state == AwsEnvState::Sealed);
    let seen = AccountsSeen::read(paths);
    let account = seen.active().map(|f| f.name.as_str());
    let mut rows = vec![row_setup_token(&state, &path, &recorded, rejected.as_ref().ok().and_then(Option::as_ref), account, now)];
    if let Err(e) = &rejected {
        rows.push(DoctorLine::row(Tag::Warn, format!("setup-token refusals unknown: {e}  <- repair it, or remove it to forget every recorded refusal (credentialed commands refuse every seal meanwhile)")));
    }
    rows.extend(seen.problems(paths).into_iter().map(|p| DoctorLine::row(Tag::Warn, p)));
    rows.push(DoctorLine::row(tag, line));
    rows
}

// ---- creds forget -----------------------------------------------------------------------

/// `ai-env creds forget [--yes]`: a dry run without `--yes`. A1: every Claude
/// account too (everything in `credentials/accounts/`, the directory
/// removed once empty, and `state/accounts.toml`, readable or not: this is
/// the forget-all, which never adopts), deleted under the store's lock (no
/// install runs meanwhile; the lock file itself stays); each holder's line
/// names the account it received.
pub fn cmd_forget(yes: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let creds = paths.credentials();
    let mut files: Vec<PathBuf> = [paths.setup_token_env(), paths.combined_env()].into_iter().filter(|p| std::fs::symlink_metadata(p).is_ok()).collect();
    files.extend(backups_in(&creds, "setup-token.env"));
    files.extend(backups_in(&creds, "combined.env"));
    let account_files = account_entries(&paths);
    let accounts_n = account_files.iter().filter(|p| p.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".env")).is_some_and(accounts::valid_name)).count();
    files.extend(account_files);
    if std::fs::symlink_metadata(paths.accounts_state()).is_ok() {
        files.push(paths.accounts_state());
    }
    // Before anything goes: the accounts' names for the holders' lines.
    let index = AccountsSeen::read(&paths).any().then(|| accounts::tag_index(&paths));
    let (held, unread) = holders(&paths).unwrap_or_else(|e| {
        eprintln!("warning: the VM registry cannot be read ({e}): VMs that received the token are not listed; `ai-env vm list` shows them");
        (Vec::new(), Vec::new())
    });
    let verb = if yes { "deleting" } else { "would delete" };
    if files.is_empty() {
        outln!("nothing to delete: no setup-token, combined.env or backup of them under {}", creds.display());
    }
    for f in &files {
        outln!("{verb} {}", f.display());
    }
    for h in &held {
        outln!("{} ({}) received {} at {}: only terminating it clears its copies: ai-env vm terminate {}", h.id, h.status, received(h, index.as_ref()), rfc3339_utc(h.credential_at), h.id);
    }
    for u in &unread {
        outln!("{UNREADABLE_ROW}: {u}; only terminating its VM clears its copies (`ai-env vm list` shows the VMs)");
    }
    if accounts_n > 1 {
        outln!("ai-env cannot revoke the tokens: revoke each in the claude.ai account it was made in (README, Credentials)");
    } else {
        outln!("ai-env cannot revoke the token: revoke it on Anthropic's side (README, Credentials)");
    }
    if !yes {
        outln!("dry run: nothing deleted; pass --yes to delete");
        return Ok(());
    }
    // Under the store's lock (C11), when there is anything to delete: no install copies an account meanwhile.
    let held_lock = if files.is_empty() {
        None
    } else {
        accounts::lock(&paths).map_err(|e| eprintln!("warning: the Claude accounts' lock cannot be taken ({e}): deleting without it")).ok()
    };
    let mut failed = Vec::new();
    for f in &files {
        if let Err(e) = std::fs::remove_file(f) {
            if e.kind() != ErrorKind::NotFound {
                failed.push(format!("{}: {e}", f.display()));
            }
        }
    }
    // Emptied: the directory goes too (anything left in it, a directory of its own, keeps it).
    if let Err(e) = std::fs::remove_dir(paths.accounts_dir()) {
        if e.kind() != ErrorKind::NotFound && accounts_dir_listed(&paths) {
            eprintln!("warning: {} is not removed: {e}", paths.accounts_dir().display());
        }
    }
    drop(held_lock);
    let row = audit::AuditRow::new(
        "creds_forget",
        None,
        audit::detail(&[
            ("files", files.len().to_string()),
            ("accounts", accounts_n.to_string()),
            ("holders", held.len().to_string()),
            ("holders_unreadable", unread.len().to_string()),
            ("failed", failed.len().to_string()),
        ]),
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

/// A1: what `creds forget` deletes of `credentials/accounts/`: every entry
/// but a directory (the accounts' files, their combined containers and
/// backups, a link, a leftover temp file), by name; none when it is absent
/// or a link (the link is never followed: it is listed itself).
fn account_entries(paths: &Paths) -> Vec<PathBuf> {
    let dir = paths.accounts_dir();
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.file_type().is_symlink() => return vec![dir],
        Ok(m) if m.is_dir() => {}
        _ => return Vec::new(),
    }
    let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut out: Vec<PathBuf> = entries.flatten().filter(|e| e.file_type().is_ok_and(|t| !t.is_dir())).map(|e| e.path()).collect();
    out.sort();
    out
}

/// Is `credentials/accounts/` still a directory with something in it?
fn accounts_dir_listed(paths: &Paths) -> bool {
    std::fs::read_dir(paths.accounts_dir()).is_ok_and(|mut d| d.next().is_some())
}

/// `ai-env creds forget --ops [--yes]` (S8 operators): `credentials/ops.env`
/// and its `ops.env.<unix>.bak` backups, nothing else, a dry run without
/// `--yes`; then how to delete the key in IAM (ai-env cannot), naming its
/// last four as the notes recorded them.
pub fn cmd_forget_ops(yes: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let ops = paths.ops_env();
    let notes = match aws_env_state(&ops) {
        AwsEnvState::Sealed => crate::bridge::registry::read_regular_file(&ops).ok().flatten().map(|text| KeyNotes::of(&text)).unwrap_or_default(),
        _ => KeyNotes::default(),
    };
    let mut files: Vec<PathBuf> = [ops].into_iter().filter(|p| std::fs::symlink_metadata(p).is_ok()).collect();
    files.extend(backups_in(&paths.credentials(), "ops.env"));
    let verb = if yes { "deleting" } else { "would delete" };
    if files.is_empty() {
        outln!("nothing to delete: no ops.env or backup of it under {}", paths.credentials().display());
    }
    for f in &files {
        outln!("{verb} {}", f.display());
    }
    let key = notes.key_id_last4.as_deref().map_or_else(|| "the key (its last four not recorded)".to_string(), |tail| format!("the key ...{tail}"));
    outln!("ai-env cannot deactivate {key}: delete it in IAM:");
    outln!("  ai-env as deployer -- aws iam list-access-keys --user-name {OPS_USER} --region {}", crate::bridge::config::REGION);
    outln!("  ai-env as deployer -- aws iam delete-access-key --user-name {OPS_USER} --access-key-id <id> --region {}", crate::bridge::config::REGION);
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
    let row = audit::AuditRow::new("creds_forget", None, audit::detail(&[("ops", "true".to_string()), ("files", files.len().to_string()), ("failed", failed.len().to_string())]));
    if let Err(e) = audit::append(&paths.audit(), &row) {
        crate::bridge::voice::warn(&format!("the audit row was not written: {e}"));
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
        let (tag, t) = text(row_setup_token(&AwsEnvState::Absent, p, &Recorded::default(), None, None, 1_790_000_000));
        assert!(tag == Tag::Skip && t.contains("<- claude setup-token, then ai-env creds setup-token"), "{t}");
        let (tag, t) = text(row_setup_token(&AwsEnvState::NotSealed("is a symlink".into()), p, &Recorded::default(), None, None, 0));
        assert!(tag == Tag::No && t.contains("is a symlink"), "{t}");
        let (tag, t) = text(row_setup_token(&AwsEnvState::Sealed, p, &rec, None, None, 1_790_000_000 + 86_400));
        assert_eq!((tag, t.as_str()), (Tag::Ok, "setup-token sealed: sk-ant-oat01-… (108 chars), sealed 2026-09-21 (about 364 days left of its one-year life)"));
        let (tag, _) = text(row_setup_token(&AwsEnvState::Sealed, p, &rec, None, None, 1_790_000_000 + 86_400 * 331));
        assert_eq!(tag, Tag::Warn, "past 330 days");
        let r = crate::bridge::agent::credential::Rejection { tag: "seal".into(), at: "2026-10-07T12:00:00Z".into(), vm: "microvm-1".into() };
        let (tag, t) = text(row_setup_token(&AwsEnvState::Sealed, p, &rec, Some(&r), None, 1_790_000_000));
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
        let names = |f: &str| backups_in(&paths.credentials(), f).iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        assert_eq!(names("setup-token.env"), ["setup-token.env.1700000000.bak", "setup-token.env.1700000001.bak"]);
        assert_eq!(names("combined.env"), ["combined.env.1700000002.bak"]);
        // A1: the accounts' own, in credentials/accounts/, counted per file for `creds status`.
        std::fs::create_dir_all(paths.accounts_dir()).unwrap();
        for name in ["work.env", "work.env.1700000004.bak", "work.env.1700000005.bak", "work.combined.env.1700000006.bak", "spare.env.1700000007.bak", "Bad.env.1700000008.bak", "work.env.x.bak", "default.env"] {
            std::fs::write(paths.accounts_dir().join(name), "x").unwrap();
        }
        let in_accounts = backups_in(&paths.accounts_dir(), "work.env").iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        assert_eq!(in_accounts, ["work.env.1700000004.bak", "work.env.1700000005.bak"]);
        assert_eq!(account_backups(&paths), [("accounts/spare.env".to_string(), 1), ("accounts/work.combined.env".to_string(), 1), ("accounts/work.env".to_string(), 2)]);
    }

    /// A1 (C2): an account's combined container is judged against its own
    /// file and aws.env, never the installed copy, which may be another
    /// account's; a stale verdict names `accounts/<name>.env`; and the text
    /// judgement an install uses agrees with the files' one.
    #[test]
    fn an_accounts_combined_is_judged_against_its_own_file() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.accounts_dir()).unwrap();
        let blob = b"age-encryption.org/v1\n-> x\n--- y\n";
        let (aws, work, other) = (container::write(blob), container::write_annotated(blob, &[("kind", "setup-token"), ("account", "work")]).unwrap(), container::write_annotated(blob, &[("kind", "setup-token"), ("chars", "2")]).unwrap());
        std::fs::write(paths.aws_env(), &aws).unwrap();
        std::fs::write(paths.account_env("work"), &work).unwrap();
        std::fs::write(paths.setup_token_env(), &other).unwrap();
        assert_eq!(account_combined_state(&paths, "work"), CombinedState::Absent);
        let combined = container::write_annotated(blob, &[("aws_file_sha256", &text_sha256(&aws)), ("token_file_sha256", &text_sha256(&work)), ("account", "work")]).unwrap();
        std::fs::write(paths.account_combined_env("work"), &combined).unwrap();
        assert_eq!(account_combined_state(&paths, "work"), CombinedState::Current, "its own file, though another seal is installed");
        assert_eq!(combined_judged(&combined, Some(&text_sha256(&aws)), Some(&text_sha256(&work)), "x"), CombinedState::Current);
        assert_eq!(combined_judged(&combined, Some(&text_sha256(&aws)), None, "accounts/work.env"), CombinedState::Stale("accounts/work.env is gone".into()));
        std::fs::write(paths.account_env("work"), &other).unwrap();
        assert_eq!(account_combined_state(&paths, "work"), CombinedState::Stale("accounts/work.env changed since it was built".into()));
        let target = CombinedFor::account(&paths, "work");
        assert_eq!((target.token_src, target.out, target.account.as_str()), (paths.account_env("work"), paths.account_combined_env("work"), "work"));
        assert_eq!((source_name(&paths.setup_token_env()), source_name(&paths.account_env("work"))), ("setup-token.env".to_string(), "accounts/work.env".to_string()));
    }

    /// A1: doctor's setup-token row names the Claude account it is; the
    /// accounts as a whole add a `[!! ]` row each: none in a tree with no
    /// account, a seal no account holds, no account active, a store that
    /// cannot be read (never written); nothing is written by any of it.
    #[test]
    fn doctor_names_the_account_and_what_is_wrong_with_them() {
        use crate::commands::DoctorLine;
        let rows = |paths: &Paths| doctor_rows(paths, 1_790_000_000).into_iter().map(|l| match l {
            DoctorLine::Row { tag, text } => (tag, text),
            DoctorLine::Plain(t) => panic!("{t}"),
        }).collect::<Vec<_>>();
        let rec = Recorded { prefix: Some("sk-ant-oat01-".into()), chars: Some(108), sealed_at: Some(1_790_000_000) };
        let line = |l: DoctorLine| match l {
            DoctorLine::Row { text, .. } => text,
            DoctorLine::Plain(t) => t,
        };
        assert!(line(row_setup_token(&AwsEnvState::Sealed, Path::new("/x"), &rec, None, Some("work"), 1_790_000_000)).starts_with("setup-token sealed (Claude account work): sk-ant-oat01-… (108 chars)"));
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.accounts_dir()).unwrap();
        let blob = b"age-encryption.org/v1\n-> x\n--- y\n";
        let work = container::write_annotated(blob, &[("kind", "setup-token")]).unwrap();
        std::fs::write(paths.setup_token_env(), &work).unwrap();
        assert_eq!(rows(&paths).len(), 2, "no account: the legacy rows");
        std::fs::write(paths.account_env("work"), &work).unwrap();
        let all = rows(&paths);
        assert!(all.len() == 2 && all[0].1.starts_with("setup-token sealed (Claude account work):"), "{all:?}");
        std::fs::write(paths.setup_token_env(), container::write(blob)).unwrap();
        let all = rows(&paths);
        assert!(all.len() == 3 && all[1].0 == Tag::Warn && all[1].1.starts_with("setup-token.env holds a seal no Claude account holds (seal "), "{all:?}");
        std::fs::remove_file(paths.setup_token_env()).unwrap();
        let all = rows(&paths);
        assert!(all.len() == 3 && all[1].1 == crate::bridge::accounts::NO_ACTIVE, "{all:?}");
        std::fs::write(paths.setup_token_env(), &work).unwrap();
        std::fs::create_dir_all(paths.accounts_state().parent().unwrap()).unwrap();
        std::fs::write(paths.accounts_state(), "[[account]\n").unwrap();
        let all = rows(&paths);
        assert!(all.len() == 3 && all[1].0 == Tag::Warn && all[1].1.contains("cannot be parsed") && all[1].1.ends_with("rebuilds it from credentials/accounts/ (without its usage)"), "{all:?}");
        assert_eq!(std::fs::read_to_string(paths.accounts_state()).unwrap(), "[[account]\n", "never written");
    }

    /// C13: an account Anthropic refused says so, and is flagged so (`creds
    /// status` shows it `[!! ]`, never `[NO ]`, which `make acceptance`
    /// refuses); one whose combined container is not usable while the
    /// runtime key is sealed in container mode warns; refusals that cannot
    /// be read warn too.
    #[test]
    fn an_accounts_row_says_its_seal_refusal_and_combined() {
        let shown = |refused, combined| AccountShown { name: "old".into(), tag: "0123456789abcdef".into(), active: false, recorded: Recorded { prefix: Some("sk-ant-oat01-".into()), chars: Some(108), sealed_at: Some(1_790_000_000) }, refused, combined, note: None };
        let (text, warn, refused) = shown(Ok(None), CombinedState::Current).text(&Ok(()), true, 1_790_000_000 + 86_400);
        assert_eq!((text.as_str(), warn, refused), ("seal 0123456789abcdef, sk-ant-oat01-… (108 chars), sealed 2026-09-21 (about 364 days left); combined.env current", false, false));
        let r = crate::bridge::agent::credential::Rejection { tag: "0123456789abcdef".into(), at: "2026-10-07T12:00:00Z".into(), vm: "microvm-1".into() };
        let (text, warn, refused) = shown(Ok(Some(r)), CombinedState::Current).text(&Ok(()), true, 1_790_000_000);
        assert!(warn && refused && text.ends_with("; refused by Anthropic on 2026-10-07T12:00:00Z (microvm-1): seal a fresh token for it (`claude setup-token` logged in as that account, then `ai-env creds account add old`)"), "{text}");
        let (text, warn, _) = shown(Ok(None), CombinedState::Absent).text(&Ok(()), true, 1_790_000_000);
        assert!(warn && text.ends_with("; combined.env absent"), "{text}");
        let (_, warn, _) = shown(Ok(None), CombinedState::Absent).text(&Ok(()), false, 1_790_000_000);
        assert!(!warn, "no runtime key sealed: nothing to combine");
        let (text, warn, _) = shown(Ok(None), CombinedState::Absent).text(&Err("[aws].credentials is profile:x".into()), true, 1_790_000_000);
        assert!(!warn && text.ends_with("; combined.env not used ([aws].credentials is profile:x)"), "{text}");
        let (text, warn, refused) = shown(Err("state/creds.toml cannot be parsed (x)".into()), CombinedState::Current).text(&Ok(()), true, 1_790_000_000);
        assert!(warn && !refused && text.ends_with("; refusals unknown (state/creds.toml cannot be parsed (x))"), "{text}");
        assert_eq!(shown(Ok(None), CombinedState::Current).title(), "old");
        // L-8: the name is the file's; notes that name another account (sealed under it, then renamed) are
        // neither shown nor warned of.
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let file = AccountFile { name: "spare".into(), text: container::write_annotated(b"age-encryption.org/v1\n-> x\n--- y\n", &[("kind", "setup-token"), ("account", "work")]).unwrap(), tag: "t".into(), sealed: None };
        let renamed = AccountShown::of(&paths, &file, false);
        let (text, warn, refused) = renamed.text(&Ok(()), false, 1_790_000_000);
        assert!(!warn && !refused && !text.contains("work"), "{text}");
        assert!(!renamed.json(None, 1_790_000_000).to_string().contains("work"));
        assert_eq!(renamed.title(), "spare");
    }

    /// A1: what a holder's line and `--json` say it received: the token in
    /// a tree with no account (or for a row that records no seal), else the
    /// account the seal is (an older seal too), a seal no account holds
    /// (`unknown` in `--json`), or, while the accounts cannot be read, a
    /// token of an unknown account.
    #[test]
    fn a_holder_names_the_account_it_received() {
        let h = |tag: Option<&str>| Holder { id: "microvm-1".into(), status: "running", credential_at: 1_790_000_000, tag: tag.map(Into::into) };
        let index: SealIndex = Ok(BTreeMap::from([("aaaaaaaaaaaaaaaa".to_string(), ("work".to_string(), true)), ("bbbbbbbbbbbbbbbb".to_string(), ("work".to_string(), false))]));
        let unreadable: SealIndex = Err("state/accounts.toml cannot be parsed (x)".into());
        let says = |h: &Holder, index: Option<&SealIndex>| (received(h, index), holder_account(h, index));
        assert_eq!(says(&h(Some("aaaaaaaaaaaaaaaa")), None), ("the token".into(), None), "a tree with no account");
        assert_eq!(says(&h(Some("aaaaaaaaaaaaaaaa")), Some(&index)), ("Claude account work's token (seal aaaaaaaaaaaaaaaa)".into(), Some("work".into())));
        assert_eq!(says(&h(Some("bbbbbbbbbbbbbbbb")), Some(&index)), ("Claude account work's token (seal bbbbbbbbbbbbbbbb)".into(), Some("work".into())), "an older seal");
        assert_eq!(says(&h(Some("cccccccccccccccc")), Some(&index)), ("a token no Claude account holds (seal cccccccccccccccc)".into(), Some(accounts::UNKNOWN.into())));
        assert_eq!(says(&h(Some("aaaaaaaaaaaaaaaa")), Some(&unreadable)), ("a token of an unknown Claude account (seal aaaaaaaaaaaaaaaa)".into(), Some(accounts::UNKNOWN.into())));
        assert_eq!(says(&h(None), Some(&index)), ("the token".into(), None), "a row that records no seal");
    }

    /// A1: a link in place of `credentials/accounts/` is never listed
    /// through: `make runtime-key` removes no combined container in what it
    /// points at, and `creds status` counts no backup there.
    #[test]
    fn a_link_in_place_of_the_accounts_directory_is_never_followed() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(paths.credentials()).unwrap();
        for name in ["work.combined.env", "work.env.1700000000.bak"] {
            std::fs::write(elsewhere.join(name), "x").unwrap();
        }
        std::os::unix::fs::symlink(&elsewhere, paths.accounts_dir()).unwrap();
        assert!(remove_account_combineds(&paths).is_empty() && elsewhere.join("work.combined.env").exists(), "nothing removed through the link");
        assert!(account_backups(&paths).is_empty());
        std::fs::remove_file(paths.accounts_dir()).unwrap();
        std::fs::rename(&elsewhere, paths.accounts_dir()).unwrap();
        assert_eq!((remove_account_combineds(&paths), account_backups(&paths)), (vec!["work".to_string()], vec![("accounts/work.env".to_string(), 1)]), "a real directory");
    }

    /// Design §5: an install decided before the paste is judged again under
    /// the store's lock: it goes on while `setup-token.env` holds one of the
    /// account's seals (its file's, or, just sealed anew, the replaced one in
    /// its backup), or is absent as it was at the start; never once another
    /// account is installed, or the account is gone from it; a file in the
    /// clear there goes to the install, which refuses it.
    #[test]
    fn an_install_goes_on_only_while_the_account_is_still_installed() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.accounts_dir()).unwrap();
        let sealed = |n: &str| container::write_annotated(b"age-encryption.org/v1\n-> x\n--- y\n", &[("kind", "setup-token"), ("n", n)]).unwrap();
        let (old, new, spare) = (sealed("1"), sealed("2"), sealed("3"));
        // work sealed anew: its file holds the new seal, its backup the replaced one, still installed.
        std::fs::write(paths.account_env("work"), &new).unwrap();
        std::fs::write(paths.accounts_dir().join("work.env.1700000000.bak"), &old).unwrap();
        std::fs::write(paths.account_env("spare"), &spare).unwrap();
        std::fs::write(paths.setup_token_env(), &old).unwrap();
        let still = |name: &str, absent: bool| still_installs(&paths, name, absent).unwrap();
        assert!(still("work", false) && !still("spare", false), "the replaced seal is work's");
        std::fs::write(paths.setup_token_env(), &new).unwrap();
        assert!(still("work", false), "its file's seal");
        // `creds account use spare` meanwhile.
        std::fs::write(paths.setup_token_env(), &spare).unwrap();
        assert!(!still("work", false) && !still("work", true), "another account is installed");
        std::fs::remove_file(paths.setup_token_env()).unwrap();
        assert!(still("work", true) && !still("work", false), "absent: only when it was at the start");
        std::fs::write(paths.setup_token_env(), "CLAUDE_CODE_OAUTH_TOKEN=placeholder\n").unwrap();
        assert!(still("work", false), "the install refuses it, saying why");
        assert_eq!(install_sealed(&paths, "work", Install::No).map(|r| r.is_ok()), None);
        std::fs::write(paths.setup_token_env(), &spare).unwrap();
        assert!(install_sealed(&paths, "work", Install::IfStill { absent: false }).is_none() && std::fs::read_to_string(paths.setup_token_env()).unwrap() == spare, "not installed over spare");
        let done = install_sealed(&paths, "work", Install::Always).unwrap().unwrap();
        assert_eq!((done.from.as_deref(), std::fs::read_to_string(paths.setup_token_env()).unwrap()), (Some("spare"), new), "--use installs whatever is there");
    }

    /// A1: a `<name>.env` in `credentials/accounts/` that is no container
    /// (a plaintext file) is no account, and doctor, `creds status` and
    /// `creds account list` say so in a `[!! ]` row, in a tree with no
    /// account too.
    #[test]
    fn a_file_in_the_clear_among_the_accounts_is_said() {
        use crate::commands::DoctorLine;
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.accounts_dir()).unwrap();
        std::fs::write(paths.account_env("spare"), "CLAUDE_CODE_OAUTH_TOKEN=placeholder\n").unwrap();
        std::fs::write(paths.accounts_dir().join("Bad.env"), "x").unwrap();
        let seen = AccountsSeen::read(&paths);
        let says = format!("{} is not an ai-env container (plaintext?): it is no Claude account; move it away (and revoke what it holds)", paths.account_env("spare").display());
        assert_eq!((seen.files().len(), seen.problems(&paths)), (0, vec![says.clone()]), "Bad.env is no account's name");
        let rows: Vec<(Tag, String)> = doctor_rows(&paths, 1_790_000_000).into_iter().filter_map(|l| match l {
            DoctorLine::Row { tag, text } => Some((tag, text)),
            DoctorLine::Plain(_) => None,
        }).collect();
        assert!(rows.contains(&(Tag::Warn, says)), "{rows:?}");
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
        let CombinedOutcome::Failed { why, removed: false } = rebuild_with_token(&store, &paths, "rq7", &token, &"0".repeat(64), false, false, &CombinedFor::account(&paths, accounts::DEFAULT)) else {
            panic!("the rebuild was not refused");
        };
        assert!(![&id, &secret, &t].iter().any(|s| why.contains(s.as_str())), "the line holds a credential ({} bytes)", why.len());
        let says = format!("{} is not an ai-env container (plaintext?): move it away (and rotate the key it holds), then seal the runtime key with `make runtime-key`", paths.aws_env().display());
        assert_eq!(why, says);
        assert!(!paths.combined_env().exists(), "nothing built");
    }

    /// S8 operators: `creds status`'s ops key row (the file's state as aws.env's,
    /// then what its notes recorded, the UTC day) and the deployer row (what
    /// state/infra.toml records, never an account).
    #[test]
    fn the_ops_key_and_deployer_rows() {
        let notes = KeyNotes { kind: Some("aws-key".into()), user: Some(OPS_USER.into()), key_id_last4: Some("WXYZ".into()), sealed_at: Some(1_791_979_200) };
        let facts = |state: AwsEnvState, opens_with: Option<std::result::Result<String, OpenFault>>, key_notes: KeyNotes| FileFacts {
            path: PathBuf::from("/b/credentials/ops.env"),
            state,
            opens_with,
            recorded: Recorded::default(),
            key_notes,
        };
        let row = |f: FileFacts| ops_text(&f);
        assert_eq!(row(facts(AwsEnvState::Absent, None, KeyNotes::default())), (Tag::Skip, "ops.env: absent (the ai-env-ops key: ai-env as deployer -- make ops-key)".to_string()));
        assert_eq!(row(facts(AwsEnvState::NotSealed("is a symlink".into()), None, KeyNotes::default())), (Tag::No, "ops.env is a symlink".to_string()));
        assert_eq!(
            row(facts(AwsEnvState::Sealed, Some(Ok("ai-env-bridge".into())), notes.clone())),
            (Tag::Ok, "ops.env: sealed, opens with key ai-env-bridge; recorded at sealing, not authenticated: ai-env-ops ...WXYZ, sealed 2026-10-14".to_string())
        );
        let (tag, text) = row(facts(AwsEnvState::Sealed, Some(Err(OpenFault::NoKey("no keystore key opens it".into()))), notes.clone()));
        assert!(tag == Tag::No && text == "ops.env: sealed, but no keystore key opens it; recorded at sealing, not authenticated: ai-env-ops ...WXYZ, sealed 2026-10-14", "{text}");
        let (tag, text) = row(facts(AwsEnvState::Sealed, Some(Err(OpenFault::Unknown("odd header".into()))), KeyNotes::default()));
        assert!(tag == Tag::Warn && text.ends_with("which key opens it is unknown (odd header); recorded at sealing, not authenticated: nothing (no notes)"), "{text}");
        let partial = KeyNotes { sealed_at: None, ..notes.clone() };
        assert_eq!(recorded_key(&partial), "ai-env-ops ...WXYZ, its sealing day not recorded");
        assert_eq!(recorded_key(&KeyNotes { user: None, ..notes.clone() }), "a key ...WXYZ (its user not recorded), sealed 2026-10-14");
        assert_eq!(recorded_key(&KeyNotes { key_id_last4: None, ..notes }), "ai-env-ops (its last four not recorded), sealed 2026-10-14");

        use crate::bridge::infra::InfraState;
        let arn = "arn:aws:iam::123456789012:user/ai-env-deployer";
        let state = InfraState { deployer_user_arn: Some(arn.into()), ..InfraState::default() };
        let (tag, text) = deployer_text(&Ok(Some(state.clone())));
        assert_eq!((tag, text.as_str()), (Tag::Ok, "deployer user/ai-env-deployer (state/infra.toml): its key lives in Strongbox only (ai-env as deployer -- … asks for it)"));
        assert!(!text.contains("123456789012"), "a row shows no account");
        let none = (Tag::Skip, "deployer: none recorded in state/infra.toml (the bootstrap deploy, then make infra-status WRITE=1)".to_string());
        assert_eq!(deployer_text(&Ok(None)), none);
        assert_eq!(deployer_text(&Ok(Some(InfraState { deployer_user_arn: Some(" ".into()), ..state }))), none);
        assert_eq!(deployer_text(&Err(BridgeError::Config("x cannot be parsed".into()))), (Tag::Warn, "deployer: state/infra.toml unreadable (config: x cannot be parsed)".to_string()));
        assert_eq!((arn_resource(arn), arn_resource("not-an-arn")), ("user/ai-env-deployer", "not-an-arn"));
    }
}
