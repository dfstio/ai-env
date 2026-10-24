//! Several Claude accounts, one of them active (S10 addendum A1): the store.
//! The commands that use it come with slices A (`creds account add|use|list|
//! forget|check`) and B (the usage records).
//!
//! Files (0600 in 0700 directories, written with `store::write_atomic`):
//! `credentials/accounts/<name>.env`, the account's sealed setup-token, and
//! `<name>.combined.env`, the runtime key with that token (derived, never
//! backed up); a backup is `<name>.env.<unix>.bak`. A name never holds a `.`
//! ([`valid_name`]), so those roles never collide. An account's name is its
//! file's, never what the file's notes say: notes are not authenticated (C1).
//! The `account=` they record (written when ai-env seals an account) is only
//! the name it was sealed under: [`rename`] moves files, never their bytes
//! (so never their seal id), and nothing warns that the two differ.
//!
//! The active account is installed by byte copy ([`install`]) as
//! `credentials/setup-token.env` and `combined.env`, the files every spawn
//! and credentialed command reads as before. A copy has the same bytes, so
//! the same seal id (`credential::seal_tag`): the refusal record, the VM
//! cache checks and `combined.env`'s hash checks keep working unchanged. The
//! order is fixed (remove `combined.env`, write `setup-token.env`, then
//! `combined.env` only when the account's own is current), so a reader never
//! pairs a token with another account's combined copy.
//!
//! `state/accounts.toml` ([`AccountsState`]) names the accounts by seal id
//! and keeps what was observed of their usage. It is derived from the files
//! ([`reconcile`]): its rows are rebuilt from them, and `active` is the
//! account whose seal is the installed one, never trusted alone. Every write
//! of it, every adoption and every install runs under
//! `state/accounts.toml.lock` ([`lock`]; C11: `write_atomic`'s fixed temp
//! name would collide otherwise); readers rely on its atomic renames.
//!
//! A row may carry the user's note on the account ([`AccountRow::note`]:
//! free text such as an email, [`set_note`]). It is written nowhere but this
//! store (never to an audit row, a log, the census or an error), and every
//! rebuild of the rows keeps it while its name has a file, or gives it to
//! the file's new name when the file moved outside the store (a [`rename`]
//! stopped before its store write, a `mv` by hand). [`rename`] moves an
//! account's files to another name under the store's lock, its row, note,
//! usage and `active` with them.
//!
//! Labels fail open, refusals fail closed (L-2): a store that cannot be read
//! never blocks a spawn or a credentialed command (every label reads
//! [`UNKNOWN`]) and is never written: its writers refuse (exit 1) with the
//! repair hint ([`unreadable`]). A tree with no account at all, the legacy
//! one, gets no label.
//!
//! Adoption: the first writer (`creds account …`, `creds setup-token`, `creds
//! aws-set`) in a tree with no account file and a sealed `setup-token.env`
//! byte-copies it to `accounts/default.env` ([`reconcile`]), and its
//! `combined.env` too when current. Read paths (status, doctor, the
//! wrappers) never write.
//!
//! Slice A's commands: `creds account add|use|list|forget` ([`cmd`]) and
//! `creds account check` ([`check`]).
//!
//! What was seen of each account's usage, its records, the pump's tap and
//! the note a limited chat gets, are [`usage`]'s (slice B).
pub mod check;
pub mod cmd;
pub mod usage;

use crate::bridge::agent::credential::tag_of;
use crate::bridge::audit;
use crate::bridge::config::Paths;
use crate::bridge::creds::{aws_env_state, AwsEnvState};
use crate::bridge::errors::BridgeError;
use crate::bridge::vm::lock::FlockGuard;
use crate::bridge::voice;
use crate::container;
use crate::errors::{CliError, Result};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// The account a legacy `setup-token.env` is adopted as.
pub const DEFAULT: &str = "default";

/// [`label`]'s word for a seal no account holds while accounts exist, and
/// for every seal while the store cannot be read: never an account's name
/// ([`valid_name`]), so a record that says it never means an account.
pub const UNKNOWN: &str = "unknown";

/// The longest account name.
pub const MAX_NAME: usize = 32;

/// The name rule as [`check_name`] states it.
const NAME_RULE: &str = "1-32 of a-z 0-9 _ -, the first a letter or a digit, not `unknown`";

/// [`spawn_problem`]'s text (L-2).
pub const NO_ACTIVE: &str = "no Claude account is active (credentials/setup-token.env is absent): `ai-env creds account use NAME` installs one (`ai-env creds account list` names them)";

/// The audit rows of the Claude accounts (L-5, slice A's), each written by
/// the command it is named after, beside the `creds_*` rows the sealing
/// commands write; `cmd`'s tests keep them unique.
pub mod audit_event {
    /// [`super::reconcile`] adopted a legacy `setup-token.env`: `name`, `tag`, `combined`.
    pub const ADOPT: &str = "creds_account_adopt";
    /// `creds account use`: `from`, `to`, `tag`, `combined`, `chats_other`.
    pub const USE: &str = "creds_account_use";
    /// `creds account forget --yes`: `name`, `files`, `holders`, `was_active`, `failed`.
    pub const FORGET: &str = "creds_account_forget";
    /// `creds account check`, per account answered or limited: `account`, `tag`, `outcome`, `status`,
    /// `five_hour`, `seven_day`, `kind`, `resets_at`, `model`, `claude`, `exit`, `ms`.
    pub const CHECK: &str = "account_check";
    /// [`super::rename`] (`creds account rename`): `from`, `to`, `tag`.
    pub const RENAME: &str = "creds_account_rename";
    /// [`super::set_note`] (`creds account note`, `add --note`), when it changed the note: `name`, `set`
    /// (`set` or `cleared`), never the text.
    pub const NOTE: &str = "creds_account_note";
    /// Every one of them.
    pub const ALL: [&str; 6] = [ADOPT, USE, FORGET, CHECK, RENAME, NOTE];
}

// ---- names --------------------------------------------------------------------------------

/// A Claude account name: `[a-z0-9][a-z0-9_-]{0,31}`, and never
/// [`UNKNOWN`], which labels read for a seal no account holds (an account
/// so named could not be told from none). It names files under
/// `credentials/accounts/`, so never a `.` or a `/`; a file whose name is
/// none (`unknown.env` too) is no account.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    name != UNKNOWN && (1..=MAX_NAME).contains(&b.len()) && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// [`valid_name`], else exit 2, as `creds aws-set --user` refuses a user
/// name. One longer than any name is described by its length, never
/// echoed: a token pasted in its place would reach the terminal.
/// [`UNKNOWN`] is refused with why.
pub fn check_name(name: &str) -> Result<()> {
    if valid_name(name) {
        return Ok(());
    }
    if name == UNKNOWN {
        return Err(CliError::Usage(format!("{UNKNOWN:?} is not a Claude account name: it is the label of a seal no account holds")));
    }
    let chars = name.chars().count();
    let shown = if chars <= MAX_NAME { crate::wire::redact::scrub(&format!("{name:?}")).into_owned() } else { format!("a name of {chars} characters") };
    Err(CliError::Usage(format!("{shown} is not a Claude account name ({NAME_RULE})")))
}

// ---- notes --------------------------------------------------------------------------------

/// The longest note, in characters.
pub const MAX_NOTE: usize = 120;

/// The note rule as [`check_note`] states it.
const NOTE_RULE: &str = "1-120 characters once trimmed, no control character, no token or key";

/// Why `t`, a trimmed note, is none, described by its length or the kind of
/// its characters, never echoed: it may be an email, or a token pasted in
/// its place. `None`: it is one.
fn note_fault(t: &str) -> Option<String> {
    let chars = t.chars().count();
    if chars == 0 {
        return Some(format!("an empty note is not a Claude account note ({NOTE_RULE})"));
    }
    if chars > MAX_NOTE {
        return Some(format!("a note of {chars} characters is not a Claude account note ({NOTE_RULE})"));
    }
    if let Some(c) = t.chars().find(|c| c.is_control()) {
        return Some(format!("a note with a control character (U+{:04X}) is not a Claude account note ({NOTE_RULE})", u32::from(c)));
    }
    // The store is not sealed: a token pasted here would lie on disk in the clear. Only a credential's own shape
    // counts (the scan's built-in tripwires: an `sk-ant-` token, an AWS key id, …), never a word such as `token:`
    // before ordinary text, nor what this process registered to mask: `wire::redact::scrub` would refuse both.
    let (_, shape) = crate::bridge::scan::Rules::defaults().scan_bytes(t.as_bytes()).into_iter().next()?;
    Some(format!("a note holding a credential's shape ({shape}) is not a Claude account note: the store keeps notes in the clear ({NOTE_RULE})"))
}

/// Is `s`, trimmed, a Claude account's note: free text the user gives it
/// (an email, say), 1 to [`MAX_NOTE`] characters (not bytes), none of them
/// a control character (`char::is_control`: a line break, a tab, an escape),
/// so it shows on one line as given, and no token or key in it (a match of
/// a built-in `bridge::scan` tripwire)? A pure check of the text alone.
#[must_use]
pub fn valid_note(s: &str) -> bool {
    note_fault(s.trim()).is_none()
}

/// `s` trimmed when it is a note ([`valid_note`]), else exit 2, the note
/// described by its length or the kind of its characters, never echoed.
pub fn check_note(s: &str) -> Result<String> {
    let t = s.trim();
    match note_fault(t) {
        None => Ok(t.to_string()),
        Some(why) => Err(CliError::Usage(why)),
    }
}

// ---- the store ----------------------------------------------------------------------------

/// `state/accounts.toml`: the accounts by seal id, the active one, and what
/// was observed of their usage. Every field defaults, so a store that lacks
/// one still reads.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AccountsState {
    /// The account whose seal is the installed `credentials/setup-token.env`,
    /// as [`reconcile`] or [`install`] last found it: none with nothing
    /// installed, or with a seal no account holds (a foreign one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    /// One row per sealed `credentials/accounts/<name>.env`, by name.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub account: Vec<AccountRow>,
    /// `[usage.<name>]` (slice B's records, L-3), kept raw: a malformed entry
    /// never makes the store unreadable. [`reconcile`] prunes a name without
    /// a row, and an account sealed anew.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub usage: BTreeMap<String, toml::Value>,
}

/// One account: its file's name, the seal id of that file, and when it was
/// sealed as the file's notes record it (RFC 3339; an adopted legacy file
/// records it too, a hand-made one may not).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AccountRow {
    pub name: String,
    pub tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed: Option<String>,
    /// The user's note on the account ([`check_note`]: free text such as an
    /// email), kept by every rebuild of the rows while the name has a file,
    /// and written nowhere but this store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The seal a generation runs on (L-4): the seal id of its token's
/// container, and the account that is, when one is known.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seal {
    pub tag: String,
    pub account: Option<String>,
}

impl Seal {
    /// `tag`, with the account [`label`] names for it now.
    #[must_use]
    pub fn of(paths: &Paths, tag: String) -> Seal {
        let account = label(paths, &tag);
        Seal { tag, account }
    }
}

/// `state/accounts.toml`, or `None` when it does not exist. One that cannot
/// be read or parsed (a link, not a regular file, broken TOML) is an error
/// on one line naming it, as `credential::read_creds_state` says of the
/// refusal record; what a reader does then is L-2's: labels fail open,
/// writers refuse.
pub fn read(paths: &Paths) -> std::result::Result<Option<AccountsState>, String> {
    let path = paths.accounts_state();
    match crate::bridge::registry::read_regular_file(&path) {
        Ok(None) => Ok(None),
        Ok(Some(text)) => toml::from_str(&text).map(Some).map_err(|e| format!("{} cannot be parsed ({})", path.display(), e.message().lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(", "))),
        // Each names the file already.
        Err(BridgeError::Config(m)) => Err(m),
        Err(e) => Err(e.to_string()),
    }
}

/// What doctor, `creds status` and a writer that refuses say of a store
/// that cannot be read (L-2); `why` is [`read`]'s error, which names it.
#[must_use]
pub fn unreadable(why: &str) -> String {
    format!("{why}: Claude account names are unknown; remove it, and `ai-env creds account list` rebuilds it from credentials/accounts/ (without its usage)")
}

/// `state/accounts.toml.lock`, held: released when dropped.
#[derive(Debug)]
pub struct StoreLock {
    _guard: FlockGuard,
}

/// `state/accounts.toml.lock`.
fn lock_path(paths: &Paths) -> PathBuf {
    let mut lock = paths.accounts_state().into_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
}

/// Take the store's lock (C11), waiting for it: its holders keep it for
/// milliseconds and never ask for Touch ID under it. Never take it again
/// while holding it: flock(2) locks are per open file, so the second waits
/// for the first forever ([`update_held`] and [`install_held`] work under a
/// hold).
pub fn lock(paths: &Paths) -> std::result::Result<StoreLock, String> {
    crate::bridge::vm::lock::lock_blocking(&lock_path(paths)).map(|g| StoreLock { _guard: g }).map_err(|e| e.to_string())
}

/// The store's text (empty for an empty store).
fn render(state: &AccountsState) -> std::result::Result<String, String> {
    toml::to_string(state).map_err(|e| format!("state/accounts.toml cannot be rendered ({e})"))
}

/// Is `after` another store than `before` (none: an empty one)? Judged on
/// their texts as this module writes them, so a hand-formatted store keeps
/// its form until something in it changes.
fn differs(before: Option<&AccountsState>, after: &AccountsState) -> std::result::Result<bool, String> {
    Ok(render(before.unwrap_or(&AccountsState::default()))? != render(after)?)
}

/// `state/.accounts.toml.tmp`: the fixed temp file `store::write_atomic`
/// writes the store through, opened `O_EXCL`.
fn temp_path(paths: &Paths) -> PathBuf {
    paths.accounts_state().with_file_name(".accounts.toml.tmp")
}

/// Write `after` when it [`differs`] from `before`, the lock held: whether
/// it did. An absent store stays absent while nothing is put in it. A
/// leftover temp file ([`temp_path`]) is removed first: only a holder of the
/// lock writes one, so while it is held a leftover is a dead holder's (one
/// killed mid-write), and it would fail every write after it.
fn write_if_changed(paths: &Paths, _held: &StoreLock, before: Option<&AccountsState>, after: &AccountsState) -> std::result::Result<bool, String> {
    if !differs(before, after)? {
        return Ok(false);
    }
    crate::bridge::registry::remove_if_present(&temp_path(paths)).map_err(|e| e.to_string())?;
    crate::store::write_atomic(&paths.accounts_state(), render(after)?.as_bytes()).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Read the store, apply `f`, and write it back when that changed it, under
/// its lock, so two writers never undo each other (the
/// `credential::update_creds_state` pattern). A store that cannot be read is
/// never written ([`unreadable`]'s text); an absent one starts empty and is
/// created only when `f` puts something in it.
pub fn update<T>(paths: &Paths, f: impl FnOnce(&mut AccountsState) -> T) -> std::result::Result<T, String> {
    let held = lock(paths)?;
    update_held(paths, &held, f)
}

/// [`update`] with the lock already held, between the other steps of one
/// hold (a deletion and its row).
pub fn update_held<T>(paths: &Paths, held: &StoreLock, f: impl FnOnce(&mut AccountsState) -> T) -> std::result::Result<T, String> {
    let before = read(paths).map_err(|e| unreadable(&e))?;
    let mut state = before.clone().unwrap_or_default();
    let out = f(&mut state);
    write_if_changed(paths, held, before.as_ref(), &state)?;
    Ok(out)
}

/// What one [`try_update`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryUpdate {
    /// `f` changed the store, and it was written.
    Written,
    /// `f` changed nothing: nothing was written.
    Unchanged,
    /// Someone else held the lock: nothing was read or written.
    Busy,
    /// There is no store: none was created.
    NoFile,
    /// The store cannot be read: it is left as it is.
    Unreadable,
}

/// [`update`] for the pump, which never waits (L-3): one non-blocking
/// attempt at the lock, and never a store, or the directory of its lock,
/// created (the lock file itself may be, beside an existing store). `Err`
/// is an I/O failure: the lock file cannot be opened, the write failed.
pub fn try_update(paths: &Paths, f: impl FnOnce(&mut AccountsState)) -> std::result::Result<TryUpdate, String> {
    if matches!(std::fs::symlink_metadata(paths.accounts_state()), Err(e) if e.kind() == ErrorKind::NotFound) {
        return Ok(TryUpdate::NoFile);
    }
    let Some(guard) = crate::bridge::vm::lock::try_lock_exclusive(&lock_path(paths)).map_err(|e| e.to_string())? else {
        return Ok(TryUpdate::Busy);
    };
    let held = StoreLock { _guard: guard };
    let before = match read(paths) {
        Ok(Some(state)) => state,
        // Removed since it was seen (`creds forget`): never recreated here.
        Ok(None) => return Ok(TryUpdate::NoFile),
        Err(_) => return Ok(TryUpdate::Unreadable),
    };
    let mut state = before.clone();
    f(&mut state);
    Ok(if write_if_changed(paths, &held, Some(&before), &state)? { TryUpdate::Written } else { TryUpdate::Unchanged })
}

// ---- the files ----------------------------------------------------------------------------

/// One sealed account file, read once: what an install copies and what its
/// seal id names are the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountFile {
    pub name: String,
    /// The container's text, as read.
    pub text: String,
    /// Its seal id (`credential::tag_of` of `text`).
    pub tag: String,
    /// When it was sealed, as its notes record it (`sealed=`).
    pub sealed: Option<String>,
}

impl AccountFile {
    fn of(name: &str, text: String) -> AccountFile {
        let tag = tag_of(&text);
        let sealed = container::meta(&text).remove("sealed");
        AccountFile { name: name.to_string(), text, tag, sealed }
    }

    /// Its row in the store, without a note: notes are the store's alone
    /// (each rebuild of the rows keeps the one its name's row had).
    #[must_use]
    pub fn row(&self) -> AccountRow {
        AccountRow { name: self.name.clone(), tag: self.tag.clone(), sealed: self.sealed.clone(), note: None }
    }
}

/// `path` classified ([`aws_env_state`]: never through a link, never
/// blocking on a FIFO), then read once and that text checked again: what is
/// tagged, copied or installed is exactly the container read. `Err` is the
/// state otherwise (absent, or why it is not sealed).
fn read_sealed(path: &Path) -> std::result::Result<String, AwsEnvState> {
    match aws_env_state(path) {
        AwsEnvState::Sealed => {}
        other => return Err(other),
    }
    match crate::bridge::registry::read_regular_file(path) {
        Ok(Some(text)) if container::detect(&text) => Ok(text),
        Ok(Some(_)) => Err(AwsEnvState::NotSealed("is not an ai-env container (plaintext?)".into())),
        Ok(None) => Err(AwsEnvState::Absent),
        Err(BridgeError::Config(m)) => Err(AwsEnvState::NotSealed(format!("cannot be read ({m})"))),
        Err(e) => Err(AwsEnvState::NotSealed(format!("cannot be read ({e})"))),
    }
}

/// Is `dir` a real directory (`Ok(false)`: absent)? A link or anything else
/// in its place is an error naming it, never followed.
fn real_dir(dir: &Path) -> std::result::Result<bool, String> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => Err(format!("{} is a symlink; refusing to use Claude accounts through it", dir.display())),
        Ok(m) if !m.is_dir() => Err(format!("{} is not a directory", dir.display())),
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot stat {}: {e}", dir.display())),
    }
}

/// The names of `credentials/accounts/`'s entries, with their paths.
fn entries(paths: &Paths) -> std::result::Result<Vec<(String, PathBuf)>, String> {
    let dir = paths.accounts_dir();
    if !real_dir(&dir)? {
        return Ok(Vec::new());
    }
    let listed = |e: std::io::Error| format!("cannot list {}: {e}", dir.display());
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(listed)? {
        let entry = entry.map_err(listed)?;
        if let Some(name) = entry.file_name().to_str() {
            out.push((name.to_string(), entry.path()));
        }
    }
    Ok(out)
}

/// The sealed account files, by name: the `<name>.env` entries of
/// `credentials/accounts/` with a valid name that are regular files holding
/// an ai-env container (a link, a plaintext file, a combined container or a
/// backup is none), each read once. No directory is no account; a link in
/// its place is an error.
pub fn account_files(paths: &Paths) -> std::result::Result<Vec<AccountFile>, String> {
    let mut out: Vec<AccountFile> = entries(paths)?
        .into_iter()
        .filter_map(|(file, path)| {
            let name = file.strip_suffix(".env").filter(|n| valid_name(n))?;
            read_sealed(&path).ok().map(|text| AccountFile::of(name, text))
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// The `<name>.env` entries of `credentials/accounts/` with a valid name
/// that are no sealed container (a plaintext file, a link, a FIFO), by name,
/// each with why (`aws_env_state`'s words): no account ([`account_files`]
/// skips them), but one may hold a token in the clear, which doctor, `creds
/// status`, `creds account list` and `check` say (slice A).
pub fn unsealed_files(paths: &Paths) -> std::result::Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = entries(paths)?
        .into_iter()
        .filter_map(|(file, path)| {
            let name = file.strip_suffix(".env").filter(|n| valid_name(n))?;
            match read_sealed(&path) {
                Err(AwsEnvState::NotSealed(why)) => Some((name.to_string(), why)),
                _ => None,
            }
        })
        .collect();
    out.sort();
    Ok(out)
}

/// The account a backup's file name, `<name>.env.<unix>.bak`, is of.
fn backup_of(file: &str) -> Option<&str> {
    let (name, rest) = file.split_once(".env.")?;
    let unix = rest.strip_suffix(".bak")?;
    (valid_name(name) && !unix.is_empty() && unix.bytes().all(|b| b.is_ascii_digit())).then_some(name)
}

/// The seals the accounts' backups hold (`<name>.env.<unix>.bak`: older
/// seals of that account), as (name, tag), by name; a backup that is not a
/// sealed regular file holds none.
fn backup_tags(paths: &Paths) -> std::result::Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = entries(paths)?.into_iter().filter_map(|(file, path)| Some((backup_of(&file)?.to_string(), tag_of(&read_sealed(&path).ok()?)))).collect();
    out.sort();
    Ok(out)
}

/// Is `combined` (a combined container's text) current for `token`, the
/// account file's text it pairs, and the aws.env there now: are the two
/// hashes its notes record those of these texts? `setup_token`'s rule
/// (`combined_state_of`, on the texts already read: `combined_judged`),
/// judged against the bytes the caller holds of the account's own file
/// (C2), never the installed copy, which may be another account's, nor a
/// second read of that file.
fn combined_current(paths: &Paths, combined: &str, token: &str) -> bool {
    use crate::bridge::setup_token::{combined_judged, file_sha256, text_sha256, CombinedState};
    combined_judged(combined, file_sha256(&paths.aws_env()).as_deref(), Some(&text_sha256(token)), "the account's file") == CombinedState::Current
}

/// `write_atomic`'s fixed temp file beside `path` (`.<file>.tmp`, opened
/// `O_EXCL`): a leftover one fails every write of `path` after it. Only a
/// holder of the store's lock may clear one: where every writer of `path`
/// holds it (the installed pair, and slice A's seals into
/// `credentials/accounts/`), a leftover is a dead holder's.
pub(crate) fn temp_beside(path: &Path) -> PathBuf {
    let name = path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    path.with_file_name(format!(".{name}.tmp"))
}

// ---- reconcile ----------------------------------------------------------------------------

/// What [`reconcile`] found, and left.
#[derive(Debug, Clone, Default)]
pub struct View {
    /// The store as it now stands.
    pub state: AccountsState,
    /// Does `state/accounts.toml` exist? A tree with nothing sealed has none.
    pub stored: bool,
    /// The sealed account files, by name, as read (an adopted one included).
    pub files: Vec<AccountFile>,
    /// The seal id of the installed `credentials/setup-token.env`, when it
    /// holds a container.
    pub installed: Option<String>,
    /// The legacy `setup-token.env` this call adopted, if it did.
    pub adopted: Option<Adopted>,
    /// Did this call write anything?
    pub written: bool,
}

/// A legacy `setup-token.env` adopted as [`DEFAULT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adopted {
    pub tag: String,
    /// `copied` (its `combined.env` was current, and went with it), else what
    /// there was: `absent`, `stale` or `not-sealed`.
    pub combined: &'static str,
}

/// An adoption due: the installed `combined.env` text that goes with the
/// token when it is current, else the word for what there is.
struct Adoption {
    combined: std::result::Result<String, &'static str>,
}

/// What the tree holds, and the store it calls for: taken without the lock,
/// then again under it before anything is written.
struct Survey {
    stored: Option<AccountsState>,
    /// The account files, an adoption's [`DEFAULT`] included.
    files: Vec<AccountFile>,
    installed: Option<String>,
    adopt: Option<Adoption>,
    desired: AccountsState,
}

impl Survey {
    fn take(paths: &Paths) -> Result<Survey> {
        let stored = read(paths).map_err(|e| CliError::Msg(unreadable(&e)))?;
        let mut files = account_files(paths).map_err(CliError::Msg)?;
        let installed = read_sealed(&paths.setup_token_env()).ok();
        let adopt = match (&installed, files.is_empty()) {
            (Some(text), true) => adoption(paths, text)?,
            _ => None,
        };
        if let (Some(_), Some(text)) = (&adopt, &installed) {
            files.push(AccountFile::of(DEFAULT, text.clone()));
        }
        let installed = installed.as_deref().map(tag_of);
        let mut desired = desired(stored.as_ref(), &files, installed.as_deref());
        if adopt.is_some() {
            // An adopted DEFAULT is a new account: no note, whatever a stale row of that name said, and nothing from a
            // row of its bytes (`moved_from`): a usage under DEFAULT that the store never had came from one.
            desired.account.iter_mut().filter(|r| r.name == DEFAULT).for_each(|r| r.note = None);
            if stored.as_ref().is_none_or(|s| !s.usage.contains_key(DEFAULT)) {
                desired.usage.remove(DEFAULT);
            }
        }
        Ok(Survey { stored, files, installed, adopt, desired })
    }

    fn changes(&self) -> Result<bool> {
        Ok(self.adopt.is_some() || differs(self.stored.as_ref(), &self.desired).map_err(CliError::Msg)?)
    }

    fn view(self, written: bool, adopted: Option<Adopted>) -> View {
        View { stored: self.stored.is_some() || written, state: self.desired, files: self.files, installed: self.installed, adopted, written }
    }
}

/// Whether the sealed `setup-token.env` read as `token` is adopted, in a
/// tree with no account file: when `accounts/default.env` is free. Something
/// other than a container there (a link, a plaintext file) refuses (exit 5),
/// never replaced: it may hold a token in the clear.
fn adoption(paths: &Paths, token: &str) -> Result<Option<Adoption>> {
    let target = paths.account_env(DEFAULT);
    match aws_env_state(&target) {
        AwsEnvState::Absent => {}
        // Sealed since the files were listed: an account now, nothing to adopt.
        AwsEnvState::Sealed => return Ok(None),
        AwsEnvState::NotSealed(why) => {
            return Err(CliError::AuthUnavailable(format!(
                "{} {why}: move it away (and revoke what it holds), then the sealed setup-token.env is adopted as Claude account {DEFAULT}",
                target.display()
            )))
        }
    }
    let combined = match read_sealed(&paths.combined_env()) {
        Ok(text) if combined_current(paths, &text, token) => Ok(text),
        Ok(_) => Err("stale"),
        Err(AwsEnvState::Absent) => Err("absent"),
        Err(_) => Err("not-sealed"),
    };
    Ok(Some(Adoption { combined }))
}

/// The store the files call for: a row per file, `active` the account whose
/// seal is installed (the one already active, when several hold it), and the
/// usage of the names that keep a row with the seal their row had (one
/// sealed anew may be another login, C9: what was seen of it goes). A row
/// keeps the note its name's row had, sealed anew or not: a note is the
/// user's word on the name, not on a seal. A file that moved outside the
/// store ([`moved_from`]) is that row's account by another name: its row
/// takes the old row's note, its usage (unless the new name has its own)
/// and `active`, as [`rename`] would have.
fn desired(stored: Option<&AccountsState>, files: &[AccountFile], installed: Option<&str>) -> AccountsState {
    let moved: Vec<(&str, &AccountRow)> = files.iter().filter_map(|f| Some((f.name.as_str(), moved_from(stored?, files, f)?))).collect();
    let from = |name: &str| moved.iter().find(|(to, _)| *to == name).map(|(_, r)| *r);
    let note = |name: &str| stored.and_then(|s| s.account.iter().find(|r| r.name == name).or_else(|| from(name))?.note.clone());
    let account: Vec<AccountRow> = files.iter().map(|f| AccountRow { note: note(&f.name), ..f.row() }).collect();
    let was = stored.and_then(|s| s.active.as_deref()).map(|a| moved.iter().find(|(_, r)| r.name == a).map_or(a, |(to, _)| *to));
    let holders = || account.iter().filter(|r| Some(r.tag.as_str()) == installed);
    let active = holders().find(|r| Some(r.name.as_str()) == was).or_else(|| holders().next()).map(|r| r.name.clone());
    let kept = |s: &AccountsState, name: &str| account.iter().find(|r| r.name == name).is_some_and(|now| s.account.iter().find(|r| r.name == name).is_none_or(|then| then.tag == now.tag));
    let mut usage: BTreeMap<String, toml::Value> = stored.map(|s| s.usage.iter().filter(|(name, _)| kept(s, name)).map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
    for (to, r) in &moved {
        if let Some(v) = stored.and_then(|s| s.usage.get(&r.name)) {
            usage.entry((*to).to_string()).or_insert_with(|| v.clone());
        }
    }
    AccountsState { active, account, usage }
}

/// The stored row `file` moved from, when it is that account's file by
/// another name, moved outside the store (a [`rename`] stopped between its
/// account file's move and its store write, a `mv` by hand): no stored row
/// has the file's name, and the one stored row with its seal id (the same
/// bytes, so the same account) whose name has no file left is claimed by no
/// other file without a row. One to one, never a guess.
fn moved_from<'a>(stored: &'a AccountsState, files: &[AccountFile], file: &AccountFile) -> Option<&'a AccountRow> {
    let rowless = |f: &AccountFile| !stored.account.iter().any(|r| r.name == f.name);
    if !rowless(file) || files.iter().filter(|f| f.tag == file.tag && rowless(f)).count() != 1 {
        return None;
    }
    let mut gone = stored.account.iter().filter(|r| r.tag == file.tag && !files.iter().any(|f| f.name == r.name));
    let row = gone.next()?;
    gone.next().is_none().then_some(row)
}

/// Bring the store in line with the files (C10: every credential writer
/// runs it first): (a) adopt a sealed legacy `setup-token.env` as
/// [`DEFAULT`] when there is no account file, by byte copy (its seal id
/// unchanged), its `combined.env` too when current, audited
/// `creds_account_adopt`; (b) rebuild the rows from the files, each
/// keeping its note, a file moved outside the store taking its old row's
/// note and usage (`moved_from`; an adopted [`DEFAULT`] takes none); (c) set
/// `active` to the account whose seal is installed (none for nothing
/// installed, or a foreign seal); (d) prune the usage of names without a
/// row, and of an account sealed anew since its row was written. It works
/// out what to do without the lock and returns when nothing is to change:
/// it then writes nothing, not even the lock file. Otherwise it takes the
/// lock, works it out again, and writes. A store that cannot be read is
/// never written (exit 1, [`unreadable`]).
///
/// An adoption copies `combined.env` first and `accounts/default.env` last,
/// then audits: that file is an account, which ends adoption for good, so
/// one that fails before it (a full disk, a link where a copy goes, a kill)
/// leaves the next call to adopt again, whole. A combined copy left behind
/// alone is no account file ([`account_files`]): the next adoption replaces
/// it when it has one to copy, and an install copies it only while it is
/// current.
pub fn reconcile(paths: &Paths) -> Result<View> {
    let first = Survey::take(paths)?;
    if !first.changes()? {
        return Ok(first.view(false, None));
    }
    let held = lock(paths).map_err(CliError::Msg)?;
    let now = Survey::take(paths)?;
    let mut adopted = None;
    if let Some(a) = &now.adopt {
        let file = now.files.iter().find(|f| f.name == DEFAULT).ok_or_else(|| CliError::Msg("the adopted account is missing".into()))?;
        crate::bridge::creds::ensure_private_dir(&paths.credentials())?;
        crate::bridge::creds::ensure_private_dir(&paths.accounts_dir())?;
        let combined = match &a.combined {
            Ok(text) => {
                crate::store::write_atomic(&paths.account_combined_env(DEFAULT), text.as_bytes())?;
                "copied"
            }
            Err(word) => *word,
        };
        crate::store::write_atomic(&paths.account_env(DEFAULT), file.text.as_bytes())?;
        let row = audit::AuditRow::new(audit_event::ADOPT, None, audit::detail(&[("name", DEFAULT.into()), ("tag", file.tag.clone()), ("combined", combined.into())]));
        if let Err(e) = audit::append(&paths.audit(), &row) {
            voice::warn(&format!("the audit row creds_account_adopt was not written: {e}"));
        }
        adopted = Some(Adopted { tag: file.tag.clone(), combined });
    }
    let written = write_if_changed(paths, &held, now.stored.as_ref(), &now.desired).map_err(CliError::Msg)?;
    let written = written || adopted.is_some();
    Ok(now.view(written, adopted))
}

// ---- labels -------------------------------------------------------------------------------

/// The account `tag` is, for rows, records and notes (L-2: labels fail
/// open). `None` in a tree with no account at all (the legacy one: no row,
/// no account file); else the account whose row, then whose file, has that
/// seal; else [`UNKNOWN`]: a seal no account holds, or any seal while the
/// store or `credentials/accounts/` cannot be read.
#[must_use]
pub fn label(paths: &Paths, tag: &str) -> Option<String> {
    let Ok(stored) = read(paths) else { return Some(UNKNOWN.into()) };
    let rows = stored.as_ref().map_or(&[][..], |s| s.account.as_slice());
    if let Some(r) = rows.iter().find(|r| r.tag == tag && valid_name(&r.name)) {
        return Some(r.name.clone());
    }
    let Ok(files) = account_files(paths) else { return Some(UNKNOWN.into()) };
    if let Some(f) = files.iter().find(|f| f.tag == tag) {
        return Some(f.name.clone());
    }
    (!rows.is_empty() || !files.is_empty()).then(|| UNKNOWN.to_string())
}

/// Every seal an account holds or held, to (name, current): its file's and
/// its row's (current, unless its file now holds another), and its backups'
/// (`accounts/<name>.env.<unix>.bak`, older seals), so a VM that received an
/// older seal is named too. A seal two accounts share goes to a current
/// one, then to the first name. `Err` when the store or
/// `credentials/accounts/` cannot be read: a reader shows [`UNKNOWN`] then,
/// a writer refuses.
pub fn tag_index(paths: &Paths) -> std::result::Result<BTreeMap<String, (String, bool)>, String> {
    let stored = read(paths)?;
    let files = account_files(paths)?;
    let mut index: BTreeMap<String, (String, bool)> = BTreeMap::new();
    let mut put = |tag: &str, name: &str, current: bool| {
        let better = index.get(tag).is_none_or(|(n, c)| (current, std::cmp::Reverse(name)) > (*c, std::cmp::Reverse(n.as_str())));
        if better && !tag.is_empty() {
            index.insert(tag.to_string(), (name.to_string(), current));
        }
    };
    for f in &files {
        put(&f.tag, &f.name, true);
    }
    for r in stored.iter().flat_map(|s| &s.account).filter(|r| valid_name(&r.name)) {
        put(&r.tag, &r.name, files.iter().find(|f| f.name == r.name).is_none_or(|f| f.tag == r.tag));
    }
    for (name, tag) in backup_tags(paths)? {
        put(&tag, &name, false);
    }
    Ok(index)
}

/// Why no spawn can start for want of an account (L-2's one case): no
/// `credentials/setup-token.env` while accounts exist. `None` otherwise,
/// including a legacy tree, where today's "seal it with `ai-env creds
/// setup-token`" stands, and a store that cannot be read (it never blocks a
/// spawn).
#[must_use]
pub fn spawn_problem(paths: &Paths) -> Option<String> {
    if aws_env_state(&paths.setup_token_env()) != AwsEnvState::Absent {
        return None;
    }
    let rows = read(paths).ok().flatten().is_some_and(|s| !s.account.is_empty());
    (rows || account_files(paths).is_ok_and(|f| !f.is_empty())).then(|| NO_ACTIVE.to_string())
}

/// The `account list` summary of one account's raw `[usage.<name>]` entry
/// at `now` (unix seconds): [`usage::describe`] of it, read leniently
/// ([`usage::read_record`]); `None` when nothing was seen.
#[must_use]
pub fn usage_summary(v: &toml::Value, now: u64) -> Option<String> {
    usage::describe(&usage::read_record(v), now)
}

// ---- install ------------------------------------------------------------------------------

/// What became of `combined.env` at an install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CombinedInstall {
    /// The account's own was current (its notes record the account file's
    /// hash and aws.env's now): installed by byte copy.
    Installed,
    /// The account's own pairs another aws.env or token text, or is no
    /// container: none is installed, and a credentialed command asks for
    /// Touch ID twice until `make runtime-key` rebuilds it.
    Stale,
    /// The account has none: likewise.
    Absent,
    /// The account's own was current, but copying it failed (why is among
    /// [`Installed::warnings`]): likewise.
    Failed,
}

impl CombinedInstall {
    /// `installed`, `stale`, `absent` or `failed`: the word for audit rows
    /// and `--json`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            CombinedInstall::Installed => "installed",
            CombinedInstall::Stale => "stale",
            CombinedInstall::Absent => "absent",
            CombinedInstall::Failed => "failed",
        }
    }
}

/// What [`install`] did: the account is installed, whatever its warnings
/// say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The seal id of the bytes installed (the account file's).
    pub tag: String,
    pub combined: CombinedInstall,
    /// The account the replaced `setup-token.env` was, when it was one's:
    /// the one whose file holds that seal, else whose row names it, else
    /// whose backup holds it (the store's `active` first among several).
    pub from: Option<String>,
    /// Where the replaced seal was kept (`setup-token.env.<unix>.bak`) when
    /// no account's file or backup holds its bytes: a foreign seal, or one
    /// only a row still names.
    pub backup: Option<PathBuf>,
    /// What failed after the switch, one line each for the operator,
    /// without the `ai-env:` prefix: the combined copy
    /// ([`CombinedInstall::Failed`]), the store's row and `active` (which
    /// [`reconcile`] repairs). The caller audits and reports the switch
    /// all the same.
    pub warnings: Vec<String>,
}

/// [`install_held`], taking the store's lock around it.
pub fn install(paths: &Paths, name: &str) -> Result<Installed> {
    let held = lock(paths).map_err(CliError::Msg)?;
    install_held(paths, &held, name)
}

/// Make `name` the active account, the store's lock held: byte copies of
/// its files installed as `setup-token.env` and `combined.env`, in the order
/// that never pairs a token with another account's combined copy (remove
/// `combined.env`, write `setup-token.env`, then `combined.env` only when
/// the account's own is current), then the store's row and `active`. A
/// replaced seal whose bytes no account's file or backup holds is backed up
/// first ([`Installed::backup`]); an account's needs none.
///
/// `Err` means `setup-token.env` still holds what it held. Every refusal
/// comes before anything changes: a bad name (exit 2); an account file that
/// is absent (1) or not a container (5); a store that cannot be read (1,
/// [`unreadable`]); an installed `setup-token.env` that is a link or not a
/// container (5: it may hold a token in the clear); a link in place of
/// `credentials/` or its `accounts/` (1). A failure before the switch (the
/// backup, removing `combined.env`, writing `setup-token.env`) is exit 1 and
/// may leave `combined.env` removed: the safe direction, two Touch IDs until
/// `make runtime-key`. Once `setup-token.env` holds the account the result
/// is `Ok`, and what failed after it is among [`Installed::warnings`]. A
/// leftover temp file of either copy (`.setup-token.env.tmp`,
/// `.combined.env.tmp`) is cleared before its write, as the store's is
/// (`write_if_changed`): every writer of those two files holds this lock
/// (the installs, and slice A's `setup_token::install_built`), so a
/// leftover is a dead holder's, and would fail every install after it.
pub fn install_held(paths: &Paths, held: &StoreLock, name: &str) -> Result<Installed> {
    check_name(name)?;
    real_dir(&paths.accounts_dir()).map_err(CliError::Msg)?;
    let source = paths.account_env(name);
    let text = match read_sealed(&source) {
        Ok(text) => text,
        Err(AwsEnvState::NotSealed(why)) => {
            return Err(CliError::AuthUnavailable(format!("{} {why}: move it away (and revoke what it holds), then `ai-env creds account add {name}` seals it anew; nothing was installed", source.display())))
        }
        Err(_) => return Err(CliError::Msg(format!("{} does not exist: there is no Claude account {name}", source.display()))),
    };
    let stored = read(paths).map_err(|e| CliError::Msg(unreadable(&e)))?;
    let target = paths.setup_token_env();
    let replaced = match read_sealed(&target) {
        Ok(old) => Some(tag_of(&old)),
        Err(AwsEnvState::NotSealed(why)) => return Err(CliError::AuthUnavailable(format!("{} {why}: move it away (and revoke what it holds); nothing was installed", target.display()))),
        Err(_) => None,
    };
    crate::bridge::creds::ensure_private_dir(&paths.credentials())?;
    let files = account_files(paths).map_err(CliError::Msg)?;
    let (from, kept) = match &replaced {
        Some(tag) => held_by(paths, stored.as_ref(), &files, tag).map_err(CliError::Msg)?,
        None => (None, true),
    };
    let backup = if kept { None } else { Some(crate::bridge::creds::backup_existing(&target)?) };
    let removed = crate::bridge::registry::remove_if_present(&paths.combined_env())?;
    let written = crate::bridge::registry::remove_if_present(&temp_beside(&target)).map_err(CliError::from).and_then(|_| crate::store::write_atomic(&target, text.as_bytes()));
    written.map_err(|e| {
        let gone = if removed { ": combined.env is removed, so a credentialed command asks for Touch ID twice until `make runtime-key` rebuilds it" } else { "" };
        CliError::Msg(format!("Claude account {name} is not installed ({e}){gone}"))
    })?;
    // Switched: what fails from here on is a warning in the result, never an `Err`.
    let mut warnings = Vec::new();
    let combined = install_combined(paths, name, &text).unwrap_or_else(|e| {
        warnings.push(format!("Claude account {name} is installed without its combined.env ({e}): a credentialed command asks for Touch ID twice until `make runtime-key` rebuilds it"));
        CombinedInstall::Failed
    });
    let installed = AccountFile::of(name, text);
    let mut state = stored.clone().unwrap_or_default();
    match state.account.iter_mut().find(|r| r.name == name) {
        Some(row) => {
            // Sealed anew since its row was written: what was seen of it is another seal's (as `reconcile`).
            if row.tag != installed.tag {
                state.usage.remove(name);
            }
            *row = AccountRow { note: row.note.take(), ..installed.row() };
        }
        None => {
            state.account.push(installed.row());
            state.account.sort_by(|a, b| a.name.cmp(&b.name));
        }
    }
    state.active = Some(name.to_string());
    if let Err(e) = write_if_changed(paths, held, stored.as_ref(), &state) {
        warnings.push(format!("Claude account {name} is installed, but {} is not updated ({e}): `ai-env creds account list` repairs it", paths.accounts_state().display()));
    }
    Ok(Installed { tag: installed.tag, combined, from, backup, warnings })
}

/// Who held `tag`, the seal an install replaces, by [`tag_index`]'s
/// sources: the account to name for it (the one whose file holds it, else
/// whose row names it, else whose backup holds it; among several the
/// store's `active`, else the first name), and whether its bytes are kept
/// beside the installed copy, in an account's file or backup. A row keeps a
/// seal's id, never its container: a seal only a row names is backed up
/// all the same.
fn held_by(paths: &Paths, stored: Option<&AccountsState>, files: &[AccountFile], tag: &str) -> std::result::Result<(Option<String>, bool), String> {
    let was = stored.and_then(|s| s.active.as_deref());
    let pick = |mut names: Vec<&str>| {
        names.sort_unstable();
        names.iter().find(|n| Some(**n) == was).or(names.first()).map(|n| (*n).to_string())
    };
    if let Some(name) = pick(files.iter().filter(|f| f.tag == tag).map(|f| f.name.as_str()).collect()) {
        return Ok((Some(name), true));
    }
    let backups = backup_tags(paths)?;
    let in_backup = pick(backups.iter().filter(|(_, t)| t == tag).map(|(n, _)| n.as_str()).collect());
    let in_row = pick(stored.iter().flat_map(|s| &s.account).filter(|r| r.tag == tag && valid_name(&r.name)).map(|r| r.name.as_str()).collect());
    let kept = in_backup.is_some();
    Ok((in_row.or(in_backup), kept))
}

/// [`install_held`]'s last copy: `accounts/<name>.combined.env`, read once,
/// installed as `combined.env` when it is current for `token` (the bytes
/// just installed) and aws.env now. `Err`: that copy failed, and none is
/// installed ([`CombinedInstall::Failed`]).
fn install_combined(paths: &Paths, name: &str, token: &str) -> Result<CombinedInstall> {
    match read_sealed(&paths.account_combined_env(name)) {
        Ok(combined) if combined_current(paths, &combined, token) => {
            crate::bridge::registry::remove_if_present(&temp_beside(&paths.combined_env()))?;
            crate::store::write_atomic(&paths.combined_env(), combined.as_bytes())?;
            Ok(CombinedInstall::Installed)
        }
        Ok(_) | Err(AwsEnvState::NotSealed(_)) => Ok(CombinedInstall::Stale),
        Err(_) => Ok(CombinedInstall::Absent),
    }
}

// ---- note and rename ----------------------------------------------------------------------

/// What [`set_note`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteChange {
    /// The account has the note given (it had none, or another).
    Set,
    /// Its note is removed.
    Cleared,
    /// It had that note already, or none to clear: nothing was written.
    Unchanged,
}

impl NoteChange {
    /// `set`, `cleared` or `unchanged`: the word for audit rows and `--json`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            NoteChange::Set => "set",
            NoteChange::Cleared => "cleared",
            NoteChange::Unchanged => "unchanged",
        }
    }
}

/// Give Claude account `name` the note `note` (trimmed, [`check_note`]), or
/// clear it (`None`). No Touch ID: a note is the store's alone, never the
/// sealed file's, whose bytes (so seal id) it never touches. Refusals come
/// before anything is written: a bad name or note (exit 2, the note
/// described, never echoed); no sealed `credentials/accounts/<name>.env`
/// (1); a store that cannot be read (1, [`unreadable`]). The tree is
/// reconciled first (C10: an adoption, the rows), then the row is set under
/// the store's lock (made from the file, should a writer have raced the
/// reconcile). A change is audited `creds_account_note` with `name` and
/// `set` (`set` or `cleared`), never the text.
pub fn set_note(paths: &Paths, name: &str, note: Option<&str>) -> Result<NoteChange> {
    check_name(name)?;
    let note = note.map(check_note).transpose()?;
    reconcile(paths)?;
    let held = lock(paths).map_err(CliError::Msg)?;
    real_dir(&paths.accounts_dir()).map_err(CliError::Msg)?;
    let path = paths.account_env(name);
    let file = match read_sealed(&path) {
        Ok(text) => AccountFile::of(name, text),
        Err(AwsEnvState::NotSealed(why)) => return Err(CliError::Msg(format!("{} {why}: there is no Claude account {name}", path.display()))),
        Err(_) => return Err(CliError::Msg(format!("{} does not exist: there is no Claude account {name}", path.display()))),
    };
    let change = update_held(paths, &held, |s| {
        if !s.account.iter().any(|r| r.name == name) {
            s.account.push(file.row());
            s.account.sort_by(|a, b| a.name.cmp(&b.name));
        }
        let mut change = NoteChange::Unchanged;
        for row in s.account.iter_mut().filter(|r| r.name == name && r.note != note) {
            change = if note.is_some() { NoteChange::Set } else { NoteChange::Cleared };
            row.note.clone_from(&note);
        }
        change
    })
    .map_err(CliError::Msg)?;
    if change != NoteChange::Unchanged {
        let row = audit::AuditRow::new(audit_event::NOTE, None, audit::detail(&[("name", name.into()), ("set", change.word().into())]));
        if let Err(e) = audit::append(&paths.audit(), &row) {
            voice::warn(&format!("the audit row {} was not written: {e}", audit_event::NOTE));
        }
    }
    Ok(change)
}

/// What [`rename`] did: the account has its new name, whatever its
/// warnings say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renamed {
    /// Its seal id, the same: the files keep their bytes.
    pub tag: String,
    /// It was the active account (its seal is the installed one): it still
    /// is, by the new name, the installed copies untouched.
    pub was_active: bool,
    /// The files renamed, by their new paths, in the order renamed: the
    /// combined copy, the backups, the account file last. A rename run again
    /// after one stopped midway lists what it moved itself.
    pub moved: Vec<PathBuf>,
    /// What failed once the account file had its new name, one line each
    /// for the operator, without the `ai-env:` prefix, as
    /// [`Installed::warnings`]: the store (which [`reconcile`] rebuilds from
    /// the files, the old row's note and usage carried) and the audit row.
    pub warnings: Vec<String>,
}

/// [`rename_held`], the tree reconciled first (C10) and the store's lock
/// taken around it.
pub fn rename(paths: &Paths, old: &str, new: &str) -> Result<Renamed> {
    check_name(old)?;
    check_name(new)?;
    reconcile(paths)?;
    let held = lock(paths).map_err(CliError::Msg)?;
    rename_held(paths, &held, old, new)
}

/// Rename Claude account `old` to `new`, the store's lock held. No Touch ID:
/// the sealed bytes never change, so neither does the seal id, and all that
/// is keyed by it stays as it is: the installed copies (`setup-token.env`,
/// `combined.env`), the refusal record, the VM caches; labels name the
/// account `new` at once. Each container's `account=` keeps the name it was
/// sealed under (the module's doc).
///
/// The files go by rename(2) within `credentials/accounts/` (atomic per
/// file, never a copy, each target checked free first: rename(2) would
/// replace it), in an order a crash leaves whole: (a) `<old>.combined.env`;
/// (b) the backups, `<old>.env.<unix>.bak` and
/// `<old>.combined.env.<unix>.bak`; (c) `<old>.env` last, the file whose
/// name is the account's; then (d) the store (the row with its note,
/// `active` when it was `old`, `usage.<old>`), worked out before the first
/// move; (e) the audit row `creds_account_rename` (`from`, `to`, `tag`).
/// Killed before (c), the account is still `old`, the files moved so far
/// under the new name: the same rename run again finishes it, counting as
/// moved a combined copy or backup of the new name whose `<old>` one is
/// gone, while there is no `<new>.env` and no row of `new`. Killed between
/// (c) and (d), it is `new`, and [`reconcile`] gives its row the old row's
/// note, usage and `active` (a file moved outside the store: `moved_from`).
/// No file ever has two names.
///
/// Refusals come before anything is renamed: a bad name (exit 2); no
/// `<old>.env` (1), or one that is not a sealed regular file (5); a store
/// that cannot be read (1, [`unreadable`]); a link or non-regular file among
/// the files to move or named `<new>.…` (5); `<new>.env` or a row of `new`
/// (1: the account exists); any other file so named that is not one moved
/// already (1: it is in the way); a link in place of `accounts/` (1). A move
/// that fails midway puts back what it moved: `Err` means the account keeps
/// its name. Once `<new>.env` is in place the result is `Ok`, and what
/// failed after it is among [`Renamed::warnings`].
pub fn rename_held(paths: &Paths, held: &StoreLock, old: &str, new: &str) -> Result<Renamed> {
    check_name(old)?;
    check_name(new)?;
    let dir = paths.accounts_dir();
    real_dir(&dir).map_err(CliError::Msg)?;
    let stored = read(paths).map_err(|e| CliError::Msg(unreadable(&e)))?;
    let source = paths.account_env(old);
    let text = match read_sealed(&source) {
        Ok(text) => text,
        Err(AwsEnvState::NotSealed(why)) => return Err(CliError::AuthUnavailable(format!("{} {why}: move it away (and revoke what it holds); nothing was renamed", source.display()))),
        Err(_) => return Err(CliError::Msg(format!("{} does not exist: there is no Claude account {old}", source.display()))),
    };
    let mut listed = entries(paths).map_err(CliError::Msg)?;
    listed.sort();
    // An account's files are the entries named `<name>.…`, and no other's: a name never holds a `.`.
    let of = |name: &str, file: &str| file.strip_prefix(name)?.strip_prefix('.').map(str::to_string);
    let unix_bak = |rest: &str| rest.strip_suffix(".bak").is_some_and(|u| !u.is_empty() && u.bytes().all(|b| b.is_ascii_digit()));
    // What a rename moves besides the account file: the combined copy and the backups.
    let moves = |rest: &str| rest == "combined.env" || rest.strip_prefix("env.").or_else(|| rest.strip_prefix("combined.env.")).is_some_and(unix_bak);
    let listed_as = |file: String| listed.iter().any(|(f, _)| *f == file);
    let (new_file, new_row) = (listed_as(format!("{new}.env")), stored.iter().flat_map(|s| &s.account).any(|r| r.name == new));
    // A rename stopped before its account file moved left files of the new name whose old ones are gone: this
    // one, run again, counts them as moved. Never beside an account `new` (its file, its row).
    let moved_before = |rest: &str| moves(rest) && !new_file && !new_row && !listed_as(format!("{old}.{rest}"));
    let (mut taken, mut resumed, mut combined, mut backups) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (file, path) in &listed {
        if let Some(rest) = of(new, file) {
            if moved_before(&rest) {
                resumed.push(path.clone());
            } else {
                taken.push(path.clone());
            }
        } else if let Some(rest) = of(old, file) {
            let to = dir.join(format!("{new}.{rest}"));
            if rest == "combined.env" {
                combined.push((path.clone(), to));
            } else if moves(&rest) {
                backups.push((path.clone(), to));
            }
        }
    }
    let plan: Vec<(PathBuf, PathBuf)> = combined.into_iter().chain(backups).chain([(source, paths.account_env(new))]).collect();
    let odd = |path: &Path| match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Some("is a symlink"),
        Ok(m) if !m.is_file() => Some("is not a regular file"),
        _ => None,
    };
    if let Some((path, why)) = taken.iter().chain(&resumed).chain(plan.iter().map(|(from, _)| from)).find_map(|p| odd(p).map(|why| (p, why))) {
        return Err(CliError::AuthUnavailable(format!("{} {why}: move it away (and revoke what it holds); nothing was renamed", path.display())));
    }
    if new_file {
        return Err(CliError::Msg(format!("a Claude account {new} exists ({}): nothing was renamed", paths.account_env(new).display())));
    }
    if new_row {
        return Err(CliError::Msg(format!("a Claude account {new} exists (its row in {}): nothing was renamed", paths.accounts_state().display())));
    }
    if let Some(path) = taken.first() {
        return Err(CliError::Msg(format!("{} is in the way of the name {new} (there is no Claude account {new}): move it away, then rename again; nothing was renamed", path.display())));
    }
    // (d) worked out first: the files as they will be, the stored names moved.
    let tag = tag_of(&text);
    let mut files = account_files(paths).map_err(CliError::Msg)?;
    files.retain(|f| f.name != old);
    files.push(AccountFile::of(new, text));
    files.sort_by(|a, b| a.name.cmp(&b.name));
    let mut renamed = stored.clone().unwrap_or_default();
    for r in renamed.account.iter_mut().filter(|r| r.name == old) {
        new.clone_into(&mut r.name);
    }
    if renamed.active.as_deref() == Some(old) {
        renamed.active = Some(new.to_string());
    }
    renamed.usage.remove(new);
    if let Some(usage) = renamed.usage.remove(old) {
        renamed.usage.insert(new.to_string(), usage);
    }
    let installed = read_sealed(&paths.setup_token_env()).ok().map(|t| tag_of(&t));
    let after = desired(Some(&renamed), &files, installed.as_deref());
    move_in_order(&plan).map_err(|e| CliError::Msg(format!("Claude account {old} keeps its name: {e}")))?;
    // Renamed: what fails from here on is a warning in the result, never an `Err`. The new names reach the disk
    // before the store says them.
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    let mut warnings = Vec::new();
    if let Err(e) = write_if_changed(paths, held, stored.as_ref(), &after) {
        warnings.push(format!("Claude account {old} is renamed {new}, but {} is not updated ({e}): `ai-env creds account list` rebuilds it from the files, {old}'s note and usage carried", paths.accounts_state().display()));
    }
    let row = audit::AuditRow::new(audit_event::RENAME, None, audit::detail(&[("from", old.into()), ("to", new.into()), ("tag", tag.clone())]));
    if let Err(e) = audit::append(&paths.audit(), &row) {
        warnings.push(format!("the audit row {} was not written: {e}", audit_event::RENAME));
    }
    Ok(Renamed { tag, was_active: after.active.as_deref() == Some(new), moved: plan.into_iter().map(|(_, to)| to).collect(), warnings })
}

/// Rename each `(from, to)` of `plan` in order by rename(2), each `to`
/// checked free first (rename(2) would replace it). On a failure what was
/// moved is put back, last first, the same way: `Err` says why, and what
/// could not be put back.
fn move_in_order(plan: &[(PathBuf, PathBuf)]) -> std::result::Result<(), String> {
    let step = |from: &Path, to: &Path| match std::fs::symlink_metadata(to) {
        Err(e) if e.kind() == ErrorKind::NotFound => std::fs::rename(from, to).map_err(|e| format!("{} cannot be renamed ({e})", from.display())),
        Ok(_) => Err(format!("{} exists", to.display())),
        Err(e) => Err(format!("cannot stat {}: {e}", to.display())),
    };
    for (i, (from, to)) in plan.iter().enumerate() {
        if let Err(why) = step(from, to) {
            let stuck: Vec<String> = plan[..i].iter().rev().filter_map(|(from, to)| step(to, from).err()).collect();
            return Err(if stuck.is_empty() { format!("{why}; nothing was renamed") } else { format!("{why}; putting back what was moved failed ({}): move those back by hand", stuck.join("; ")) });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    const BLOB: &[u8] = b"age-encryption.org/v1\n-> x\n--- y\n";

    /// A sealed setup-token container; `n` tells the bytes, so the seal id, apart.
    fn token(n: &str) -> String {
        container::write_annotated(BLOB, &[("kind", "setup-token"), ("chars", n), ("sealed", "2026-10-07T08:00:00Z")]).unwrap()
    }

    /// A combined container recording the aws.env and setup-token texts it pairs.
    fn combined(aws: &str, token: &str) -> String {
        use crate::bridge::setup_token::text_sha256;
        container::write_annotated(BLOB, &[("kind", "combined"), ("parts", "aws,setup-token"), ("aws_file_sha256", &text_sha256(aws)), ("token_file_sha256", &text_sha256(token))]).unwrap()
    }

    fn put(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn bytes(path: &Path) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A bridge root under `d` with a sealed aws.env (its text returned).
    fn tree(d: &Path) -> (Paths, String) {
        let paths = Paths::from_root_and_env(d.join("bridge"), None);
        let aws = container::write_annotated(BLOB, &[("kind", "aws")]).unwrap();
        put(&paths.aws_env(), &aws);
        (paths, aws)
    }

    /// Account `name` sealed as [`token`]`(n)`, with a current combined when `with_combined`.
    fn account(paths: &Paths, aws: &str, name: &str, n: &str, with_combined: bool) -> String {
        let t = token(n);
        put(&paths.account_env(name), &t);
        if with_combined {
            put(&paths.account_combined_env(name), &combined(aws, &t));
        }
        t
    }

    fn adopt_rows(paths: &Paths) -> Vec<serde_json::Value> {
        crate::bridge::audit::read_rows(&paths.audit(), None).unwrap().into_iter().filter(|r| r["event"] == "creds_account_adopt").collect()
    }

    #[test]
    fn account_names_follow_their_rule_and_name_their_files() {
        for ok in ["default", "a", "0", "work-2", "a_b", "9lives", &"x".repeat(32)] {
            assert!(valid_name(ok) && check_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-a", "_a", "A", "Work", "a.b", "a b", "a/b", "..", "é", "a\n", "unknown", &"x".repeat(33)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        let e = check_name("Work").unwrap_err();
        assert_eq!(e.exit_code(), 2, "{e}");
        assert_eq!(e.to_string(), "\"Work\" is not a Claude account name (1-32 of a-z 0-9 _ -, the first a letter or a digit, not `unknown`)");
        // A token pasted in a name's place is never echoed.
        let pasted = format!("sk-ant-oat01-{}", "Qz7_".repeat(24));
        let e = check_name(&pasted).unwrap_err();
        assert!(e.exit_code() == 2 && !e.to_string().contains(&pasted) && e.to_string().starts_with(&format!("a name of {} characters is not", pasted.len())), "{} bytes said", e.to_string().len());
        let paths = Paths::from_root_and_env(PathBuf::from("/b"), None);
        assert_eq!(paths.accounts_dir(), Path::new("/b/credentials/accounts"));
        assert_eq!(paths.account_env("work"), Path::new("/b/credentials/accounts/work.env"));
        assert_eq!(paths.account_combined_env("work"), Path::new("/b/credentials/accounts/work.combined.env"));
        assert_eq!(paths.accounts_state(), Path::new("/b/state/accounts.toml"));
        assert_eq!(lock_path(&paths), Path::new("/b/state/accounts.toml.lock"));
    }

    /// The store reads what it writes, keeps raw usage it does not
    /// understand (a malformed entry included), is written only when it
    /// changes (a hand-formatted one keeps its bytes), and an empty store is
    /// never created.
    #[test]
    fn the_store_round_trips_and_keeps_its_usage() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        assert_eq!(read(&paths), Ok(None));
        assert_eq!(update(&paths, |s| s.active.clone()), Ok(None));
        assert!(!paths.accounts_state().exists(), "nothing put in it: none created");
        assert_eq!(render(&AccountsState::default()).unwrap(), "");
        let text = "active = \"work\"\n\n[[account]]\nname = \"default\"\ntag = \"3f9c0a1b2c3d4e5f\"\nsealed = \"2026-10-07T08:00:00Z\"\n\n[[account]]\nname = \"work\"\ntag = \"a1b2c3d4e5f60718\"\n\n[usage]\ndefault = 5\n\n[usage.work]\nseen_at = 1792569600\nsource = \"chat\"\nstatus = \"allowed_warning\"\nfive_hour = { utilization = 0.42, resets_at = 1792584000 }\n\n[usage.work.limited]\nat = 1792569600\ntext = \"weekly\"\nkinds = [\"seven_day\", 2]\n";
        put(&paths.accounts_state(), text);
        let state = read(&paths).unwrap().unwrap();
        assert_eq!(state.active.as_deref(), Some("work"));
        assert_eq!(state.account, [
            AccountRow { name: "default".into(), tag: "3f9c0a1b2c3d4e5f".into(), sealed: Some("2026-10-07T08:00:00Z".into()), note: None },
            AccountRow { name: "work".into(), tag: "a1b2c3d4e5f60718".into(), sealed: None, note: None },
        ]);
        assert_eq!(state.usage["default"], toml::Value::Integer(5), "a malformed entry is kept as it is");
        assert_eq!(state.usage["work"]["five_hour"]["utilization"].as_float(), Some(0.42));
        assert_eq!(update(&paths, |s| s.account.len()), Ok(2));
        assert_eq!(std::fs::read_to_string(paths.accounts_state()).unwrap(), text, "unchanged: not rewritten");
        update(&paths, |s| s.active = Some("default".into())).unwrap();
        let again = read(&paths).unwrap().unwrap();
        assert_eq!((again.active.as_deref(), &again.account, &again.usage), (Some("default"), &state.account, &state.usage), "only active changed");
        assert_eq!(render(&again).unwrap(), std::fs::read_to_string(paths.accounts_state()).unwrap());
        assert_eq!(mode(&paths.accounts_state()), 0o600);
        assert_eq!(mode(paths.accounts_state().parent().unwrap()), 0o700);
        assert_eq!(usage_summary(&again.usage["work"], 1_792_569_600).as_deref(), Some("limited, \"weekly\"; near its usage limit; seen 0 s ago in a chat"), "slice B's describe, read leniently");
    }

    /// L-2: a store that cannot be read (broken TOML, a link) is never
    /// written by any writer (update, try_update, reconcile, install), and
    /// every label reads `unknown` meanwhile; the error is on one line and
    /// carries the repair hint.
    #[test]
    fn an_unreadable_store_is_never_written_and_its_labels_read_unknown() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let a = account(&paths, &aws, "a", "1", true);
        reconcile(&paths).unwrap();
        assert_eq!(label(&paths, &tag_of(&a)).as_deref(), Some("a"));
        let mut broken = std::fs::read(paths.accounts_state()).unwrap();
        broken.extend_from_slice(b"\n[[account]\n");
        std::fs::write(paths.accounts_state(), &broken).unwrap();
        let why = read(&paths).unwrap_err();
        assert!(why.starts_with(&format!("{} cannot be parsed (", paths.accounts_state().display())) && !why.contains('\n'), "{why}");
        let e = update(&paths, |s| s.active = None).unwrap_err();
        assert!(e.contains("cannot be parsed") && e.ends_with("Claude account names are unknown; remove it, and `ai-env creds account list` rebuilds it from credentials/accounts/ (without its usage)"), "{e}");
        assert_eq!(try_update(&paths, |s| s.active = None), Ok(TryUpdate::Unreadable));
        let e = reconcile(&paths).unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("Claude account names are unknown"), "{e}");
        let e = install(&paths, "a").unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("remove it, and `ai-env creds account list` rebuilds it"), "{e}");
        assert!(!paths.setup_token_env().exists(), "nothing installed");
        assert_eq!(std::fs::read(paths.accounts_state()).unwrap(), broken, "left as it was");
        assert_eq!(label(&paths, &tag_of(&a)).as_deref(), Some(UNKNOWN), "labels fail open");
        assert_eq!(Seal::of(&paths, tag_of(&a)), Seal { tag: tag_of(&a), account: Some(UNKNOWN.into()) });
        assert!(tag_index(&paths).is_err());
        assert_eq!(spawn_problem(&paths).as_deref(), Some(NO_ACTIVE), "the files still say accounts exist");
        std::fs::remove_file(paths.accounts_state()).unwrap();
        let elsewhere = d.path().join("elsewhere.toml");
        std::os::unix::fs::symlink(&elsewhere, paths.accounts_state()).unwrap();
        assert!(read(&paths).unwrap_err().contains("symlink"));
        assert!(update(&paths, |s| s.active = None).unwrap_err().contains("symlink"));
        assert_eq!(try_update(&paths, |s| s.active = None), Ok(TryUpdate::Unreadable));
        assert!(reconcile(&paths).is_err());
        assert_eq!(label(&paths, &tag_of(&a)).as_deref(), Some(UNKNOWN));
        assert!(std::fs::symlink_metadata(paths.accounts_state()).unwrap().file_type().is_symlink() && !elsewhere.exists(), "nothing written through the link");
    }

    /// C11: writers at the same moment never undo each other: the read,
    /// change and write hold the store's lock.
    #[test]
    fn updates_made_at_once_are_all_kept() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let names: Vec<String> = (0..16).map(|i| format!("acct{i:02}")).collect();
        std::thread::scope(|s| {
            for (i, name) in names.iter().enumerate() {
                let paths = &paths;
                s.spawn(move || update(paths, |st| st.usage.insert(name.clone(), toml::Value::Integer(i64::try_from(i).unwrap()))).unwrap());
            }
        });
        let usage = read(&paths).unwrap().unwrap().usage;
        assert_eq!(usage.keys().collect::<Vec<_>>(), names.iter().collect::<Vec<_>>(), "every write is kept");
    }

    /// L-3: the pump's attempt never waits (`Busy` while the lock is held)
    /// and never creates the store, its directory or the lock beside none.
    #[test]
    fn a_try_never_waits_and_never_creates_the_store() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        assert_eq!(try_update(&paths, |s| s.active = Some("a".into())), Ok(TryUpdate::NoFile));
        assert!(!paths.root.join("state").exists(), "no store, no directory, no lock file");
        update(&paths, |s| s.active = Some("a".into())).unwrap();
        let held = lock(&paths).unwrap();
        let before = std::fs::read(paths.accounts_state()).unwrap();
        let t = std::time::Instant::now();
        assert_eq!(try_update(&paths, |s| s.active = Some("b".into())), Ok(TryUpdate::Busy));
        assert!(t.elapsed() < std::time::Duration::from_secs(1), "no wait");
        assert_eq!(std::fs::read(paths.accounts_state()).unwrap(), before);
        drop(held);
        assert_eq!(try_update(&paths, |_| {}), Ok(TryUpdate::Unchanged));
        assert_eq!(try_update(&paths, |s| s.active = Some("b".into())), Ok(TryUpdate::Written));
        assert_eq!(read(&paths).unwrap().unwrap().active.as_deref(), Some("b"));
        std::fs::remove_file(paths.accounts_state()).unwrap();
        assert_eq!(try_update(&paths, |s| s.active = Some("c".into())), Ok(TryUpdate::NoFile));
        assert!(!paths.accounts_state().exists(), "never recreated");
    }

    /// Adoption is a byte copy: `accounts/default.env` holds the very bytes
    /// of the legacy setup-token.env (the same seal id: refusals, VM caches
    /// and combined.env's hashes stay valid), and the current combined.env
    /// goes with it; one audit row, and a second pass changes nothing.
    #[test]
    fn a_legacy_token_is_adopted_by_byte_copy() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let t = token("108");
        put(&paths.setup_token_env(), &t);
        put(&paths.combined_env(), &combined(&aws, &t));
        let tag = tag_of(&t);
        assert_eq!((label(&paths, &tag), spawn_problem(&paths)), (None, None), "a legacy tree: no label, no problem");
        let v = reconcile(&paths).unwrap();
        assert_eq!(v.adopted, Some(Adopted { tag: tag.clone(), combined: "copied" }));
        assert!(v.written && v.stored && v.installed.as_deref() == Some(tag.as_str()), "{v:?}");
        assert_eq!(bytes(&paths.account_env(DEFAULT)), bytes(&paths.setup_token_env()), "a byte copy");
        assert_eq!(crate::bridge::agent::credential::seal_tag(&paths.account_env(DEFAULT)), Some(tag.clone()));
        assert_eq!(bytes(&paths.account_combined_env(DEFAULT)), bytes(&paths.combined_env()));
        assert_eq!(crate::bridge::setup_token::combined_state(&paths), crate::bridge::setup_token::CombinedState::Current, "the installed pair is untouched");
        let state = read(&paths).unwrap().unwrap();
        assert_eq!(state.account, [AccountRow { name: DEFAULT.into(), tag: tag.clone(), sealed: Some("2026-10-07T08:00:00Z".into()), note: None }]);
        assert_eq!(state.active.as_deref(), Some(DEFAULT));
        assert_eq!((mode(&paths.accounts_dir()), mode(&paths.account_env(DEFAULT)), mode(&paths.account_combined_env(DEFAULT))), (0o700, 0o600, 0o600));
        let rows = adopt_rows(&paths);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0]["detail"]["name"].as_str(), rows[0]["detail"]["tag"].as_str(), rows[0]["detail"]["combined"].as_str()), (Some(DEFAULT), Some(tag.as_str()), Some("copied")));
        let ino = std::fs::metadata(paths.accounts_state()).unwrap().ino();
        let v = reconcile(&paths).unwrap();
        assert!(v.adopted.is_none() && !v.written, "{v:?}");
        assert_eq!(std::fs::metadata(paths.accounts_state()).unwrap().ino(), ino, "not rewritten");
        assert_eq!(adopt_rows(&paths).len(), 1, "adopted once");
        assert_eq!(label(&paths, &tag).as_deref(), Some(DEFAULT));
    }

    /// A combined.env that is not current for the adopted token stays
    /// behind (none copied); there is nothing to adopt beside an account
    /// file, or in a tree with nothing sealed (which stays untouched); and a
    /// plaintext file where the copy goes is refused, never replaced.
    #[test]
    fn adoption_takes_a_combined_only_when_current_and_never_beside_an_account() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let t = token("1");
        put(&paths.setup_token_env(), &t);
        put(&paths.combined_env(), &combined(&aws, &token("other")));
        assert_eq!(reconcile(&paths).unwrap().adopted.map(|a| a.combined), Some("stale"));
        assert!(paths.account_env(DEFAULT).exists() && !paths.account_combined_env(DEFAULT).exists());
        let d = tempfile::tempdir().unwrap();
        let (paths, _) = tree(d.path());
        put(&paths.setup_token_env(), &token("1"));
        assert_eq!(reconcile(&paths).unwrap().adopted.map(|a| a.combined), Some("absent"));
        // An account already: the installed seal is a foreign one, never adopted.
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let work = account(&paths, &aws, "work", "w", false);
        put(&paths.setup_token_env(), &token("foreign"));
        let v = reconcile(&paths).unwrap();
        assert!(v.adopted.is_none() && v.state.active.is_none() && !paths.account_env(DEFAULT).exists(), "{v:?}");
        assert_eq!(v.state.account, [AccountRow { name: "work".into(), tag: tag_of(&work), sealed: Some("2026-10-07T08:00:00Z".into()), note: None }]);
        assert!(adopt_rows(&paths).is_empty());
        // Nothing sealed: nothing written, not even a directory.
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let v = reconcile(&paths).unwrap();
        assert!(!v.written && !v.stored && v.state == AccountsState::default(), "{v:?}");
        assert!(!paths.root.exists());
        // A plaintext file where the copy would go.
        let d = tempfile::tempdir().unwrap();
        let (paths, _) = tree(d.path());
        put(&paths.setup_token_env(), &token("1"));
        put(&paths.account_env(DEFAULT), "kept as it is\n");
        let e = reconcile(&paths).unwrap_err();
        assert!(e.exit_code() == 5 && e.to_string().contains("is not an ai-env container (plaintext?): move it away (and revoke what it holds)"), "{e}");
        assert_eq!(std::fs::read_to_string(paths.account_env(DEFAULT)).unwrap(), "kept as it is\n");
        assert!(!paths.accounts_state().exists());
    }

    /// The rows are rebuilt from the files (stale and orphaned rows go),
    /// `active` follows the installed copy (the one already active among
    /// accounts that share it), the usage of a name without a row, or of an
    /// account sealed anew, is pruned, and a store that already says all
    /// that is left alone: no write, and no lock file taken.
    #[test]
    fn reconcile_rebuilds_the_rows_from_the_files() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let a = account(&paths, &aws, "a", "1", false);
        let b = account(&paths, &aws, "b", "2", false);
        put(&paths.setup_token_env(), &a);
        let rows = format!("[[account]]\nname = \"a\"\ntag = \"{}\"\n[[account]]\nname = \"b\"\ntag = \"0000000000000000\"\n[[account]]\nname = \"c\"\ntag = \"1111111111111111\"\n", tag_of(&a));
        put(&paths.accounts_state(), &format!("active = \"b\"\n{rows}[usage.a]\nseen_at = 1\n[usage.b]\nseen_at = 2\n[usage.c]\nseen_at = 3\n"));
        let v = reconcile(&paths).unwrap();
        assert!(v.written && v.adopted.is_none());
        let state = read(&paths).unwrap().unwrap();
        assert_eq!(state.account.iter().map(|r| (r.name.as_str(), r.tag.clone())).collect::<Vec<_>>(), [("a", tag_of(&a)), ("b", tag_of(&b))]);
        assert_eq!(state.active.as_deref(), Some("a"), "the installed copy decides, never the stored name");
        assert_eq!(state.usage.keys().collect::<Vec<_>>(), ["a"], "b was sealed anew and c has no file: their usage goes");
        assert_eq!(v.state, state);
        // A foreign installed seal: no account is active.
        put(&paths.setup_token_env(), &token("foreign"));
        assert_eq!(reconcile(&paths).unwrap().state.active, None);
        // Two accounts with the same bytes: the one already active stays.
        put(&paths.account_env("c"), &b);
        put(&paths.setup_token_env(), &b);
        update(&paths, |s| s.active = Some("c".into())).unwrap();
        assert_eq!(reconcile(&paths).unwrap().state.active.as_deref(), Some("c"));
        // Already in line, and no lock file yet: nothing is written or taken.
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let a = account(&paths, &aws, "a", "1", false);
        put(&paths.setup_token_env(), &a);
        let state = AccountsState { active: Some("a".into()), account: vec![AccountRow { name: "a".into(), tag: tag_of(&a), sealed: Some("2026-10-07T08:00:00Z".into()), note: None }], usage: BTreeMap::from([("a".to_string(), toml::Value::Integer(1))]) };
        put(&paths.accounts_state(), &render(&state).unwrap());
        let ino = std::fs::metadata(paths.accounts_state()).unwrap().ino();
        let v = reconcile(&paths).unwrap();
        assert!(!v.written && v.state == state, "{v:?}");
        assert_eq!(std::fs::metadata(paths.accounts_state()).unwrap().ino(), ino);
        assert!(!lock_path(&paths).exists(), "no lock taken");
    }

    /// An install copies the account's bytes exactly, and its combined copy
    /// only when that is current for those bytes and aws.env now (the
    /// installed pair then reads `Current`, as before accounts); a stale or
    /// missing one leaves none. The store follows; a replaced account needs
    /// no backup. Refusals: an unknown, bad or unsealed account.
    #[test]
    fn an_install_copies_the_bytes_and_a_current_combined_only() {
        use crate::bridge::setup_token::{combined_state, CombinedState};
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let a = account(&paths, &aws, "a", "1", true);
        let b = account(&paths, &aws, "b", "2", false);
        put(&paths.account_combined_env("b"), &combined(&format!("{aws}# another aws.env\n"), &b));
        let c = account(&paths, &aws, "c", "3", false);
        reconcile(&paths).unwrap();
        let done = install(&paths, "a").unwrap();
        assert_eq!(done, Installed { tag: tag_of(&a), combined: CombinedInstall::Installed, from: None, backup: None, warnings: Vec::new() });
        assert_eq!(bytes(&paths.setup_token_env()), Some(a.as_bytes().to_vec()), "a byte copy");
        assert_eq!(bytes(&paths.combined_env()), bytes(&paths.account_combined_env("a")));
        assert_eq!(combined_state(&paths), CombinedState::Current);
        assert_eq!((mode(&paths.setup_token_env()), mode(&paths.combined_env())), (0o600, 0o600));
        assert_eq!(read(&paths).unwrap().unwrap().active.as_deref(), Some("a"));
        let done = install(&paths, "b").unwrap();
        assert_eq!((done.combined, done.from.as_deref(), done.backup), (CombinedInstall::Stale, Some("a"), None));
        assert_eq!(bytes(&paths.setup_token_env()), Some(b.as_bytes().to_vec()));
        assert!(!paths.combined_env().exists() && combined_state(&paths) == CombinedState::Absent, "none installed");
        // c's row names an older seal than its file now holds: its usage goes with it, b's stays.
        update(&paths, |s| {
            s.account[2].tag = "3333333333333333".into();
            s.usage.insert("b".into(), toml::Value::Integer(2));
            s.usage.insert("c".into(), toml::Value::Integer(3));
        })
        .unwrap();
        let done = install(&paths, "c").unwrap();
        assert_eq!((done.tag, done.combined, done.from.as_deref()), (tag_of(&c), CombinedInstall::Absent, Some("b")));
        let state = read(&paths).unwrap().unwrap();
        assert_eq!(state.active.as_deref(), Some("c"));
        assert_eq!(state.account.iter().map(|r| r.tag.clone()).collect::<Vec<_>>(), [tag_of(&a), tag_of(&b), tag_of(&c)]);
        assert_eq!(state.usage.keys().collect::<Vec<_>>(), ["b"]);
        assert!(std::fs::read_dir(paths.credentials()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".bak")), "no backup of an account's seal");
        assert_eq!(install(&paths, "nope").unwrap_err().exit_code(), 1);
        assert_eq!(install(&paths, "Bad").unwrap_err().exit_code(), 2);
        put(&paths.account_env("b"), "not sealed\n");
        let e = install(&paths, "b").unwrap_err();
        assert!(e.exit_code() == 5 && e.to_string().contains("move it away (and revoke what it holds)"), "{e}");
        assert_eq!(bytes(&paths.setup_token_env()), Some(c.as_bytes().to_vec()), "nothing changed");
    }

    /// An installed seal no account holds is kept as a backup before it is
    /// replaced; a link or a plaintext file in setup-token.env's place is
    /// refused (exit 5) with nothing changed: not the file, not
    /// combined.env, not the store.
    #[test]
    fn a_foreign_seal_is_kept_and_a_link_or_plaintext_in_its_place_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let a = account(&paths, &aws, "a", "1", true);
        let foreign = token("foreign");
        put(&paths.setup_token_env(), &foreign);
        reconcile(&paths).unwrap();
        let done = install(&paths, "a").unwrap();
        let bak = done.backup.expect("the foreign seal is kept");
        let name = bak.file_name().unwrap().to_string_lossy().into_owned();
        assert!(bak.parent() == Some(paths.credentials().as_path()) && name.starts_with("setup-token.env.") && name.ends_with(".bak"), "{name}");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), foreign);
        assert_eq!((done.from, bytes(&paths.setup_token_env())), (None, Some(a.as_bytes().to_vec())));
        let store = std::fs::read(paths.accounts_state()).unwrap();
        let pair = bytes(&paths.combined_env());
        assert!(pair.is_some());
        let elsewhere = d.path().join("elsewhere.env");
        put(&elsewhere, &a);
        for (what, make) in [("is a symlink", 0), ("is not an ai-env container (plaintext?)", 1)] {
            std::fs::remove_file(paths.setup_token_env()).unwrap();
            if make == 0 {
                std::os::unix::fs::symlink(&elsewhere, paths.setup_token_env()).unwrap();
            } else {
                put(&paths.setup_token_env(), &format!("{}=placeholder\n", crate::bridge::setup_token::TOKEN_VAR));
            }
            let before = std::fs::symlink_metadata(paths.setup_token_env()).unwrap().ino();
            let e = install(&paths, "a").unwrap_err();
            assert!(e.exit_code() == 5 && e.to_string().contains(what) && e.to_string().contains("move it away (and revoke what it holds); nothing was installed"), "{e}");
            assert_eq!(std::fs::symlink_metadata(paths.setup_token_env()).unwrap().ino(), before, "{what}: left in place");
            assert_eq!(bytes(&paths.combined_env()), pair, "{what}: combined.env untouched");
            assert_eq!(std::fs::read(paths.accounts_state()).unwrap(), store, "{what}: the store untouched");
        }
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), a, "nothing written through the link");
    }

    /// C11: installs racing each other (8 threads, a and b alternately) each
    /// run whole under the store's lock, so setup-token.env and combined.env
    /// are never of two accounts, and the store's active is the installed one.
    #[test]
    fn installs_at_once_always_leave_a_consistent_pair() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let a = account(&paths, &aws, "a", "1", true);
        let b = account(&paths, &aws, "b", "2", true);
        let pairs = [("a", a, std::fs::read_to_string(paths.account_combined_env("a")).unwrap()), ("b", b, std::fs::read_to_string(paths.account_combined_env("b")).unwrap())];
        let check = |paths: &Paths| {
            let installed = std::fs::read_to_string(paths.setup_token_env()).unwrap();
            let (name, _, combined) = pairs.iter().find(|(_, t, _)| *t == installed).expect("an account's bytes");
            assert_eq!(std::fs::read_to_string(paths.combined_env()).ok().as_ref(), Some(combined), "the pair is {name}'s");
            assert_eq!(read(paths).unwrap().unwrap().active.as_deref(), Some(*name));
        };
        std::thread::scope(|s| {
            for t in 0..8 {
                let (paths, check) = (&paths, &check);
                s.spawn(move || {
                    for i in 0..4 {
                        let name = if (t + i) % 2 == 0 { "a" } else { "b" };
                        assert_eq!(install(paths, name).unwrap().combined, CombinedInstall::Installed);
                        let held = lock(paths).unwrap();
                        check(paths);
                        drop(held);
                    }
                });
            }
        });
        check(&paths);
        assert!(std::fs::read_dir(paths.credentials()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".tmp")), "no temp file left");
    }

    /// The index names every seal an account holds or held: its file's
    /// (current) and its backups' (older), never a backup of another shape;
    /// a store that cannot be read is an error, not an empty index.
    #[test]
    fn the_tag_index_names_older_seals_too() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let a = account(&paths, &aws, "a", "1", false);
        let b = account(&paths, &aws, "b", "2", false);
        let (old, other) = (token("old"), token("other"));
        put(&paths.accounts_dir().join("a.env.1700000000.bak"), &old);
        put(&paths.accounts_dir().join("a.env.x.bak"), &other);
        put(&paths.accounts_dir().join("Bad.env.1700000000.bak"), &other);
        put(&paths.accounts_dir().join("b.combined.env.1700000001.bak"), &other);
        assert_eq!(tag_index(&paths).unwrap(), BTreeMap::from([(tag_of(&a), ("a".to_string(), true)), (tag_of(&b), ("b".to_string(), true)), (tag_of(&old), ("a".to_string(), false))]), "no store yet: the files and backups");
        reconcile(&paths).unwrap();
        update(&paths, |s| s.account[1].tag = "2222222222222222".into()).unwrap();
        let index = tag_index(&paths).unwrap();
        assert_eq!((index.len(), &index["2222222222222222"]), (4, &("b".to_string(), false)), "a row's stale seal: b's, not current");
        put(&paths.accounts_state(), "[[account\n");
        assert!(tag_index(&paths).is_err());
    }

    /// Labels: none in a tree with no account; an account's name by its row,
    /// or by its file when no row has it yet; `unknown` for a seal no
    /// account holds, or while `credentials/accounts/` is a link.
    #[test]
    fn labels_fail_open_and_name_what_they_can() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        assert_eq!(label(&paths, "0123456789abcdef"), None, "a legacy tree");
        let a = account(&paths, &aws, "a", "1", false);
        assert_eq!(label(&paths, &tag_of(&a)).as_deref(), Some("a"), "by its file, no store yet");
        reconcile(&paths).unwrap();
        let late = account(&paths, &aws, "late", "9", false);
        assert_eq!(label(&paths, &tag_of(&a)).as_deref(), Some("a"), "by its row");
        assert_eq!(label(&paths, &tag_of(&late)).as_deref(), Some("late"), "by its file, before a row");
        assert_eq!(label(&paths, "0123456789abcdef").as_deref(), Some(UNKNOWN));
        assert_eq!(Seal::of(&paths, tag_of(&a)), Seal { tag: tag_of(&a), account: Some("a".into()) });
        let moved = d.path().join("moved");
        std::fs::rename(paths.accounts_dir(), &moved).unwrap();
        std::os::unix::fs::symlink(&moved, paths.accounts_dir()).unwrap();
        assert!(account_files(&paths).unwrap_err().contains("is a symlink"));
        assert_eq!(label(&paths, &tag_of(&late)).as_deref(), Some(UNKNOWN), "no row has it, and the files cannot be read");
        let e = install(&paths, "a").unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("is a symlink"), "{e}");
    }

    /// L-2's one case: setup-token.env absent while accounts exist, with
    /// its exact text; nothing in a legacy tree, nor while a token is
    /// installed, nor for a link in its place (the token's own row says
    /// that).
    #[test]
    fn the_spawn_problem_is_no_active_account() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        assert_eq!(spawn_problem(&paths), None, "a legacy tree keeps today's words");
        let a = account(&paths, &aws, "a", "1", false);
        assert_eq!(spawn_problem(&paths).as_deref(), Some("no Claude account is active (credentials/setup-token.env is absent): `ai-env creds account use NAME` installs one (`ai-env creds account list` names them)"));
        install(&paths, "a").unwrap();
        assert_eq!(spawn_problem(&paths), None);
        std::fs::remove_file(paths.setup_token_env()).unwrap();
        std::os::unix::fs::symlink(paths.account_env("a"), paths.setup_token_env()).unwrap();
        assert_eq!(spawn_problem(&paths), None);
        assert_eq!(std::fs::read_to_string(paths.account_env("a")).unwrap(), a);
    }

    /// The installed account sealed anew (slice A's `creds setup-token`):
    /// its file holds the new seal and its backup the old one, still
    /// installed. Installing it names the account as `from` and backs
    /// nothing up in credentials/, whether its row still names the old seal
    /// or the new one already; with no file or backup holding the old
    /// bytes, a row keeps only their name, so they are backed up.
    #[test]
    fn a_resealed_account_replaces_its_own_older_seal_without_a_backup() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let old = account(&paths, &aws, "work", "old", false);
        install(&paths, "work").unwrap();
        let bak = paths.accounts_dir().join("work.env.1792569600.bak");
        put(&bak, &old);
        let new = account(&paths, &aws, "work", "new", false);
        assert_eq!(read(&paths).unwrap().unwrap().account[0].tag, tag_of(&old), "its row still names the old seal");
        let listing = |dir: &Path| {
            let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name()).collect();
            names.sort();
            names
        };
        let before = listing(&paths.credentials());
        let done = install(&paths, "work").unwrap();
        assert_eq!((done.tag, done.from.as_deref(), done.backup), (tag_of(&new), Some("work"), None), "by its row");
        assert_eq!(listing(&paths.credentials()), before, "no new file in credentials/");
        assert_eq!(bytes(&paths.setup_token_env()), Some(new.as_bytes().to_vec()));
        // The row names the new seal already: the backup alone holds the old one.
        put(&paths.setup_token_env(), &old);
        let done = install(&paths, "work").unwrap();
        assert_eq!((done.from.as_deref(), done.backup), (Some("work"), None), "by its backup");
        assert_eq!(listing(&paths.credentials()), before);
        // No backup: only the row (put back by hand) names the old seal, and the bytes are kept.
        std::fs::remove_file(&bak).unwrap();
        put(&paths.setup_token_env(), &old);
        update(&paths, |s| s.account[0].tag = tag_of(&old)).unwrap();
        let done = install(&paths, "work").unwrap();
        assert_eq!(done.from.as_deref(), Some("work"));
        assert_eq!(std::fs::read_to_string(done.backup.expect("the old bytes are kept")).unwrap(), old);
    }

    /// Once setup-token.env holds the account, an install is `Ok` whatever
    /// fails after it, each failure a warning: here the combined copy (a
    /// directory where `.combined.env.tmp` goes, which no clearing removes)
    /// and the store (a directory where its temp file goes). No combined.env
    /// is installed then, never the other account's, and `reconcile` repairs
    /// the store as the warning says. A failure before the switch is an
    /// `Err` with setup-token.env as it was.
    #[test]
    fn an_install_warns_of_what_fails_after_the_switch_and_errs_only_before_it() {
        use crate::bridge::setup_token::{combined_state, CombinedState};
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let a = account(&paths, &aws, "a", "1", true);
        let b = account(&paths, &aws, "b", "2", true);
        install(&paths, "a").unwrap();
        let combined_tmp = paths.credentials().join(".combined.env.tmp");
        std::fs::create_dir(&combined_tmp).unwrap();
        std::fs::create_dir(temp_path(&paths)).unwrap();
        let done = install(&paths, "b").unwrap();
        assert_eq!((done.tag.as_str(), done.combined, done.combined.word(), done.from.as_deref()), (tag_of(&b).as_str(), CombinedInstall::Failed, "failed", Some("a")));
        assert_eq!(done.warnings.len(), 2, "{:?}", done.warnings);
        assert!(done.warnings[0].starts_with("Claude account b is installed without its combined.env (") && done.warnings[0].ends_with("): a credentialed command asks for Touch ID twice until `make runtime-key` rebuilds it"), "{}", done.warnings[0]);
        assert!(done.warnings[1].starts_with(&format!("Claude account b is installed, but {} is not updated (", paths.accounts_state().display())) && done.warnings[1].ends_with("): `ai-env creds account list` repairs it"), "{}", done.warnings[1]);
        assert_eq!(bytes(&paths.setup_token_env()), Some(b.as_bytes().to_vec()), "switched");
        assert!(!paths.combined_env().exists() && combined_state(&paths) == CombinedState::Absent, "none installed, never a's");
        assert_eq!(read(&paths).unwrap().unwrap().active.as_deref(), Some("a"), "the store as it was");
        std::fs::remove_dir(temp_path(&paths)).unwrap();
        assert_eq!(reconcile(&paths).unwrap().state.active.as_deref(), Some("b"), "repaired");
        // Before the switch: setup-token.env's own temp file is taken (by a directory no clearing removes).
        std::fs::remove_dir(&combined_tmp).unwrap();
        install(&paths, "a").unwrap();
        assert_eq!(combined_state(&paths), CombinedState::Current);
        std::fs::create_dir(paths.credentials().join(".setup-token.env.tmp")).unwrap();
        let e = install(&paths, "b").unwrap_err();
        let text = e.to_string();
        assert!(e.exit_code() == 1 && text.starts_with("Claude account b is not installed (") && text.ends_with("): combined.env is removed, so a credentialed command asks for Touch ID twice until `make runtime-key` rebuilds it"), "{e}");
        assert_eq!(bytes(&paths.setup_token_env()), Some(a.as_bytes().to_vec()), "as it was");
        assert!(!paths.combined_env().exists(), "the safe direction");
        assert_eq!(read(&paths).unwrap().unwrap().active.as_deref(), Some("a"));
    }

    /// Adoption writes the combined copy first and the account file last:
    /// that file ends adoption for good, so a failure before it (a link
    /// where the combined copy goes, which `write_atomic` refuses) adopts
    /// nothing, and the next pass adopts whole, with one audit row.
    #[test]
    fn an_adoption_that_fails_midway_is_made_whole_by_the_next() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let t = token("1");
        put(&paths.setup_token_env(), &t);
        put(&paths.combined_env(), &combined(&aws, &t));
        std::fs::create_dir_all(paths.accounts_dir()).unwrap();
        let elsewhere = d.path().join("elsewhere.env");
        std::os::unix::fs::symlink(&elsewhere, paths.account_combined_env(DEFAULT)).unwrap();
        let e = reconcile(&paths).unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("is a symlink"), "{e}");
        assert!(!paths.account_env(DEFAULT).exists() && !elsewhere.exists(), "no account file, nothing written through the link");
        assert!(adopt_rows(&paths).is_empty() && !paths.accounts_state().exists());
        std::fs::remove_file(paths.account_combined_env(DEFAULT)).unwrap();
        let v = reconcile(&paths).unwrap();
        assert_eq!(v.adopted, Some(Adopted { tag: tag_of(&t), combined: "copied" }));
        assert_eq!(bytes(&paths.account_env(DEFAULT)), Some(t.as_bytes().to_vec()));
        assert_eq!(bytes(&paths.account_combined_env(DEFAULT)), bytes(&paths.combined_env()));
        assert_eq!(adopt_rows(&paths).len(), 1);
    }

    /// A leftover `state/.accounts.toml.tmp` (a holder of the lock killed
    /// mid-write) is `write_atomic`'s own temp, opened `O_EXCL`: it would
    /// fail every later write of the store. Each writer removes it under
    /// the lock: reconcile, update, try_update and install.
    #[test]
    fn a_dead_writers_temp_file_never_blocks_the_store() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        account(&paths, &aws, "a", "1", false);
        let leftover = paths.root.join("state").join(".accounts.toml.tmp");
        put(&leftover, "half a store");
        let e = crate::store::write_atomic(&paths.accounts_state(), b"").unwrap_err();
        assert!(e.to_string().contains(".accounts.toml.tmp exists"), "{e}");
        assert!(reconcile(&paths).unwrap().written && !leftover.exists());
        put(&leftover, "half a store");
        update(&paths, |s| s.usage.insert("a".into(), toml::Value::Integer(1))).unwrap();
        assert!(!leftover.exists());
        put(&leftover, "half a store");
        assert_eq!(try_update(&paths, |s| _ = s.usage.insert("a".into(), toml::Value::Integer(2))), Ok(TryUpdate::Written));
        assert!(!leftover.exists());
        put(&leftover, "half a store");
        install(&paths, "a").unwrap();
        assert!(!leftover.exists());
        let state = read(&paths).unwrap().unwrap();
        assert_eq!((state.active.as_deref(), &state.usage["a"]), (Some("a"), &toml::Value::Integer(2)));
    }

    /// A1 (slice A): every writer of setup-token.env and combined.env holds
    /// the store's lock, so a leftover `.setup-token.env.tmp` or
    /// `.combined.env.tmp` (a holder killed mid-write) is cleared by the next
    /// install, which `write_atomic`'s `O_EXCL` temp would otherwise fail.
    #[test]
    fn a_dead_installs_temp_files_never_block_the_next() {
        use crate::bridge::setup_token::{combined_state, CombinedState};
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let a = account(&paths, &aws, "a", "1", true);
        account(&paths, &aws, "b", "2", true);
        install(&paths, "b").unwrap();
        let leftovers = [paths.credentials().join(".setup-token.env.tmp"), paths.credentials().join(".combined.env.tmp")];
        for t in &leftovers {
            put(t, "half a copy");
        }
        let done = install(&paths, "a").unwrap();
        assert_eq!((done.combined, done.warnings.len()), (CombinedInstall::Installed, 0), "{:?}", done.warnings);
        assert_eq!(bytes(&paths.setup_token_env()), Some(a.as_bytes().to_vec()));
        assert_eq!(combined_state(&paths), CombinedState::Current);
        assert!(leftovers.iter().all(|t| !t.exists()), "cleared");
    }

    /// `unknown` is [`label`]'s word for a seal no account holds: never an
    /// account's name, so a hand-made `unknown.env` is no account.
    #[test]
    fn unknown_is_never_an_account_name() {
        assert!(!valid_name(UNKNOWN));
        let e = check_name(UNKNOWN).unwrap_err();
        assert_eq!(e.exit_code(), 2, "{e}");
        assert_eq!(e.to_string(), "\"unknown\" is not a Claude account name: it is the label of a seal no account holds");
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let t = account(&paths, &aws, UNKNOWN, "1", false);
        assert!(account_files(&paths).unwrap().is_empty());
        assert_eq!(label(&paths, &tag_of(&t)), None, "no account at all");
        assert_eq!(install(&paths, UNKNOWN).unwrap_err().exit_code(), 2);
    }

    /// The note of `name`'s row in the store.
    fn note_of(paths: &Paths, name: &str) -> Option<String> {
        read(paths).unwrap().unwrap().account.into_iter().find(|r| r.name == name)?.note
    }

    /// Every file under `dir` but lock files (a link as its target): what a
    /// refusal leaves as it was.
    fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(d) = todo.pop() {
            for entry in std::fs::read_dir(&d).unwrap().flatten() {
                let (path, kind) = (entry.path(), entry.file_type().unwrap());
                if kind.is_dir() {
                    todo.push(path);
                } else if kind.is_symlink() {
                    out.insert(path.clone(), std::fs::read_link(&path).unwrap().to_string_lossy().into_owned().into_bytes());
                } else if path.extension().is_none_or(|e| e != "lock") {
                    out.insert(path.clone(), std::fs::read(&path).unwrap());
                }
            }
        }
        out
    }

    /// A note is free text, trimmed: 1-120 characters (not bytes), no
    /// control character, no token or key (a credential's own shape, never
    /// a word such as `token:` before ordinary text). A bad one is
    /// described by its length or the kind of its characters, never echoed:
    /// it may be an email, or a token pasted in its place. The check is of
    /// the text alone: what the process registered to mask counts for
    /// nothing.
    #[test]
    fn notes_are_trimmed_bounded_and_never_echoed() {
        let longest = "é".repeat(MAX_NOTE);
        let padded = format!("  {}\n", "note-".repeat(MAX_NOTE / 5));
        for ok in [
            "a",
            "work@example.com",
            "Работа: team plan, renews in May",
            "a – b ✓",
            "token: expires 2027-10-21",
            "setup token: mike@example.com",
            "OAuth: Google SSO",
            "team plan, secret=no",
            longest.as_str(),
            padded.as_str(),
        ] {
            assert!(valid_note(ok), "{ok:?}");
            assert_eq!(check_note(ok).unwrap(), ok.trim());
        }
        assert_eq!(check_note("\t work@example.com \r\n").unwrap(), "work@example.com", "trimmed");
        let registered = format!("mine-{}", "n0te".repeat(4));
        crate::wire::redact::register_secret(&registered);
        let pure = valid_note(&format!("seen as {registered}"));
        crate::wire::redact::forget_secret(&registered);
        assert!(pure, "the text alone decides");
        let long = "x".repeat(MAX_NOTE + 1);
        let pasted = format!("sk-ant-oat01-{}", "Qz7_".repeat(24));
        let key_id = format!("aws {}{}", "AKIA", "Q7".repeat(8));
        let rule = "(1-120 characters once trimmed, no control character, no token or key)";
        for (bad, says) in [
            ("", "an empty note is not a Claude account note"),
            (" \n\t ", "an empty note is not a Claude account note"),
            (long.as_str(), "a note of 121 characters is not a Claude account note"),
            ("work@example.com\nhome@example.com", "a note with a control character (U+000A) is not a Claude account note"),
            ("red \u{1b}[31malert", "(U+001B)"),
            ("a\tb", "(U+0009)"),
            ("del\u{7f}", "(U+007F)"),
            ("next\u{85}line", "(U+0085)"),
            (pasted.as_str(), "a note holding a credential's shape (anthropic-key) is not a Claude account note: the store keeps notes in the clear"),
            (key_id.as_str(), "(aws-access-key-id)"),
        ] {
            assert!(!valid_note(bad), "{bad:?}");
            let e = check_note(bad).unwrap_err();
            let text = e.to_string();
            assert!(e.exit_code() == 2 && text.contains(says) && text.ends_with(rule), "{text}");
        }
        for bad in ["work@example.com\nhome@example.com", pasted.as_str(), long.as_str(), key_id.as_str()] {
            let text = check_note(bad).unwrap_err().to_string();
            assert!(!text.contains("example") && !text.contains("sk-ant") && !text.contains("Qz7_") && !text.contains("xxxx") && !text.contains("Q7Q7"), "never echoed: {text}");
        }
    }

    /// A note is set, changed, cleared, or left as it was (nothing written),
    /// with no Touch ID; its audit row says the name and what became of the
    /// note, never the text, and no file but state/accounts.toml ever holds
    /// it. Refused with nothing written: an unknown or unsealed account, a
    /// bad name or note, a store that cannot be read. A legacy tree's token
    /// is adopted first, as by any writer.
    #[test]
    fn a_note_is_set_and_cleared_and_only_the_store_holds_it() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        account(&paths, &aws, "work", "1", true);
        let text = "work@example.com, team plan";
        let audited = |paths: &Paths| crate::bridge::audit::read_rows(&paths.audit(), None).unwrap().into_iter().filter(|r| r["event"] == "creds_account_note").collect::<Vec<_>>();
        assert_eq!(set_note(&paths, "work", Some(text)).unwrap(), NoteChange::Set);
        assert_eq!(note_of(&paths, "work").as_deref(), Some(text));
        let ino = std::fs::metadata(paths.accounts_state()).unwrap().ino();
        assert_eq!(set_note(&paths, "work", Some(format!(" {text}\n").as_str())).unwrap(), NoteChange::Unchanged, "the same once trimmed");
        assert_eq!(std::fs::metadata(paths.accounts_state()).unwrap().ino(), ino, "not rewritten");
        assert_eq!(set_note(&paths, "work", Some("another")).unwrap(), NoteChange::Set);
        assert_eq!(set_note(&paths, "work", None).unwrap(), NoteChange::Cleared);
        assert_eq!(note_of(&paths, "work"), None);
        assert_eq!(set_note(&paths, "work", None).unwrap(), NoteChange::Unchanged);
        assert_eq!(set_note(&paths, "work", Some(text)).unwrap().word(), "set");
        let rows = audited(&paths);
        assert_eq!(rows.iter().map(|r| r["detail"]["set"].as_str().unwrap()).collect::<Vec<_>>(), ["set", "set", "cleared", "set"]);
        for r in &rows {
            // S11: `actor` is every row's (audit schema v2).
            assert_eq!((r["detail"].as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(), r["detail"]["name"].as_str()), (vec!["actor", "name", "set"], Some("work")));
        }
        let holders: Vec<PathBuf> = snapshot(&paths.root).into_iter().filter(|(_, b)| String::from_utf8_lossy(b).contains("example.com")).map(|(p, _)| p).collect();
        assert_eq!(holders, [paths.accounts_state()], "the store alone holds it");
        // Refusals: nothing written.
        put(&paths.account_env("plain"), "not sealed\n");
        let before = snapshot(&paths.root);
        for (name, note, code, says) in [
            ("nope", "x", 1, "nope.env does not exist: there is no Claude account nope"),
            ("plain", "x", 1, "plain.env is not an ai-env container (plaintext?): there is no Claude account plain"),
            ("Work", "x", 2, "\"Work\" is not a Claude account name"),
            ("work", "", 2, "an empty note is not"),
            ("work", "a\nb", 2, "(U+000A)"),
        ] {
            let e = set_note(&paths, name, Some(note)).unwrap_err();
            assert!(e.exit_code() == code && e.to_string().contains(says), "{name}: {e}");
        }
        assert_eq!(snapshot(&paths.root), before, "nothing written");
        let mut broken = std::fs::read(paths.accounts_state()).unwrap();
        broken.extend_from_slice(b"\n[[account]\n");
        std::fs::write(paths.accounts_state(), &broken).unwrap();
        let e = set_note(&paths, "work", Some("x")).unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("remove it, and `ai-env creds account list` rebuilds it"), "{e}");
        assert_eq!((std::fs::read(paths.accounts_state()).unwrap(), audited(&paths).len()), (broken, 4), "never written");
        // A legacy tree: its token is adopted as `default` first.
        let d = tempfile::tempdir().unwrap();
        let (paths, _) = tree(d.path());
        put(&paths.setup_token_env(), &token("legacy"));
        assert_eq!(set_note(&paths, DEFAULT, Some("legacy@example.com")).unwrap(), NoteChange::Set);
        assert_eq!((adopt_rows(&paths).len(), note_of(&paths, DEFAULT).as_deref()), (1, Some("legacy@example.com")));
    }

    /// A note is the user's word on a name: every rebuild of the rows keeps
    /// it (an install, a reconcile, the account sealed anew, a stale row an
    /// install rewrites), it goes with a removed account's row, and an
    /// adopted `default` has none, whatever a stale row of that name said.
    #[test]
    fn notes_survive_every_rebuild_of_the_rows() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        account(&paths, &aws, "a", "1", true);
        account(&paths, &aws, "b", "2", false);
        set_note(&paths, "a", Some("a@example.com")).unwrap();
        let noted = |paths: &Paths| read(paths).unwrap().unwrap().account.into_iter().map(|r| (r.name, r.note)).collect::<Vec<_>>();
        let kept = vec![("a".to_string(), Some("a@example.com".to_string())), ("b".to_string(), None)];
        install(&paths, "a").unwrap();
        install(&paths, "b").unwrap();
        assert_eq!(noted(&paths), kept, "installs rewrite the rows");
        // Sealed anew: the row's seal changes and its usage goes (C9); its note stays.
        update(&paths, |s| _ = s.usage.insert("a".into(), toml::Value::Integer(1))).unwrap();
        let a2 = account(&paths, &aws, "a", "1b", true);
        let v = reconcile(&paths).unwrap();
        assert!(v.written && v.state.account[0].tag == tag_of(&a2) && v.state.usage.is_empty(), "{v:?}");
        assert_eq!(noted(&paths), kept);
        update(&paths, |s| s.account[0].tag = "0000000000000000".into()).unwrap();
        install(&paths, "a").unwrap();
        assert_eq!((noted(&paths), read(&paths).unwrap().unwrap().account[0].tag.clone()), (kept.clone(), tag_of(&a2)), "a stale row rewritten");
        // Removed: its row and note go; an account sealed again under that name has none.
        std::fs::remove_file(paths.account_env("a")).unwrap();
        reconcile(&paths).unwrap();
        assert_eq!(noted(&paths), [("b".to_string(), None)]);
        account(&paths, &aws, "a", "1c", false);
        reconcile(&paths).unwrap();
        assert_eq!(noted(&paths), [("a".to_string(), None), ("b".to_string(), None)]);
        // Adoption: a new account, whatever a stale `default` row said.
        let d = tempfile::tempdir().unwrap();
        let (paths, _) = tree(d.path());
        let t = token("legacy");
        put(&paths.setup_token_env(), &t);
        put(&paths.accounts_state(), "[[account]]\nname = \"default\"\ntag = \"0000000000000000\"\nnote = \"a stale row's\"\n");
        let v = reconcile(&paths).unwrap();
        assert!(v.adopted.is_some(), "{v:?}");
        assert_eq!(v.state.account, [AccountRow { name: DEFAULT.into(), tag: tag_of(&t), sealed: Some("2026-10-07T08:00:00Z".into()), note: None }]);
        assert_eq!(read(&paths).unwrap().unwrap(), v.state);
    }

    /// A file moved outside the store (a rename stopped before its store
    /// write, a `mv` by hand) is its account by another name: its row takes
    /// the old row's note, usage (the new name's own first) and `active`.
    /// Never a guess: two files of one row's bytes, neither with a row, take
    /// nothing; and an adopted `default` takes neither note nor usage from a
    /// row of its bytes.
    #[test]
    fn a_file_moved_outside_the_store_keeps_its_note_and_usage() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let work = account(&paths, &aws, "work", "1", false);
        account(&paths, &aws, "spare", "2", false);
        install(&paths, "work").unwrap();
        set_note(&paths, "work", Some("work@example.com")).unwrap();
        set_note(&paths, "spare", Some("spare@example.com")).unwrap();
        update(&paths, |s| s.usage.extend([("work".to_string(), toml::Value::Integer(7)), ("spare".to_string(), toml::Value::Integer(2))])).unwrap();
        let noted = |s: &AccountsState| s.account.iter().map(|r| (r.name.clone(), r.note.clone())).collect::<Vec<_>>();
        let usage = |s: &AccountsState| s.usage.iter().map(|(k, v)| (k.clone(), v.as_integer().unwrap())).collect::<Vec<_>>();
        let spare = ("spare".to_string(), Some("spare@example.com".to_string()));
        std::fs::rename(paths.account_env("work"), paths.account_env("job")).unwrap();
        assert_eq!(label(&paths, &tag_of(&work)).as_deref(), Some("work"), "the store not yet in line: its row names the seal");
        let v = reconcile(&paths).unwrap();
        assert_eq!(v.state.active.as_deref(), Some("job"));
        assert_eq!(noted(&v.state), [("job".to_string(), Some("work@example.com".to_string())), spare.clone()]);
        assert_eq!(usage(&v.state), [("job".to_string(), 7), ("spare".to_string(), 2)]);
        assert_eq!(read(&paths).unwrap().unwrap(), v.state);
        assert_eq!(label(&paths, &tag_of(&work)).as_deref(), Some("job"));
        // Moved again, and something seen of the new name already: that stays.
        std::fs::rename(paths.account_env("job"), paths.account_env("main")).unwrap();
        update(&paths, |s| _ = s.usage.insert("main".into(), toml::Value::Integer(9))).unwrap();
        let v = reconcile(&paths).unwrap();
        assert_eq!((v.state.active.as_deref(), noted(&v.state)), (Some("main"), vec![("main".to_string(), Some("work@example.com".to_string())), spare.clone()]));
        assert_eq!(usage(&v.state), [("main".to_string(), 9), ("spare".to_string(), 2)]);
        // Two files of its bytes without a row: which one moved is a guess, so neither takes anything.
        std::fs::copy(paths.account_env("main"), paths.account_env("x")).unwrap();
        std::fs::rename(paths.account_env("main"), paths.account_env("y")).unwrap();
        let v = reconcile(&paths).unwrap();
        assert_eq!(noted(&v.state), [spare, ("x".to_string(), None), ("y".to_string(), None)]);
        assert_eq!((v.state.active.as_deref(), usage(&v.state)), (Some("x"), vec![("spare".to_string(), 2)]));
        // Adoption: a new account, whatever row its bytes had.
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let t = account(&paths, &aws, "work", "1", false);
        install(&paths, "work").unwrap();
        set_note(&paths, "work", Some("work@example.com")).unwrap();
        update(&paths, |s| _ = s.usage.insert("work".into(), toml::Value::Integer(7))).unwrap();
        std::fs::remove_file(paths.account_env("work")).unwrap();
        let v = reconcile(&paths).unwrap();
        assert!(v.adopted.is_some(), "{v:?}");
        let row = AccountRow { name: DEFAULT.into(), tag: tag_of(&t), sealed: Some("2026-10-07T08:00:00Z".into()), note: None };
        assert_eq!(v.state, AccountsState { active: Some(DEFAULT.into()), account: vec![row], usage: BTreeMap::new() });
        assert_eq!(read(&paths).unwrap().unwrap(), v.state);
    }

    /// A rename moves the account's files by rename(2), the combined copy
    /// first and the account file last, their bytes (so seal id) unchanged:
    /// the active account stays active by its new name, the installed
    /// copies untouched (same bytes, same inodes), its row, note and usage
    /// move, labels and the tag index name it at once, and it installs by
    /// its new name with its own combined copy. A file of another shape
    /// stays where it is.
    #[test]
    fn a_rename_moves_the_files_in_order_and_the_store_with_them() {
        use crate::bridge::setup_token::{combined_state, CombinedState};
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let dir = paths.accounts_dir();
        let work = account(&paths, &aws, "work", "1", true);
        let spare = account(&paths, &aws, "spare", "2", false);
        let older = token("older");
        put(&dir.join("work.env.1700000000.bak"), &older);
        put(&dir.join("work.combined.env.1700000001.bak"), &token("kept"));
        put(&dir.join("work.env.x.bak"), "of another shape\n");
        install(&paths, "work").unwrap();
        set_note(&paths, "work", Some("work@example.com")).unwrap();
        set_note(&paths, "spare", Some("spare@example.com")).unwrap();
        update(&paths, |s| _ = s.usage.insert("work".into(), toml::Value::Integer(7))).unwrap();
        let installed = |paths: &Paths| [paths.setup_token_env(), paths.combined_env()].map(|p| (bytes(&p), std::fs::metadata(&p).unwrap().ino()));
        let pair = installed(&paths);
        let roles = ["combined.env", "combined.env.1700000001.bak", "env.1700000000.bak", "env"];
        let was: Vec<Option<Vec<u8>>> = roles.iter().map(|r| bytes(&dir.join(format!("work.{r}")))).collect();
        let done = rename(&paths, "work", "job").unwrap();
        let moved: Vec<PathBuf> = roles.iter().map(|r| dir.join(format!("job.{r}"))).collect();
        assert_eq!(done, Renamed { tag: tag_of(&work), was_active: true, moved, warnings: Vec::new() });
        for (r, was) in roles.iter().zip(&was) {
            assert!(was.is_some() && bytes(&dir.join(format!("job.{r}"))) == *was && !dir.join(format!("work.{r}")).exists(), "{r}");
        }
        assert!(dir.join("work.env.x.bak").exists(), "not one of the account's files");
        assert_eq!(installed(&paths), pair, "the installed copies untouched");
        assert_eq!(combined_state(&paths), CombinedState::Current);
        assert_eq!(crate::bridge::agent::credential::seal_tag(&paths.account_env("job")), Some(tag_of(&work)));
        let state = read(&paths).unwrap().unwrap();
        assert_eq!(state.active.as_deref(), Some("job"));
        assert_eq!(state.account, [
            AccountRow { name: "job".into(), tag: tag_of(&work), sealed: Some("2026-10-07T08:00:00Z".into()), note: Some("work@example.com".into()) },
            AccountRow { name: "spare".into(), tag: tag_of(&spare), sealed: Some("2026-10-07T08:00:00Z".into()), note: Some("spare@example.com".into()) },
        ]);
        assert_eq!(state.usage, BTreeMap::from([("job".to_string(), toml::Value::Integer(7))]));
        assert_eq!(label(&paths, &tag_of(&work)).as_deref(), Some("job"));
        assert_eq!(tag_index(&paths).unwrap()[&tag_of(&older)], ("job".to_string(), false), "its older seal");
        let rows: Vec<_> = crate::bridge::audit::read_rows(&paths.audit(), None).unwrap().into_iter().filter(|r| r["event"] == "creds_account_rename").collect();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0]["detail"]["from"].as_str(), rows[0]["detail"]["to"].as_str(), rows[0]["detail"]["tag"].as_str()), (Some("work"), Some("job"), Some(tag_of(&work).as_str())));
        let again = install(&paths, "job").unwrap();
        assert_eq!((again.combined, again.from.as_deref(), again.backup), (CombinedInstall::Installed, Some("job"), None));
        // Another account than the active one: `active` stays.
        let done = rename(&paths, "spare", "home").unwrap();
        assert_eq!((done.was_active, done.moved), (false, vec![paths.account_env("home")]));
        let state = read(&paths).unwrap().unwrap();
        assert_eq!((state.active.as_deref(), state.account[0].name.as_str(), state.account[0].note.as_deref()), (Some("job"), "home", Some("spare@example.com")));
    }

    /// Every refusal comes before anything changes, the store and the audit
    /// included: an unknown account; a name taken by an account or by a row;
    /// a file of the new name in the way (beside its old one, or of a shape
    /// a rename never makes); a bad name; a link or a directory among the
    /// files to move or in the new name's place (exit 5); a store that
    /// cannot be read.
    #[test]
    fn a_rename_refuses_before_anything_changes() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let dir = paths.accounts_dir();
        let work = account(&paths, &aws, "work", "1", true);
        account(&paths, &aws, "spare", "2", false);
        put(&dir.join("work.env.1700000000.bak"), &token("older"));
        install(&paths, "work").unwrap();
        set_note(&paths, "work", Some("work@example.com")).unwrap();
        let elsewhere = d.path().join("elsewhere.env");
        put(&elsewhere, &work);
        let refused = |old: &str, new: &str, code: i32, says: &str| {
            let before = snapshot(&paths.root);
            let e = rename(&paths, old, new).unwrap_err();
            assert!(e.exit_code() == code && e.to_string().contains(says), "{old} -> {new}: {e}");
            assert_eq!(snapshot(&paths.root), before, "{old} -> {new}: nothing changed");
        };
        refused("nope", "job", 1, "nope.env does not exist: there is no Claude account nope");
        refused("work", "spare", 1, &format!("a Claude account spare exists ({}): nothing was renamed", paths.account_env("spare").display()));
        refused("work", "work", 1, "a Claude account work exists (");
        refused("Work", "job", 2, "\"Work\" is not a Claude account name");
        refused("work", "unknown", 2, "the label of a seal no account holds");
        refused("work", "a.b", 2, "is not a Claude account name");
        // A file of the new name that no rename moved (its old one is there; a shape never moved) is in the way.
        for stray in [paths.account_combined_env("job"), dir.join("job.env.x.bak")] {
            put(&stray, "left behind\n");
            refused("work", "job", 1, &format!("{} is in the way of the name job (there is no Claude account job): move it away, then rename again; nothing was renamed", stray.display()));
            std::fs::remove_file(&stray).unwrap();
        }
        for link in [dir.join("work.env.1700000001.bak"), dir.join("work.combined.env.1700000002.bak"), paths.account_combined_env("job"), paths.account_env("job")] {
            std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
            refused("work", "job", 5, &format!("{} is a symlink: move it away (and revoke what it holds); nothing was renamed", link.display()));
            std::fs::remove_file(&link).unwrap();
        }
        std::fs::create_dir(dir.join("work.env.1700000003.bak")).unwrap();
        refused("work", "job", 5, "work.env.1700000003.bak is not a regular file: move it away");
        std::fs::remove_dir(dir.join("work.env.1700000003.bak")).unwrap();
        // A store that cannot be read, the lock taken or held.
        let store = std::fs::read(paths.accounts_state()).unwrap();
        put(&paths.accounts_state(), "[[account\n");
        refused("work", "job", 1, "Claude account names are unknown; remove it, and `ai-env creds account list` rebuilds it");
        let held = lock(&paths).unwrap();
        let e = rename_held(&paths, &held, "work", "job").unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("Claude account names are unknown"), "{e}");
        // A row of the new name with no file (no reconcile under a hold): taken too.
        std::fs::write(paths.accounts_state(), &store).unwrap();
        update_held(&paths, &held, |s| s.account.push(AccountRow { name: "job".into(), ..AccountRow::default() })).unwrap();
        let before = snapshot(&paths.root);
        let e = rename_held(&paths, &held, "work", "job").unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains(&format!("a Claude account job exists (its row in {})", paths.accounts_state().display())), "{e}");
        assert_eq!(snapshot(&paths.root), before);
        drop(held);
        // The account file itself a link: no account (a reconcile drops its row, as for any writer), refused.
        std::fs::remove_file(paths.account_env("work")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, paths.account_env("work")).unwrap();
        reconcile(&paths).unwrap();
        refused("work", "job", 5, &format!("{} is a symlink: move it away", paths.account_env("work").display()));
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), work, "nothing written through a link");
        assert!(crate::bridge::audit::read_rows(&paths.audit(), None).unwrap().iter().all(|r| r["event"] != "creds_account_rename"));
    }

    /// A rename killed midway (its moves made here by hand, then
    /// [`reconcile`]) loses no account and never gives a file two names.
    /// Killed after (a) or (b), the account is still the old name, its store
    /// whole (row, note, usage, `active`) and installable, and the same
    /// rename run again finishes it, counting the files of the new name whose
    /// old ones are gone as moved (one beside its old one is in the way:
    /// refused, nothing changed). Killed after (c), the account is the new
    /// name, its row given the old row's note, usage and `active`; the old
    /// name is no account then.
    #[test]
    fn a_rename_killed_midway_leaves_what_reconcile_makes_whole() {
        let roles = ["combined.env", "env.1700000000.bak", "env"];
        for done in 1..=3 {
            let d = tempfile::tempdir().unwrap();
            let (paths, aws) = tree(d.path());
            let dir = paths.accounts_dir();
            let work = account(&paths, &aws, "work", "1", true);
            let spare = account(&paths, &aws, "spare", "2", false);
            let older = token("older");
            put(&dir.join("work.env.1700000000.bak"), &older);
            install(&paths, "work").unwrap();
            set_note(&paths, "work", Some("work@example.com")).unwrap();
            update(&paths, |s| _ = s.usage.insert("work".into(), toml::Value::Integer(7))).unwrap();
            let whole = read(&paths).unwrap().unwrap();
            let was: Vec<Option<Vec<u8>>> = roles.iter().map(|r| bytes(&dir.join(format!("work.{r}")))).collect();
            for role in &roles[..done] {
                std::fs::rename(dir.join(format!("work.{role}")), dir.join(format!("job.{role}"))).unwrap();
            }
            let v = reconcile(&paths).unwrap();
            let rows = v.state.account.iter().map(|r| (r.name.as_str(), r.tag.clone(), r.note.as_deref())).collect::<Vec<_>>();
            if done == 3 {
                assert_eq!(v.state.active.as_deref(), Some("job"), "the installed seal is job's");
                assert_eq!(rows, [("job", tag_of(&work), Some("work@example.com")), ("spare", tag_of(&spare), None)]);
                assert_eq!(v.state.usage, BTreeMap::from([("job".to_string(), toml::Value::Integer(7))]));
                let e = rename(&paths, "work", "job").unwrap_err();
                assert!(e.exit_code() == 1 && e.to_string().contains("there is no Claude account work"), "{e}");
                continue;
            }
            assert_eq!((v.written, &v.state, v.files.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()), (false, &whole, vec!["spare", "work"]), "after {done} move(s): work, with its note, usage and active");
            assert_eq!(label(&paths, &tag_of(&work)).as_deref(), Some("work"));
            assert_eq!(install(&paths, "work").unwrap().combined, CombinedInstall::Absent, "installable, its combined copy under the new name");
            // Its combined copy made anew meanwhile: the one moved is in the way.
            put(&paths.account_combined_env("work"), &combined(&aws, &work));
            let before = snapshot(&paths.root);
            let e = rename(&paths, "work", "job").unwrap_err();
            assert!(e.exit_code() == 1 && e.to_string().contains(&format!("{} is in the way of the name job (there is no Claude account job)", paths.account_combined_env("job").display())), "{e}");
            assert_eq!(snapshot(&paths.root), before, "nothing changed");
            std::fs::remove_file(paths.account_combined_env("work")).unwrap();
            // Never resumed beside a row of the new name.
            let held = lock(&paths).unwrap();
            update_held(&paths, &held, |s| s.account.push(AccountRow { name: "job".into(), ..AccountRow::default() })).unwrap();
            let e = rename_held(&paths, &held, "work", "job").unwrap_err();
            assert!(e.to_string().contains("a Claude account job exists (its row in"), "{e}");
            update_held(&paths, &held, |s| s.account.retain(|r| r.name != "job")).unwrap();
            drop(held);
            // Run again: it finishes what the first one began.
            let again = rename(&paths, "work", "job").unwrap();
            let left: Vec<PathBuf> = roles[done..].iter().map(|r| dir.join(format!("job.{r}"))).collect();
            assert_eq!((again.tag.as_str(), again.was_active, &again.moved, again.warnings.len()), (tag_of(&work).as_str(), true, &left, 0));
            for (r, was) in roles.iter().zip(&was) {
                assert!(bytes(&dir.join(format!("job.{r}"))) == *was && !dir.join(format!("work.{r}")).exists(), "{r}");
            }
            let state = read(&paths).unwrap().unwrap();
            assert_eq!(state.active.as_deref(), Some("job"));
            assert_eq!(state.account.iter().map(|r| (r.name.as_str(), r.note.as_deref())).collect::<Vec<_>>(), [("job", Some("work@example.com")), ("spare", None)]);
            assert_eq!(state.usage, BTreeMap::from([("job".to_string(), toml::Value::Integer(7))]));
            assert_eq!(tag_index(&paths).unwrap()[&tag_of(&older)], ("job".to_string(), false));
        }
    }

    /// Once the account file has its new name the rename is done: a store
    /// that cannot be written then is a warning, never an `Err`, and
    /// [`reconcile`] rebuilds it from the files as the warning says, the
    /// note and usage carried to the new name.
    #[test]
    fn a_rename_warns_of_a_store_it_cannot_write_after_the_move() {
        let d = tempfile::tempdir().unwrap();
        let (paths, aws) = tree(d.path());
        let work = account(&paths, &aws, "work", "1", false);
        set_note(&paths, "work", Some("work@example.com")).unwrap();
        update(&paths, |s| _ = s.usage.insert("work".into(), toml::Value::Integer(7))).unwrap();
        std::fs::create_dir(temp_path(&paths)).unwrap();
        let done = rename(&paths, "work", "job").unwrap();
        assert_eq!((done.tag, done.was_active, done.moved), (tag_of(&work), false, vec![paths.account_env("job")]));
        assert_eq!(done.warnings.len(), 1, "{:?}", done.warnings);
        assert!(done.warnings[0].starts_with(&format!("Claude account work is renamed job, but {} is not updated (", paths.accounts_state().display())) && done.warnings[0].ends_with("): `ai-env creds account list` rebuilds it from the files, work's note and usage carried"), "{}", done.warnings[0]);
        assert_eq!(note_of(&paths, "work").as_deref(), Some("work@example.com"), "the store as it was");
        std::fs::remove_dir(temp_path(&paths)).unwrap();
        let v = reconcile(&paths).unwrap();
        assert_eq!(v.state.account.iter().map(|r| (r.name.as_str(), r.note.as_deref())).collect::<Vec<_>>(), [("job", Some("work@example.com"))]);
        assert_eq!(v.state.usage, BTreeMap::from([("job".to_string(), toml::Value::Integer(7))]));
    }

    /// A move that fails midway puts back what it moved, last first, and
    /// never replaces a file in its way (rename(2) would).
    #[test]
    fn moves_that_fail_midway_are_put_back() {
        let d = tempfile::tempdir().unwrap();
        let p = |f: &str| d.path().join(f);
        for f in ["a", "b", "taken"] {
            put(&p(f), f);
        }
        let e = move_in_order(&[(p("a"), p("a2")), (p("b"), p("b2")), (p("gone"), p("c2"))]).unwrap_err();
        assert!(e.starts_with(&format!("{} cannot be renamed (", p("gone").display())) && e.ends_with("; nothing was renamed"), "{e}");
        assert!(p("a").exists() && p("b").exists() && !p("a2").exists() && !p("b2").exists(), "put back");
        let e = move_in_order(&[(p("a"), p("a2")), (p("b"), p("taken"))]).unwrap_err();
        assert_eq!(e, format!("{} exists; nothing was renamed", p("taken").display()));
        assert_eq!((std::fs::read_to_string(p("taken")).unwrap(), p("a").exists(), p("a2").exists()), ("taken".to_string(), true, false));
        assert_eq!(move_in_order(&[(p("a"), p("a2"))]), Ok(()));
        assert!(!p("a").exists() && p("a2").exists());
    }
}
