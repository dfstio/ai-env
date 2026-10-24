//! `ai-env creds account add|use|list|forget` (S10 addendum A1, §2): the
//! Claude accounts' commands on the store (`super`); `check` is
//! [`super::check`]'s.
//!
//! - `add NAME` seals a token into `credentials/accounts/NAME.env`
//!   (`setup_token::seal_account`: a hidden paste, `--stdin` or
//!   `--from-env`; one Touch ID for the account's combined container).
//!   `--use` installs it, as does a first account and the active one added
//!   again, while that still holds once it is sealed (a `use` made
//!   meanwhile stays); a name added again is sealed anew, its old seal kept
//!   as a backup and what was seen of its usage gone (C9).
//! - `use NAME` installs an account by byte copy (no Touch ID), refused
//!   before anything changes for an unknown name (exit 1), a file that is no
//!   container (5) or a seal Anthropic refused (5), then names the live
//!   remote chats still on another account: each keeps its claude until its
//!   next start, which takes the new one.
//! - `list` shows them, the active one marked (no Touch ID, exit 0).
//! - `forget NAME` deletes one account (a dry run without `--yes`).
//! - `rename OLD NEW` and `note NAME [TEXT]` (L-8, no Touch ID): the
//!   store's [`super::rename`] and [`super::set_note`]; `add --note TEXT`
//!   keeps a note once the token is sealed.
//!
//! Each reconciles first (C10: a legacy `setup-token.env` is adopted as
//! `default`, by byte copy). A store that cannot be read is never written:
//! the writers refuse (exit 1, L-2), and `list` shows it.
use super::{audit_event, check_name, AccountFile, UNKNOWN};
use crate::bridge::audit;
use crate::bridge::config::Paths;
use crate::bridge::creds::{aws_env_state, key_name, AwsEnvState};
use crate::bridge::registry;
use crate::bridge::setup_token::{self, AccountsSeen, Install, SetupTokenOpts};
use crate::bridge::voice;
use crate::cli::AccountCmd;
use crate::commands::Tag;
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::Keystore;
use crate::wire::time::{rfc3339_utc, unix_now};
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::PathBuf;

/// `ai-env creds account …`.
pub fn main(store: &Keystore, cmd: AccountCmd) -> Result<()> {
    match cmd {
        AccountCmd::Add { name, stdin, from_env, activate, force, note } => add(store, &name, SetupTokenOpts { stdin, from_env, no_combined: false, force }, activate, note.as_deref()),
        AccountCmd::Rename { old, new } => rename(&old, &new),
        AccountCmd::Note { name, text } => note(&name, text.as_deref()),
        AccountCmd::Use { name } => use_account(&name),
        AccountCmd::List { json } => list(json),
        AccountCmd::Forget { name, yes } => forget(&name, yes),
        AccountCmd::Check { names, json, model } => super::check::cmd_check(store, &names, json, &model),
    }
}

/// `Claude accounts: a, b`, or that none is sealed: what a refusal of an
/// unknown name says there is.
fn known(files: &[AccountFile]) -> String {
    if files.is_empty() {
        return "no Claude account is sealed".to_string();
    }
    format!("Claude accounts: {}", files.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", "))
}

// ---- add ----------------------------------------------------------------------------------

/// `ai-env creds account add NAME [--stdin|--from-env] [--use] [--force]
/// [--note TEXT]`: the name and the note checked before anything is read
/// (exit 2), the note kept once the token is sealed ([`super::set_note`]);
/// the token sealed as
/// the account ([`setup_token::seal_account`]), and installed with `--use`;
/// else when nothing is installed (a first account) or when it is the
/// active one already (the installed copy follows its file), each judged
/// again under the store's lock once it is sealed ([`Install::IfStill`]: an
/// account installed meanwhile stays). One that became the active account
/// in place of another names the live chats still on that one, as `use`
/// does.
fn add(store: &Keystore, name: &str, o: SetupTokenOpts, activate: bool, note: Option<&str>) -> Result<()> {
    check_name(name)?;
    let note = note.map(super::check_note).transpose()?;
    let paths = Paths::resolve()?;
    let key = key_name(&paths)?;
    let view = super::reconcile(&paths)?;
    let absent = aws_env_state(&paths.setup_token_env()) == AwsEnvState::Absent;
    let install = match (activate, absent || view.state.active.as_deref() == Some(name)) {
        (true, _) => Install::Always,
        (false, true) => Install::IfStill { absent },
        (false, false) => Install::No,
    };
    // Sealed (an Err returns above); installed or not, the note goes with it.
    let installed = setup_token::seal_account(store, &paths, &key, name, o, install, "account-add")?;
    if let Some(note) = &note {
        super::set_note(&paths, name, Some(note))?;
        outln!("Claude account {name}'s note is kept (shown by `ai-env creds account list` and `ai-env creds status`)");
    }
    let Some(done) = installed else { return Ok(()) };
    if done.from.as_deref() != Some(name) {
        say_live_chats(&live_chats(&paths, &done.tag), name)?;
    }
    Ok(())
}

// ---- rename, note -------------------------------------------------------------------------

/// `ai-env creds account rename OLD NEW` (no Touch ID): [`super::rename`]
/// moves the account's files (its combined container and backups first, its
/// sealed token last), its row, usage and note and the active mark, audited
/// `creds_account_rename`. The sealed bytes never change, so its seal, the
/// installed copies, refusals and the VMs' caches are untouched; census
/// rows already written keep the old name.
fn rename(old: &str, new: &str) -> Result<()> {
    let paths = Paths::resolve()?;
    let done = super::rename(&paths, old, new)?;
    for w in &done.warnings {
        voice::warn(w);
    }
    let active = if done.was_active { " (the active one)" } else { "" };
    outln!("renamed Claude account {old}{active} to {new} (seal {}): its installed copies, refusals and the VMs' caches are unchanged", done.tag);
    Ok(())
}

/// `ai-env creds account note NAME [TEXT]` (no Touch ID): [`super::set_note`]
/// sets the note, or clears it with no TEXT; the store alone keeps it, and
/// the audit row says only that it changed.
fn note(name: &str, text: Option<&str>) -> Result<()> {
    let paths = Paths::resolve()?;
    let change = super::set_note(&paths, name, text)?;
    outln!("Claude account {name}'s note: {}", change.word());
    Ok(())
}

// ---- use ----------------------------------------------------------------------------------

/// `ai-env creds account use NAME` (no Touch ID): its files installed by
/// byte copy (`super::install`: `setup-token.env`, then `combined.env` only
/// when the account's own is current), audited `creds_account_use`. Refused
/// before anything changes: an unknown name (exit 1, naming the accounts),
/// a file in its place that is no container (5), a seal Anthropic refused
/// or refusals that cannot be read (5, M53). Then the live remote chats
/// still on another account are named, each with its way on (`session
/// migrate` now, one Touch ID, or a reopen); a running claude keeps its
/// token until its next start (a restart or a move), which takes this one.
fn use_account(name: &str) -> Result<()> {
    check_name(name)?;
    let paths = Paths::resolve()?;
    let view = super::reconcile(&paths)?;
    let Some(file) = view.files.iter().find(|f| f.name == name) else {
        let path = paths.account_env(name);
        if let AwsEnvState::NotSealed(why) = aws_env_state(&path) {
            return Err(CliError::AuthUnavailable(format!("{} {why}: move it away (and revoke what it holds), then `ai-env creds account add {name}` seals it anew; nothing was installed", path.display())));
        }
        return Err(CliError::Msg(format!("no Claude account {name} ({}): `ai-env creds account add {name}` seals one", known(&view.files))));
    };
    refuse_refused(&paths, file)?;
    let done = super::install(&paths, name)?;
    for w in &done.warnings {
        voice::warn(w);
    }
    let combined = if setup_token::container_mode(&paths).is_ok() { done.combined.word() } else { "unused" };
    let chats = live_chats(&paths, &done.tag);
    let row = audit::AuditRow::new(
        audit_event::USE,
        None,
        audit::detail(&[
            ("from", done.from.clone().unwrap_or_else(|| "-".into())),
            ("to", name.to_string()),
            ("tag", done.tag.clone()),
            ("combined", combined.into()),
            ("chats_other", chats.len().to_string()),
        ]),
    );
    if let Err(e) = audit::append(&paths.audit(), &row) {
        voice::warn(&format!("the audit row {} was not written: {e}", audit_event::USE));
    }
    if let Some(bak) = &done.backup {
        outln!("the replaced setup-token.env, a seal no Claude account holds, kept as {}", bak.display());
    }
    let with = match combined {
        "installed" => ", with its combined.env: a credentialed command asks for Touch ID once",
        "stale" | "absent" => ", without a current combined.env: a credentialed command asks for Touch ID twice until `make runtime-key` rebuilds it",
        _ => "",
    };
    let target = paths.setup_token_env();
    match done.from.as_deref() {
        Some(from) if from == name => outln!("Claude account {name} is the active one already: installed again as {}{with}", target.display()),
        Some(from) => outln!("Claude account {name} is the active one now, in place of {from}: installed as {}{with}", target.display()),
        None => outln!("Claude account {name} is the active one now: installed as {}{with}", target.display()),
    }
    outln!("new chats, moves and credentialed commands use it; a running claude keeps its own token until its next start");
    say_live_chats(&chats, name)
}

/// A seal Anthropic refused is never made active, nor one whose refusals
/// cannot be read (M53: which were refused is then unknown): exit 5, before
/// anything changes.
fn refuse_refused(paths: &Paths, file: &AccountFile) -> Result<()> {
    match crate::bridge::agent::credential::read_rejection(paths, &file.tag) {
        Ok(None) => Ok(()),
        Ok(Some(r)) => Err(CliError::AuthUnavailable(format!(
            "Claude account {}'s token (seal {}) was refused by Anthropic on {} ({}): it is not made active; seal a fresh one with `claude setup-token` (logged in as that account), then `ai-env creds account add {}`",
            file.name, file.tag, r.at, r.vm, file.name
        ))),
        Err(e) => Err(CliError::AuthUnavailable(format!(
            "{e}: which tokens Anthropic refused is unknown, so Claude account {} is not made active; repair it, or remove it to forget every recorded refusal",
            file.name
        ))),
    }
}

/// A live remote chat whose claude still runs on another seal than the one
/// installed: its session id, its workspace, and the account it runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveChat {
    sid: String,
    cwd: String,
    account: String,
}

/// The live remote chats on another seal than `tag` (C7): session rows of
/// mode `remote` and status `active`, `detached` or `parked` whose wrapper
/// is alive (`registry::confirm_wrapper`), and whose last `vms` entry names
/// another seal, or none (an older wrapper's: its account unknown). Each is
/// named by the entry's account, else by the seal's (`tag_index`, older
/// seals too), else `unknown`. A registry that cannot be listed lists none,
/// with a warning.
fn live_chats(paths: &Paths, tag: &str) -> Vec<LiveChat> {
    live_chats_with(paths, tag, |r| registry::confirm_wrapper(r, r.pid).is_ok())
}

/// [`live_chats`] with `alive` judging a row's wrapper.
fn live_chats_with(paths: &Paths, tag: &str, alive: impl Fn(&registry::SessionRow) -> bool) -> Vec<LiveChat> {
    let rows = registry::list(paths).unwrap_or_else(|e| {
        voice::warn(&format!("the session registry cannot be read ({e}): the live chats on another account are not listed (`ai-env session list` shows them)"));
        Vec::new()
    });
    let index = super::tag_index(paths).ok();
    rows.into_iter()
        .filter(|r| r.mode == "remote" && matches!(r.status.as_str(), "active" | "detached" | "parked") && alive(r))
        .filter_map(|r| {
            let last = r.vms.last().and_then(registry::VmEntry::from_value);
            let seal = last.as_ref().and_then(|e| e.tag.clone());
            if seal.as_deref() == Some(tag) {
                return None;
            }
            let named = seal.as_ref().and_then(|t| index.as_ref()?.get(t)).map(|(n, _)| n.clone());
            // The seal's name now first: the name its entry recorded may since have been renamed.
            let account = named.or_else(|| last.and_then(|e| e.account)).unwrap_or_else(|| UNKNOWN.to_string());
            Some(LiveChat { sid: r.session_id, cwd: r.cwd.unwrap_or_else(|| "?".into()), account })
        })
        .collect()
}

/// The live chats on another account, each with its way on to `name`.
fn say_live_chats(chats: &[LiveChat], name: &str) -> Result<()> {
    if chats.is_empty() {
        return Ok(());
    }
    outln!("{} live chat(s) still run as another Claude account:", chats.len());
    for c in chats {
        outln!("  {} ({}) as {}: `ai-env session migrate {}` moves it now (one Touch ID), or reopen it; its next restart or move takes {name}", c.sid, c.cwd, c.account, c.sid);
    }
    Ok(())
}

// ---- list ---------------------------------------------------------------------------------

/// `ai-env creds account list [--json]`: the accounts, the active one
/// marked, with no Touch ID; always exit 0. It reconciles first (an
/// adoption, or the store repaired from the files: its only writes); what
/// is wrong with the accounts as a whole comes first (a store that cannot
/// be read is shown, never written, and the accounts are read from their
/// files without it), then a row per account with its usage summary
/// (slice B's `usage_summary`); a refused one is `[NO ]` here.
fn list(json: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let now = unix_now();
    let failed = super::reconcile(&paths).err();
    let seen = AccountsSeen::read(&paths);
    let shown = setup_token::accounts_shown(&paths, &seen);
    if json {
        let mut doc = setup_token::accounts_json(&paths, &seen, &shown, now);
        doc["reconcile_error"] = serde_json::json!(failed.as_ref().map(ToString::to_string));
        outln!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return Ok(());
    }
    let mode = setup_token::container_mode(&paths);
    let runtime_key = aws_env_state(&paths.aws_env()) == AwsEnvState::Sealed;
    let row = |tag: Tag, text: String| crate::commands::outln(format_args!("{} {text}", tag.bracket()));
    // A failure the problems below do not say already (an adoption refused).
    if let Some(e) = failed.filter(|_| seen.store.is_ok() && seen.files.is_ok()) {
        row(Tag::Warn, e.to_string())?;
    }
    for problem in seen.problems(&paths) {
        row(Tag::Warn, problem)?;
    }
    if shown.is_empty() && seen.files.is_ok() {
        row(Tag::Skip, "no Claude account is sealed: `ai-env creds account add NAME` seals one (what `claude setup-token` prints, logged in as that account)".into())?;
    }
    for a in &shown {
        let (mut text, warn, refused) = a.text(&mode, runtime_key, now);
        if let Some(usage) = seen.usage(&a.name).and_then(|v| super::usage_summary(v, now)) {
            text.push_str(&format!("; {usage}"));
        }
        let tag = if refused {
            Tag::No
        } else if warn {
            Tag::Warn
        } else {
            Tag::Ok
        };
        row(tag, format!("{}: {text}", a.title()))?;
    }
    Ok(())
}

// ---- forget -------------------------------------------------------------------------------

/// `ai-env creds account forget NAME [--yes]`: a dry run without `--yes`.
/// What goes: the account's sealed token, its backups (older seals), its
/// combined container (and a backup of one), and, when it is the installed
/// one (`setup-token.env` holds its current seal or an older one), the
/// installed `setup-token.env` and `combined.env`: no account is active
/// then, and new chats and moves refuse (exit 5) until `use OTHER`. With
/// `--yes` what goes is decided under the store's lock and goes under the
/// same hold (C11), its row and usage with it, audited
/// `creds_account_forget` (the files it deleted counted, [`delete_each`]):
/// an install made meanwhile (`use`, `add --use` in another terminal) is
/// either done before the decision, which sees it, or waits until the files
/// are gone. The VMs that received one of its seals (or a seal their row
/// does not record) are named, with the only way to clear them, as is what
/// ai-env cannot do: revoke the token.
fn forget(name: &str, yes: bool) -> Result<()> {
    check_name(name)?;
    let paths = Paths::resolve()?;
    let view = super::reconcile(&paths)?;
    // Held from the decision to the row (a few file operations and lines, never a Touch ID).
    let locked = if yes { Some(super::lock(&paths).map_err(CliError::Msg)?) } else { None };
    let dir = paths.accounts_dir();
    let mut files: Vec<PathBuf> = [paths.account_env(name), paths.account_combined_env(name)].into_iter().filter(|p| std::fs::symlink_metadata(p).is_ok()).collect();
    files.extend(setup_token::backups_in(&dir, &format!("{name}.env")));
    files.extend(setup_token::backups_in(&dir, &format!("{name}.combined.env")));
    if files.is_empty() && !view.state.account.iter().any(|r| r.name == name) {
        return Err(CliError::Msg(format!("no Claude account {name} ({})", known(&view.files))));
    }
    let index = super::tag_index(&paths).map_err(|e| CliError::Msg(super::unreadable(&e)))?;
    let seals: BTreeSet<&str> = index.iter().filter(|(_, (n, _))| n == name).map(|(t, _)| t.as_str()).collect();
    // What setup-token.env holds now, never what the reconcile found: another account may be installed since.
    let was_active = setup_token::installed_seal(&paths).is_some_and(|t| seals.contains(t.as_str()));
    if was_active {
        files.extend([paths.setup_token_env(), paths.combined_env()].into_iter().filter(|p| std::fs::symlink_metadata(p).is_ok()));
    }
    let (held, unread) = setup_token::holders(&paths).unwrap_or_else(|e| {
        voice::warn(&format!("the VM registry cannot be read ({e}): VMs that received the token are not listed; `ai-env vm list` shows them"));
        (Vec::new(), Vec::new())
    });
    // A1 joint review (J2): a VM any of whose seals is one of the account's (a chat may still run on an earlier one).
    let held: Vec<_> = held.into_iter().filter(|h| (h.tags.is_empty() && h.tag.is_none()) || h.tags.iter().chain(h.tag.iter()).any(|t| seals.contains(t.as_str()))).collect();
    let verb = if yes { "deleting" } else { "would delete" };
    for f in &files {
        outln!("{verb} {}", f.display());
    }
    for h in &held {
        let what = h.tags.iter().chain(h.tag.iter()).find(|t| seals.contains(t.as_str())).map_or_else(|| "a token whose seal its row does not record (it may be this one)".to_string(), |t| format!("Claude account {name}'s token (seal {t})"));
        outln!("{} ({}) received {what} at {}: only terminating it clears its copies: ai-env vm terminate {}", h.id, h.status, rfc3339_utc(h.credential_at), h.id);
    }
    for u in &unread {
        outln!("{}: {u}; only terminating its VM clears its copies (`ai-env vm list` shows the VMs)", setup_token::UNREADABLE_ROW);
    }
    outln!("ai-env cannot revoke Claude account {name}'s token: revoke it in that account on claude.ai, under Settings, then Claude Code (README, Credentials)");
    let Some(lock) = locked else {
        outln!("dry run: nothing deleted; pass --yes to delete");
        return Ok(());
    };
    let (deleted, failed) = delete_each(&files);
    let forgotten = super::update_held(&paths, &lock, |s| {
        s.account.retain(|r| r.name != name);
        s.usage.remove(name);
        if s.active.as_deref() == Some(name) {
            s.active = None;
        }
    });
    drop(lock);
    if let Err(e) = forgotten {
        voice::warn(&format!("{} is not updated ({e}): `ai-env creds account list` repairs it", paths.accounts_state().display()));
    }
    let row = audit::AuditRow::new(
        audit_event::FORGET,
        None,
        audit::detail(&[("name", name.to_string()), ("files", deleted.to_string()), ("holders", held.len().to_string()), ("was_active", was_active.to_string()), ("failed", failed.len().to_string())]),
    );
    if let Err(e) = audit::append(&paths.audit(), &row) {
        voice::warn(&format!("the audit row {} was not written: {e}", audit_event::FORGET));
    }
    if !failed.is_empty() {
        return Err(CliError::Msg(format!("could not delete: {}", failed.join("; "))));
    }
    outln!("deleted {deleted} file(s)");
    if was_active {
        outln!("no Claude account is active: new chats and moves refuse (exit 5) until `ai-env creds account use OTHER` (`ai-env creds account list` names them)");
    }
    Ok(())
}

/// Delete each of `files`: how many it deleted, and those it could not
/// (`path: why`). One gone already is neither: a deleter that takes no lock
/// got there first (a combined container's rebuild removes the old one
/// before it seals), so it is not counted as this forget's.
fn delete_each(files: &[PathBuf]) -> (usize, Vec<String>) {
    let mut deleted = 0;
    let mut failed = Vec::new();
    for f in files {
        match std::fs::remove_file(f) {
            Ok(()) => deleted += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => failed.push(format!("{}: {e}", f.display())),
        }
    }
    (deleted, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L-5: slice A's audit names are unique, snake_case and new: none is a
    /// row the remote session writes (`remote::audit_event::ALL`), nor one
    /// of the sealing commands' and credentials' rows of S7–S8.
    #[test]
    fn the_account_audit_names_are_unique_and_new() {
        let earlier = ["creds_setup_token", "creds_combined", "creds_forget", "creds_aws_set", "credential_unseal", "credential_gate", "credential_deliver", "credential_rejected", "lab_probe"];
        let remote = crate::bridge::remote::audit_event::ALL;
        let all: BTreeSet<&str> = audit_event::ALL.iter().chain(remote.iter()).copied().collect();
        assert_eq!(all.len(), audit_event::ALL.len() + remote.len(), "unique, the remote session's included");
        for e in audit_event::ALL {
            assert!(!e.is_empty() && e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') && !earlier.contains(&e), "{e}");
        }
        assert_eq!(audit_event::ALL, ["creds_account_adopt", "creds_account_use", "creds_account_forget", "account_check", "creds_account_rename", "creds_account_note"]);
    }

    /// What a refusal of an unknown name says there is.
    #[test]
    fn an_unknown_name_is_told_the_accounts() {
        assert_eq!(known(&[]), "no Claude account is sealed");
        let f = |n: &str| AccountFile { name: n.into(), text: String::new(), tag: String::new(), sealed: None };
        assert_eq!(known(&[f("default"), f("work")]), "Claude accounts: default, work");
    }

    /// `forget --yes` counts the files it deleted (its audit row's `files`,
    /// its `deleted N file(s)`): one another deleter removed after the
    /// listing is neither counted nor a failure; one that cannot be deleted
    /// (a directory in its place) is a failure, never counted.
    #[test]
    fn forget_counts_only_the_files_it_deleted() {
        let d = tempfile::tempdir().unwrap();
        let [file, gone, dir] = ["work.env", "work.combined.env", "work.env.1791000000.bak"].map(|n| d.path().join(n));
        std::fs::write(&file, "x").unwrap();
        std::fs::create_dir(&dir).unwrap();
        let (deleted, failed) = delete_each(&[file.clone(), gone, dir.clone()]);
        assert_eq!(deleted, 1, "{failed:?}");
        assert!(!file.exists() && dir.is_dir());
        assert!(failed.len() == 1 && failed[0].starts_with(&format!("{}: ", dir.display())), "{failed:?}");
        assert_eq!(delete_each(&[]), (0, Vec::new()));
    }

    /// C7: a live remote chat is listed when its last generation ran on
    /// another seal, or recorded none (named by its entry, then by the
    /// index of the accounts' seals, then `unknown`), never when it runs on
    /// the new one; a closed, migrating or local chat, or one whose wrapper
    /// is not alive, is never listed.
    #[test]
    fn the_live_chats_are_those_on_another_seal() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let sealed = crate::container::write_annotated(b"age-encryption.org/v1\n-> x\n--- y\n", &[("kind", "setup-token")]).unwrap();
        std::fs::create_dir_all(paths.accounts_dir()).unwrap();
        std::fs::write(paths.account_env("spare"), &sealed).unwrap();
        let spare = crate::bridge::agent::credential::tag_of(&sealed);
        let entry = |tag: Option<&str>, account: Option<&str>| {
            toml::Value::try_from(registry::VmEntry { gen: 1, vm: "microvm-1".into(), from: "2026-10-21T10:00:00Z".into(), pid: 1, tag: tag.map(Into::into), account: account.map(Into::into), ..registry::VmEntry::default() }).unwrap()
        };
        let row = |n: u8, status: &str, mode: &str, vms: Vec<toml::Value>| registry::SessionRow {
            v: registry::REGISTRY_SCHEMA_V,
            session_id: format!("00000000-0000-4000-8000-00000000000{n}"),
            cwd: Some(format!("/w/{n}")),
            created: "2026-10-21T10:00:00Z".into(),
            last_seen: format!("2026-10-21T10:00:0{n}Z"),
            status: status.into(),
            mode: mode.into(),
            pid: u32::from(n),
            vms,
            ..registry::SessionRow::default()
        };
        let new = "bbbbbbbbbbbbbbbb";
        for r in [
            row(1, "active", "remote", vec![entry(Some(new), Some("work")), entry(Some("aaaaaaaaaaaaaaaa"), Some("default"))]),
            row(2, "parked", "remote", vec![entry(Some(&spare), None)]),
            row(3, "detached", "remote", vec![entry(None, None)]),
            row(4, "active", "remote", vec![entry(Some(new), Some("work"))]),
            row(5, "closed", "remote", vec![entry(Some("aaaaaaaaaaaaaaaa"), Some("default"))]),
            row(6, "migrating", "remote", vec![entry(Some("aaaaaaaaaaaaaaaa"), Some("default"))]),
            row(7, "active", "local-child", vec![]),
            row(8, "active", "remote", vec![entry(Some("aaaaaaaaaaaaaaaa"), Some("default"))]),
        ] {
            registry::write(&paths, &r).unwrap();
        }
        let chats = live_chats_with(&paths, new, |r| r.pid != 8);
        let got: Vec<(&str, &str)> = chats.iter().map(|c| (c.cwd.as_str(), c.account.as_str())).collect();
        assert_eq!(got, [("/w/3", UNKNOWN), ("/w/2", "spare"), ("/w/1", "default")], "the newest first; 4 runs on the new seal, 8's wrapper is gone");
        assert_eq!(chats[2].sid, "00000000-0000-4000-8000-000000000001");
        // The real check: this test process is no `ai-env-claude`, so none of its rows is confirmed.
        assert!(live_chats(&paths, new).is_empty());
    }
}
