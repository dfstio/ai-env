//! The deployer key's hand-over (S8 operators, `ai-env creds deployer-key`):
//! the JSON of `aws iam create-access-key --user-name ai-env-deployer
//! --output json` arrives on stdin, never from a terminal; the key id, then
//! the secret, goes on the clipboard of this Mac only, marked concealed
//! (`pasteboard`), for Mike to paste into the deployer's Strongbox entry, and
//! the clipboard is cleared after each Enter; both values are pasted back
//! from the saved entry with no echo and compared in constant time; then
//! `aws sts get-caller-identity`, with that key alone, must answer as
//! `ai-env-deployer` of the stack's account while IAM propagates. Only the
//! key id's last four characters are ever shown; stdout carries the `id` and
//! `arn` lines for `ops.sh key-issue`; after the parse, every failure (a
//! Ctrl-C included) prints the `aws iam delete-access-key` command of the
//! key that was not handed over. The deployer key is never stored on this
//! Mac. Contract: `plans/s8-operators-contracts.md` §6.
//!
//! Every prompt reads `/dev/tty` and nothing else, in every build: stdin is
//! the JSON pipe, so the debug builds' `AI_ENV_PASTE_STDIN` knob could only
//! answer the prompts from it. The stop handler ([`stop`]) also guards `ai-env
//! as deployer`'s two pastes.
//!
//! Phase 0 declares the module; wave 1 (W2b) builds it.
use crate::bridge::audit;
use crate::bridge::config::Paths;
use crate::bridge::creds::{cleanup_note, parse_input, read_input, recipe_line, unknown_key_note, with_note};
use crate::bridge::identity::{check_key, expected, EnvKey, KeyCheck, KeyWait, Mismatch, Verified, DEPLOYER_USER};
use crate::bridge::pasteboard::{self, Placed};
use crate::bridge::voice;
use crate::ceremony::{read_secret_dev_tty, trim_in_place};
use crate::errors::{CliError, Result};
use crate::store::Keystore;
use crate::wire::redact::{register_secret, Secret};
use std::collections::BTreeMap;
use std::io::IsTerminal as _;
use zeroize::Zeroizing;

/// What a failure past the parse did not do: the cleanup note's verb.
const WHAT: &str = "handed over";
/// The cleanup note's third line once the paste-back matched: the entry holds the key.
const CLEAR_ENTRY: &str = "\n  and clear the Strongbox entry (its history keeps the previous values)";
/// Paste-back rounds before the hand-over gives up.
const ROUNDS: u32 = 3;
/// The refusal of a terminal on stdin (exit 2), before anything is read.
pub const STDIN_IS_A_TERMINAL: &str = "stdin is a terminal: pipe the JSON of aws iam create-access-key --user-name ai-env-deployer --output json into this command; never paste it";
const NO_ACCOUNT: &str = "creds deployer-key: the stack's account is unknown here (no state/infra.toml, no [aws] ARN in bridge.toml): pass --account with its 12 digits";
const NO_TERMINAL: &str = "creds deployer-key: no terminal for the hand-over (the key is never shown or read anywhere else)";
/// An empty paste-back (exit 3; D19: one voice line with the cleanup note).
const NOTHING_PASTED: &str = "creds deployer-key: nothing was pasted back: cancelled, it was NOT handed over";
const DISCARDED: &str = "something was typed or pasted at the Enter prompt: discarded, never shown";
const PROMPT_PASTED: &str = "press Enter here when it is pasted: ";
const PROMPT_SAVED: &str = "press Enter here when the entry is saved: ";
const PROMPT_TRIED: &str = "press Enter here when you have tried: ";
/// The audit result of a hand-over a stop signal ended (§6.5's word for a cancel).
const STOPPED: &str = "cancelled";

/// The two values pasted back, in the order they are asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Id,
    Secret,
}

impl Part {
    fn name(self) -> &'static str {
        match self {
            Part::Id => "access key id",
            Part::Secret => "secret access key",
        }
    }

    fn prompt(self) -> &'static str {
        match self {
            Part::Id => "access key id (from Strongbox): ",
            Part::Secret => "secret access key (from Strongbox): ",
        }
    }
}

/// What one paste-back prompt read.
enum Pasted {
    /// The value, trimmed.
    Value(Zeroizing<String>),
    /// A paste that could not be read (a line over 4096 bytes, not UTF-8): why.
    Unreadable(String),
}

/// A value pasted back that does not match the one created: its length, or
/// why it could not be read.
enum Miss {
    Chars(usize),
    Unreadable(String),
}

/// How a paste-back ended without both values matching.
enum Unmatched {
    /// Nothing was pasted (exit 3).
    Cancelled,
    /// This value never matched in [`ROUNDS`] rounds (exit 1).
    Never(Part),
    /// A value could not be put back on the clipboard (osascript's error): the
    /// hand-over ends once the clipboard was cleared, saying how that went.
    Unplaced(CliError),
    /// An error the hand-over ends with, audited and with its cleanup note.
    Failed(CliError),
}

/// `ai-env creds deployer-key [--account ACCOUNT] [--clipboard-check]`.
///
/// Exits: 0 verified; 42 never answered; 9 another user's key (the JSON) or
/// an answer as another principal, the root or another account; 3 nothing
/// pasted back; 1 bad input, the account unknown, a paste-back that never
/// matched, a clipboard that could not be set; 2 a terminal on stdin; 5 no
/// terminal for the hand-over; 130, 143 and 129 a stop signal after the parse
/// (the stop handler: the clipboard cleared while it may hold a value of the
/// hand-over, the terminal's settings restored, the cleanup note, the audit
/// row). `--clipboard-check` puts a harmless marker on the clipboard the same
/// way, to try on another Apple device (it must not paste there), and clears it.
pub fn cmd_deployer_key(store: &Keystore, account: Option<&str>, clipboard_check: bool) -> Result<()> {
    // Nothing is unsealed: the deployer's key is never stored on this Mac.
    let _ = store;
    no_core_dumps();
    if clipboard_check {
        return check_the_clipboard();
    }
    if std::io::stdin().is_terminal() {
        return Err(CliError::Usage(STDIN_IS_A_TERMINAL.into()));
    }
    let input = read_input(&mut std::io::stdin().lock()).map_err(|e| with_note(e, &unknown_key_note(DEPLOYER_USER)))?;
    let parsed = parse_input(&input, DEPLOYER_USER, "hand over").map_err(|e| e.into_cli(DEPLOYER_USER, WHAT))?;
    drop(input);
    let note = cleanup_note(DEPLOYER_USER, &parsed.id, WHAT);
    // Registers both values with the scrubber (the parse registered the secret).
    let key = EnvKey::new(parsed.id.clone(), Zeroizing::new(parsed.secret.expose().clone())).map_err(|e| CliError::Msg(format!("{e}\n{note}")))?;
    drop(parsed);
    recipe_line(&format!("id {}", key.id()));
    let paths = Paths::resolve().map_err(|e| with_note(e.into(), &note))?;
    // Both notes are made here, before anything pasted back is registered
    // with the scrubber: a paste of the user's name would mask it in them.
    let matched = format!("{note}{CLEAR_ENTRY}");
    let mut handover = Handover { key, paths, notes: [note, matched], matched: false };
    let armed = stop::arm(&handover.notes, handover.stop_row());
    handover.run(account, armed)
}

/// Core dumps off for the rest of this process, the hard limit too (macOS
/// leaves it unlimited), as `ai-env edit` does: the secret passes through
/// buffers std never wipes (a child's environment and its envp) while the
/// hand-over runs for minutes.
fn no_core_dumps() {
    let off = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: setrlimit(2) reads a valid struct; a failure leaves the limit as it was.
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const off) };
}

/// One hand-over past the parse: every failure from here prints the cleanup
/// note and writes the audit row.
struct Handover {
    key: EnvKey,
    paths: Paths,
    /// The cleanup note before (0) and after (1) the paste-back matched, made
    /// before anything was pasted back.
    notes: [String; 2],
    /// The paste-back matched: the Strongbox entry holds the key now.
    matched: bool,
}

impl Handover {
    /// The cleanup note, with the third line once the paste-back matched.
    fn note(&self) -> &str {
        &self.notes[usize::from(self.matched)]
    }

    /// The audit row's detail with `result`.
    fn detail(&self, result: &str) -> BTreeMap<String, String> {
        audit::detail(&[("user", DEPLOYER_USER.to_string()), ("key_id_last4", self.key.tail().to_string()), ("result", result.to_string())])
    }

    /// The audit row `creds_deployer_key` (a failed write is a warning); a
    /// stop signal then writes none of its own.
    fn audit(&self, result: &str) {
        stop::audited();
        let row = audit::AuditRow::new(crate::bridge::audit::event::CREDS_DEPLOYER_KEY, None, self.detail(result));
        if let Err(e) = audit::append(&self.paths.audit(), &row) {
            voice::warn(&format!("the audit row was not written: {e}"));
        }
    }

    /// The row a stop signal writes (result `cancelled`) and the audit log it
    /// goes to, made now: the handler only puts the time in and writes it.
    /// `None` when the log cannot be opened: a stop then writes no row.
    fn stop_row(&self) -> Option<stop::Row> {
        let mut row = audit::AuditRow::new(crate::bridge::audit::event::CREDS_DEPLOYER_KEY, None, self.detail(STOPPED));
        row.ts = stop::TS_PLACEHOLDER.to_string();
        let mut line = serde_json::to_vec(&row).ok()?;
        line.push(b'\n');
        let ts_at = line.windows(stop::TS_PLACEHOLDER.len()).position(|w| w == stop::TS_PLACEHOLDER.as_bytes())?;
        let file = crate::bridge::logging::open_log_file(&self.paths.audit()).ok()?;
        Some(stop::Row { file, line, ts_at })
    }

    /// `e` as the hand-over ends with it: audited as `result`, the cleanup note appended.
    fn fail(&self, e: CliError, result: &str) -> CliError {
        self.audit(result);
        with_note(e, self.note())
    }

    /// A failure whose exit is not an error class (3, 42): its line and the
    /// cleanup note through one voice line (D19), then the bare exit.
    fn fail_with_exit(&self, text: &str, code: i32, result: &str) -> CliError {
        self.audit(result);
        voice::line(&format!("{text}\n{}", self.note()));
        CliError::Exit(code)
    }

    /// No terminal (any more) for the hand-over: exit 5.
    fn no_terminal(&self) -> CliError {
        self.fail(CliError::AuthUnavailable(NO_TERMINAL.into()), "no-terminal")
    }

    fn run(&mut self, account: Option<&str>, mut armed: stop::Armed) -> Result<()> {
        let exp = match expected(&self.paths, account) {
            Ok(exp) if exp.account.is_some() => exp,
            Ok(_) => return Err(self.fail(CliError::Msg(NO_ACCOUNT.into()), "no-account")),
            Err(e) => return Err(self.fail(prefixed(e), "no-account")),
        };
        if !armed.has_terminal() {
            return Err(self.no_terminal());
        }
        voice::note(&format!("hand-over of the {DEPLOYER_USER} access key ...{} to Strongbox (the clipboard stays on this Mac and is marked concealed; nothing is shown)", self.key.tail()));
        // From the first value placed until the paste-back's last clear, a stop
        // signal clears the clipboard too, through a clear spawned now (the
        // handler may only write a line and wait); without one it says so.
        armed.guard_clipboard(pasteboard::janitor().ok());
        self.round(Part::Id, "1/2: the access key id is on the clipboard: paste it into the Strongbox entry's user name field", PROMPT_PASTED)?;
        self.round(Part::Secret, "2/2: the secret access key is on the clipboard: paste it into the same entry's password field and save the entry", PROMPT_SAVED)?;
        self.paste_back()?;
        let checked = check_key(&self.key, DEPLOYER_USER, &exp, KeyWait::NEW_KEY, "the key");
        // Disarmed after the verdict: from here the outcome is printed as any other.
        drop(armed);
        self.verdict(checked)
    }

    fn value(&self, part: Part) -> &str {
        match part {
            Part::Id => self.key.id(),
            Part::Secret => self.key.expose_secret(),
        }
    }

    /// Put `part` on the clipboard, say `said`, wait for Enter at `prompt`,
    /// then clear the clipboard unless another copy came since, whatever the
    /// answer: a hand-over that ends at this prompt leaves nothing of the key
    /// there. A place that fails ends the hand-over once the clipboard was
    /// cleared: osascript may have set the value before it failed (killed at
    /// its timeout, or an answer that is not a change count).
    fn round(&self, part: Part, said: &str, prompt: &str) -> Result<()> {
        let placed = pasteboard::place(self.value(part)).map_err(|e| self.clipboard_failed(&e, &pasteboard::clear()))?;
        voice::note(said);
        let entered = self.enter(prompt);
        clear_if(&placed);
        entered
    }

    /// The clipboard could not be set (`e`): exit 1, saying whether the clear
    /// that followed (`cleared`) left nothing of the key there.
    fn clipboard_failed(&self, e: &CliError, cleared: &Result<()>) -> CliError {
        let left = match cleared {
            Ok(()) => "cleared, so nothing of the key is on it".to_string(),
            Err(c) => format!("it could not be cleared either ({c}): the key may be on it, clear it yourself"),
        };
        let text = format!(
            "the clipboard could not be set this-Mac-only and concealed ({e}): {left}. Delete the key, then create the deployer's key in the IAM console (Users → {DEPLOYER_USER} → Security credentials → Create access key), copy both into Strongbox there (never download the .csv), and check it with: ai-env as deployer -- true"
        );
        self.fail(CliError::Msg(text), "clipboard")
    }

    /// An Enter prompt on `/dev/tty`: anything typed or pasted there is
    /// discarded unseen (with a warning); no terminal ends the hand-over.
    fn enter(&self, prompt: &str) -> Result<()> {
        match read_secret_dev_tty(prompt) {
            Ok(answer) if answer.is_empty() => Ok(()),
            Err(CliError::AuthUnavailable(_)) => Err(self.no_terminal()),
            Ok(_) | Err(_) => {
                voice::warn(DISCARDED);
                Ok(())
            }
        }
    }

    /// One value pasted back from Strongbox: trimmed and registered with the
    /// scrubber (a wrong paste may be another secret). Nothing pasted is a
    /// cancel, no terminal ends the hand-over, and a paste that cannot be read
    /// is a value that does not match.
    fn read_back(&self, part: Part) -> std::result::Result<Pasted, Unmatched> {
        let mut pasted = match read_secret_dev_tty(part.prompt()) {
            Ok(pasted) => pasted,
            Err(CliError::AuthUnavailable(_)) => return Err(Unmatched::Failed(self.no_terminal())),
            Err(e) => return Ok(Pasted::Unreadable(e.to_string())),
        };
        trim_in_place(&mut pasted);
        if pasted.is_empty() {
            return Err(Unmatched::Cancelled);
        }
        register_secret(&pasted);
        Ok(Pasted::Value(pasted))
    }

    /// Both values pasted back and compared ([`Self::rounds`]). From the first
    /// paste-back prompt on, the clipboard may hold Strongbox's copy (or a
    /// wrong paste, maybe another secret), so every way out clears it: after a
    /// match with a note, after anything else quietly (a warning when it could
    /// not; a value that could not be put back says it in its own failure),
    /// before the failure is said.
    fn paste_back(&mut self) -> Result<()> {
        voice::note("now copy both back from the saved Strongbox entry and paste them here (nothing is shown)");
        let ended = self.rounds();
        if ended.is_ok() {
            // The entry holds the key from here: a stop's note asks to clear it too.
            self.matched = true;
            stop::matched();
        }
        let cleared = pasteboard::clear();
        stop::clipboard_clean();
        let unmatched = match ended {
            Ok(()) => {
                match cleared {
                    Ok(()) => voice::note("both match the key that was created; cleared the clipboard"),
                    Err(e) => {
                        voice::note("both match the key that was created");
                        voice::warn(&format!("the clipboard could not be cleared ({e}): clear it yourself"));
                    }
                }
                return Ok(());
            }
            Err(unmatched) => unmatched,
        };
        if let (Err(e), false) = (&cleared, matches!(unmatched, Unmatched::Unplaced(_))) {
            voice::warn(&format!("the clipboard could not be cleared ({e}): clear it yourself"));
        }
        Err(match unmatched {
            Unmatched::Cancelled => self.fail_with_exit(NOTHING_PASTED, 3, "cancelled"),
            Unmatched::Never(part) => {
                let text = format!("creds deployer-key: the {} pasted back never matched the one created ({ROUNDS} rounds): it was NOT handed over", part.name());
                self.fail(CliError::Msg(text), "mismatch")
            }
            Unmatched::Unplaced(e) => self.clipboard_failed(&e, &cleared),
            Unmatched::Failed(e) => e,
        })
    }

    /// At most [`ROUNDS`] rounds of constant-time comparisons, each asking only
    /// for the values not matched yet; a value that did not match goes back on
    /// the clipboard (place, Enter prompt, clear-if) before the next round.
    fn rounds(&self) -> std::result::Result<(), Unmatched> {
        let created = [(Part::Id, Secret::new(self.key.id().to_string())), (Part::Secret, Secret::new(self.key.expose_secret().to_string()))];
        let mut matched = [false, false];
        for round in 1..=ROUNDS {
            let mut missed: Vec<(Part, Miss)> = Vec::new();
            for (i, (part, want)) in created.iter().enumerate() {
                if matched[i] {
                    continue;
                }
                match self.read_back(*part)? {
                    Pasted::Value(pasted) if want.ct_eq(pasted.as_bytes()) => matched[i] = true,
                    Pasted::Value(pasted) => missed.push((*part, Miss::Chars(pasted.chars().count()))),
                    Pasted::Unreadable(why) => missed.push((*part, Miss::Unreadable(why))),
                }
            }
            let Some(&(first, _)) = missed.first() else { return Ok(()) };
            if round == ROUNDS {
                return Err(Unmatched::Never(first));
            }
            for (part, miss) in missed {
                // A failed place ends the rounds: paste_back clears the clipboard, then says how that went.
                let placed = pasteboard::place(self.value(part)).map_err(Unmatched::Unplaced)?;
                let want = self.value(part).chars().count();
                let got = match miss {
                    Miss::Chars(n) => format!("{n} characters, expected {want}"),
                    Miss::Unreadable(why) => format!("{why}; expected {want} characters"),
                };
                voice::note(&format!(
                    "the {} pasted back does not match the one created ({got}): it is on the clipboard again: paste it into the entry, save it, then paste it back here",
                    part.name()
                ));
                // A failed Enter prompt leaves the value there: paste_back clears it.
                self.enter(PROMPT_SAVED).map_err(Unmatched::Failed)?;
                clear_if(&placed);
            }
        }
        Ok(())
    }

    /// The sts check's verdict: `arn` on stdout for any answer, then exit 0,
    /// 9 (another principal, the root, another account or ARN) or 42 (no answer).
    fn verdict(&self, checked: std::result::Result<Verified, KeyCheck>) -> Result<()> {
        let tail = self.key.tail();
        let (result, text) = match checked {
            Ok(v) => {
                recipe_line(&format!("arn {}", v.arn));
                self.audit("verified");
                voice::note(&format!("the access key ...{tail} answers as user/{DEPLOYER_USER}: it is in Strongbox only; ai-env as deployer -- … asks for it"));
                return Ok(());
            }
            Err(KeyCheck::Mismatch(v, why)) => {
                recipe_line(&format!("arn {}", v.arn));
                match why {
                    Mismatch::Root { .. } => ("root", format!("the key ...{tail} is the account ROOT's: never paste it here (the deployer's key is its own Strongbox entry); delete root's access key")),
                    Mismatch::OtherPrincipal { arn } => ("other-principal", format!("the key ...{tail} answers as {arn}, not {DEPLOYER_USER}")),
                    Mismatch::OtherAccount { account, want, source, .. } => ("other-account", format!("the key ...{tail} is {DEPLOYER_USER} of account {account}, but the stack ({source}) is in account {want}")),
                    Mismatch::OtherArn { arn, want, source } => ("other-arn", format!("the key ...{tail} answers as {arn}, but the stack's deployer is {want} ({source})")),
                }
            }
            Err(KeyCheck::Refused(last) | KeyCheck::Failed(last)) => {
                let wait = KeyWait::NEW_KEY;
                let text = format!("creds deployer-key: the key ...{tail} never answered ({} tries, {} s apart; last: {last}): it was NOT handed over", wait.tries, wait.step.as_secs());
                return Err(self.fail_with_exit(&text, 42, "never-answered"));
            }
        };
        Err(self.fail(CliError::Policy(format!("creds deployer-key: {text}: it was NOT handed over")), result))
    }
}

/// An error of `expected` (an ambiguous account, a malformed `--account`, an
/// unreadable state) with the command's name, keeping its class.
fn prefixed(e: CliError) -> CliError {
    let add = |m: String| format!("creds deployer-key: {m}");
    match e {
        CliError::Msg(m) => CliError::Msg(add(m)),
        CliError::Usage(m) => CliError::Usage(add(m)),
        CliError::AuthUnavailable(m) => CliError::AuthUnavailable(add(m)),
        CliError::Policy(m) => CliError::Policy(add(m)),
        other => other,
    }
}

/// Clear the clipboard unless another copy came since `placed`.
fn clear_if(placed: &Placed) {
    match pasteboard::clear_if_unchanged(placed) {
        Ok(true) => voice::note("cleared the clipboard"),
        Ok(false) => voice::warn("the clipboard changed since (another copy): left as it is — make sure the key is not on it"),
        Err(e) => voice::warn(&format!("the clipboard could not be cleared ({e}): clear it yourself")),
    }
}

/// The `i`-th of the 62 letters and digits (`i` below 62): A-Z, a-z, 0-9.
fn alphanumeric(i: u8) -> char {
    char::from(match i {
        0..=25 => b'A' + i,
        26..=51 => b'a' + (i - 26),
        _ => b'0' + (i - 52),
    })
}

/// Twelve letters and digits from the OS random source: the clipboard
/// check's marker (not a secret).
fn marker() -> Result<String> {
    let mut out = String::with_capacity(12);
    while out.len() < 12 {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| CliError::Msg(format!("getrandom failed: {e}")))?;
        // 248 = 4 × 62: below it every character is equally likely.
        for b in bytes.into_iter().filter(|b| *b < 248) {
            if out.len() < 12 {
                out.push(alphanumeric(b % 62));
            }
        }
    }
    Ok(out)
}

/// `--clipboard-check` (Mike's part-B check before the first hand-over): a
/// harmless marker goes on the clipboard exactly as the key would, he tries
/// to paste it on another Apple device (it must not paste there), presses
/// Enter, and it is cleared. No stdin is read and no key is involved. A place
/// that fails is followed by a clear, as at the hand-over.
fn check_the_clipboard() -> Result<()> {
    if std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").is_err() {
        return Err(CliError::AuthUnavailable("creds deployer-key --clipboard-check: no terminal (/dev/tty) to wait on: nothing was put on the clipboard".into()));
    }
    let marker = marker()?;
    let placed = pasteboard::place(&marker).map_err(|e| {
        let left = match pasteboard::clear() {
            Ok(()) => "cleared, so the marker is not on it".to_string(),
            Err(c) => format!("it could not be cleared either ({c}): clear it yourself"),
        };
        CliError::Msg(format!("clipboard check: the clipboard could not be set this-Mac-only and concealed ({e}): {left}"))
    })?;
    voice::note(&format!("clipboard check: the marker {marker} is on the clipboard, this Mac only and concealed: try to paste it on another Apple device now; it must NOT paste there"));
    // The marker is cleared whatever the answer was; as at the hand-over's
    // Enter prompts, what was typed is discarded unseen.
    let answered = read_secret_dev_tty(PROMPT_TRIED);
    clear_if(&placed);
    match answered {
        Ok(answer) if answer.is_empty() => Ok(()),
        Ok(_) | Err(CliError::Msg(_)) => {
            voice::warn(DISCARDED);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// The stop handler of the hand-over: SIGINT, SIGTERM and SIGHUP after the
/// parse end the process with 130, 143 and 129. First it restores `/dev/tty`'s
/// settings (`TCSAFLUSH`: a prompt may have turned its echo off, and the rest
/// of a paste is dropped) and, while the clipboard may hold a value of the
/// hand-over, clears it through the janitor [`Armed::guard_clipboard`] was
/// given (a warning when it could not); then it writes the cleanup note on
/// stderr and the audit row (result `cancelled`) unless the hand-over wrote
/// its own. Everything the handler touches is made before it is installed and
/// never freed: the notes, the warning, the row, the saved settings and the
/// descriptors; it only loads atomics and makes async-signal-safe calls
/// (`tcsetattr`, `write`, `waitpid`, `poll`, `kill`, `time`, `fsync`,
/// `_exit`). A signal ignored when it is armed stays ignored. `ai-env as
/// deployer` arms it too, around its two pastes (its note, no audit row): one
/// process arms it at most once at a time.
pub(crate) mod stop {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};
    use std::time::{Duration, Instant};

    const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
    /// The stop row's `ts` until the handler writes the time there (as long as
    /// `YYYY-MM-DDTHH:MM:SSZ`).
    pub(super) const TS_PLACEHOLDER: &str = "0000-00-00T00:00:00Z";
    /// The longest stop row the handler writes (it copies the row onto its stack).
    const ROW_MAX: usize = 512;
    /// How long the handler waits for the clipboard's clear (an osascript's
    /// own bound), in steps of [`STEP_MS`].
    const CLEAR_WAIT_MS: libc::c_int = 10_000;
    const STEP_MS: libc::c_int = 20;
    /// The handler's warning when the clipboard could not be cleared.
    const NOT_CLEARED: &str = "the clipboard could not be cleared: clear it yourself";

    /// The audit row a stop writes, and the log it goes to (`O_APPEND`).
    pub(crate) struct Row {
        pub(super) file: std::fs::File,
        /// The row and its line break, its `ts` [`TS_PLACEHOLDER`] at `ts_at`.
        pub(super) line: Vec<u8>,
        pub(super) ts_at: usize,
    }

    /// What the handler writes: leaked when armed, never written or freed after.
    struct Said {
        /// A line break when stderr is a terminal (the cursor may be on a prompt).
        lead: &'static [u8],
        /// The cleanup note before (0) and after (1) the paste-back matched.
        notes: [&'static [u8]; 2],
        not_cleared: &'static [u8],
        /// The stop's audit row (empty: none), its `ts` at `ts_at`.
        row: &'static [u8],
        ts_at: usize,
    }

    static SAID: AtomicPtr<Said> = AtomicPtr::new(std::ptr::null_mut());
    static MATCHED: AtomicBool = AtomicBool::new(false);
    /// The clipboard may hold a value of the hand-over, or Strongbox's copy of one.
    static DIRTY: AtomicBool = AtomicBool::new(false);
    /// `/dev/tty` while armed, else -1.
    static TTY: AtomicI32 = AtomicI32::new(-1);
    /// Its settings when the handler was armed: a leaked `termios`.
    static SAVED: AtomicPtr<libc::termios> = AtomicPtr::new(std::ptr::null_mut());
    /// The audit log while the stop's row is still to be written, else -1.
    static AUDIT: AtomicI32 = AtomicI32::new(-1);
    /// The janitor's stdin and pid while armed, else -1.
    static JANITOR: AtomicI32 = AtomicI32::new(-1);
    static JANITOR_PID: AtomicI32 = AtomicI32::new(-1);

    /// The handler, installed until this drops (the previous dispositions come back).
    pub(crate) struct Armed {
        previous: Vec<(libc::c_int, libc::sigaction)>,
        tty: Option<std::fs::File>,
        /// The audit log the stop's row goes to, held open while armed (the
        /// handler writes to its descriptor).
        _audit: Option<std::fs::File>,
        /// The clear a stop asks for (`pasteboard::janitor`).
        janitor: Option<std::process::Child>,
    }

    impl Armed {
        /// Whether `/dev/tty` could be opened: the hand-over needs it.
        pub(crate) fn has_terminal(&self) -> bool {
            self.tty.is_some()
        }

        /// From now until [`clipboard_clean`] (or the drop), a stop clears the
        /// clipboard through `janitor` (`pasteboard::janitor`), or warns that it
        /// could not.
        pub(crate) fn guard_clipboard(&mut self, janitor: Option<std::process::Child>) {
            if let Some(j) = janitor {
                if let (Some(stdin), Ok(pid)) = (&j.stdin, i32::try_from(j.id())) {
                    JANITOR_PID.store(pid, Ordering::SeqCst);
                    JANITOR.store(stdin.as_raw_fd(), Ordering::SeqCst);
                }
                self.janitor = Some(j);
            }
            DIRTY.store(true, Ordering::SeqCst);
        }
    }

    /// `bytes`, leaked: the handler may read them at any time from now on.
    fn leak(bytes: Vec<u8>) -> &'static [u8] {
        Box::leak(bytes.into_boxed_slice())
    }

    /// Install the handler with `notes` (before and after [`matched`]) and the
    /// stop's audit `row`.
    pub(crate) fn arm(notes: &[String; 2], row: Option<Row>) -> Armed {
        use std::io::IsTerminal as _;
        let prefix = crate::bridge::voice::prefix();
        let lead: &'static [u8] = if std::io::stderr().is_terminal() { b"\n" } else { b"" };
        let (line, ts_at, audit) = match row {
            Some(Row { file, line, ts_at }) if line.len() <= ROW_MAX && ts_at + TS_PLACEHOLDER.len() <= line.len() => (line, ts_at, Some(file)),
            _ => (Vec::new(), 0, None),
        };
        let said = Said {
            lead,
            notes: [leak(format!("{prefix}: {}\n", notes[0]).into_bytes()), leak(format!("{prefix}: {}\n", notes[1]).into_bytes())],
            not_cleared: leak(format!("{prefix}: warning: {NOT_CLEARED}\n").into_bytes()),
            row: leak(line),
            ts_at,
        };
        SAID.store(Box::into_raw(Box::new(said)), Ordering::SeqCst);
        MATCHED.store(false, Ordering::SeqCst);
        DIRTY.store(false, Ordering::SeqCst);
        AUDIT.store(audit.as_ref().map_or(-1, |f| f.as_raw_fd()), Ordering::SeqCst);
        let tty = std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC).open("/dev/tty").ok();
        if let Some(t) = &tty {
            // SAFETY: tcgetattr(3) fills a zeroed (valid) termios from an open descriptor.
            let mut saved: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(t.as_raw_fd(), &raw mut saved) } == 0 {
                SAVED.store(Box::into_raw(Box::new(saved)), Ordering::SeqCst);
                TTY.store(t.as_raw_fd(), Ordering::SeqCst);
            }
        }
        let mut previous = Vec::new();
        let handler: extern "C" fn(libc::c_int) = on_stop;
        for sig in SIGNALS {
            // SAFETY: sigaction(2) on zeroed (valid) structs; the handler is
            // async-signal-safe (see the module's doc).
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, std::ptr::null(), &raw mut old) != 0 || old.sa_sigaction == libc::SIG_IGN {
                    continue;
                }
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = handler as libc::sighandler_t;
                libc::sigemptyset(&raw mut act.sa_mask);
                for s in SIGNALS {
                    libc::sigaddset(&raw mut act.sa_mask, s);
                }
                if libc::sigaction(sig, &raw const act, std::ptr::null_mut()) == 0 {
                    previous.push((sig, old));
                }
            }
        }
        Armed { previous, tty, _audit: audit, janitor: None }
    }

    /// The paste-back matched: the handler's note asks to clear the entry too.
    pub(super) fn matched() {
        MATCHED.store(true, Ordering::SeqCst);
    }

    /// The clipboard holds nothing of the hand-over any more: a stop leaves it alone.
    pub(super) fn clipboard_clean() {
        DIRTY.store(false, Ordering::SeqCst);
    }

    /// The hand-over wrote its audit row: a stop writes none.
    pub(super) fn audited() {
        AUDIT.store(-1, Ordering::SeqCst);
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            for fd in [&TTY, &AUDIT, &JANITOR, &JANITOR_PID] {
                fd.store(-1, Ordering::SeqCst);
            }
            DIRTY.store(false, Ordering::SeqCst);
            for (sig, old) in self.previous.drain(..).rev() {
                // SAFETY: restores a disposition sigaction(2) itself returned.
                unsafe { libc::sigaction(sig, &raw const old, std::ptr::null_mut()) };
            }
            if let Some(mut janitor) = self.janitor.take() {
                // The end of its input: it exits without clearing.
                drop(janitor.stdin.take());
                let deadline = Instant::now() + Duration::from_secs(2);
                while matches!(janitor.try_wait(), Ok(None)) {
                    if Instant::now() > deadline {
                        let _ = janitor.kill();
                        let _ = janitor.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    /// Write all of `bytes` to `fd`, retrying an interrupted write.
    fn write_all(fd: libc::c_int, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            // SAFETY: write(2) of a valid buffer; it is async-signal-safe.
            let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if n > 0 {
                bytes = &bytes[usize::try_from(n).unwrap_or(bytes.len()).min(bytes.len())..];
            } else if n == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
    }

    /// Ask the janitor to clear the clipboard and wait for its exit, at most
    /// [`CLEAR_WAIT_MS`]: whether it cleared.
    fn clear_now() -> bool {
        let (fd, pid) = (JANITOR.load(Ordering::SeqCst), JANITOR_PID.load(Ordering::SeqCst));
        if fd < 0 || pid <= 0 {
            return false;
        }
        write_all(fd, b"clear\n");
        let mut waited = 0;
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid(2) on this process's child; it is async-signal-safe.
            let r = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
            if r == pid {
                return libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            }
            if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return false;
            }
            if waited >= CLEAR_WAIT_MS {
                // SAFETY: kill(2) of this process's child, not reaped; it is async-signal-safe.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                return false;
            }
            // SAFETY: poll(2) without descriptors only sleeps; it is async-signal-safe.
            unsafe { libc::poll(std::ptr::null_mut(), 0, STEP_MS) };
            waited += STEP_MS;
        }
    }

    /// The stop's audit row stamped now, in one `write` (`O_APPEND`), then synced.
    fn write_row(said: &Said) {
        let fd = AUDIT.swap(-1, Ordering::SeqCst);
        let (row, at) = (said.row, said.ts_at);
        if fd < 0 || row.is_empty() || row.len() > ROW_MAX || at + TS_PLACEHOLDER.len() > row.len() {
            return;
        }
        let mut buf = [0u8; ROW_MAX];
        buf[..row.len()].copy_from_slice(row);
        // SAFETY: time(3) with a null pointer only returns the time; it is async-signal-safe.
        let now = unsafe { libc::time(std::ptr::null_mut()) };
        buf[at..at + TS_PLACEHOLDER.len()].copy_from_slice(&rfc3339(u64::try_from(now).unwrap_or(0)));
        write_all(fd, &buf[..row.len()]);
        // SAFETY: fsync(2) of the open audit log; it is async-signal-safe.
        unsafe { libc::fsync(fd) };
    }

    /// `YYYY-MM-DDTHH:MM:SSZ` of Unix `secs`, as `wire::time::rfc3339_utc`
    /// writes it, without allocating: the handler calls it.
    fn rfc3339(secs: u64) -> [u8; 20] {
        let days = i64::try_from(secs / 86_400).unwrap_or(0);
        let rem = secs % 86_400;
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        let mut out = *b"0000-00-00T00:00:00Z";
        let civil = |v: i64| u64::try_from(v).unwrap_or(0);
        for (at, width, value) in [(0, 4, civil(year)), (5, 2, civil(month)), (8, 2, civil(day)), (11, 2, rem / 3600), (14, 2, rem % 3600 / 60), (17, 2, rem % 60)] {
            let mut value = value;
            for slot in out[at..at + width].iter_mut().rev() {
                *slot = b'0' + (value % 10) as u8;
                value /= 10;
            }
        }
        out
    }

    extern "C" fn on_stop(sig: libc::c_int) {
        let (fd, saved) = (TTY.load(Ordering::SeqCst), SAVED.load(Ordering::SeqCst));
        if fd >= 0 && !saved.is_null() {
            // SAFETY: tcsetattr(3) is async-signal-safe; `saved` is a leaked termios, `fd` the open /dev/tty.
            unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, saved) };
        }
        let cleared = !DIRTY.load(Ordering::SeqCst) || clear_now();
        // SAFETY: a leaked Said, never written or freed after it was stored.
        if let Some(said) = unsafe { SAID.load(Ordering::SeqCst).as_ref() } {
            write_all(2, said.lead);
            if !cleared {
                write_all(2, said.not_cleared);
            }
            write_all(2, said.notes[usize::from(MATCHED.load(Ordering::SeqCst))]);
            write_row(said);
        }
        // SAFETY: _exit(2) is async-signal-safe and ends the process at once.
        unsafe { libc::_exit(128 + sig) }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::Path;

        /// `sig`'s handler as sigaction(2) reports it, read only.
        fn disposition(sig: libc::c_int) -> libc::sighandler_t {
            // SAFETY: a null new action only reads the current one into a zeroed (valid) struct.
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                assert_eq!(libc::sigaction(sig, std::ptr::null(), &raw mut old), 0);
                old.sa_sigaction
            }
        }

        /// The handler, end to end, in children of this test binary (as
        /// `signals`' hand-off test, F26: this test process keeps its stop
        /// signals' dispositions), each in a session of its own without a
        /// controlling terminal, so the handler never touches the settings of
        /// the terminal running these tests. With SIGHUP at its default:
        /// armed, it is SIGHUP's handler; disarmed, the default is back; armed
        /// again, the clipboard guarded (the fake osascript behind a janitor)
        /// and matched, a SIGHUP clears the clipboard, writes the second note
        /// on stderr and the stop's audit row stamped now, and ends the child
        /// with 129. With SIGHUP ignored, it stays ignored, armed or not.
        #[test]
        fn a_stop_writes_the_note_and_exits_128_plus_the_signal() {
            const TEST: &str = "bridge::handover::stop::tests::a_stop_writes_the_note_and_exits_128_plus_the_signal";
            // The child's mark: its parent's pid, which no exported value matches.
            const PARENT: &str = "AI_ENV_TEST_HANDOVER_STOP_PARENT";
            const DIR: &str = "AI_ENV_TEST_HANDOVER_STOP_DIR";
            let notes = ["first note".to_string(), "second note\n  and the third line".to_string()];
            if std::env::var(PARENT).ok() == Some(std::os::unix::process::parent_id().to_string()) {
                let dir = std::path::PathBuf::from(std::env::var_os(DIR).expect("the parent names the directory"));
                if disposition(libc::SIGHUP) == libc::SIG_IGN {
                    let armed = arm(&notes, None);
                    assert_eq!(disposition(libc::SIGHUP), libc::SIG_IGN, "an ignored SIGHUP stays ignored");
                    // SAFETY: raise(3) on this child, which ignores SIGHUP.
                    unsafe { libc::raise(libc::SIGHUP) };
                    drop(armed);
                    assert_eq!(disposition(libc::SIGHUP), libc::SIG_IGN);
                    return;
                }
                let was = disposition(libc::SIGHUP);
                let armed = arm(&notes, None);
                assert_eq!(disposition(libc::SIGHUP), on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t, "installed");
                drop(armed);
                let stored = [&TTY, &AUDIT, &JANITOR, &JANITOR_PID].map(|a| a.load(Ordering::SeqCst));
                assert_eq!((disposition(libc::SIGHUP), stored), (was, [-1; 4]), "disarmed");
                // A stop row as the hand-over makes one, its time at byte 7.
                let line = format!("{{\"ts\":\"{TS_PLACEHOLDER}\",\"event\":\"creds_deployer_key\"}}\n").into_bytes();
                let file = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("audit.jsonl")).unwrap();
                let mut armed = arm(&notes, Some(Row { file, line, ts_at: 7 }));
                armed.guard_clipboard(Some(crate::bridge::pasteboard::janitor_with(&dir.join("osascript")).unwrap()));
                matched();
                // SAFETY: raise(3) on this child, whose handler ends it.
                unsafe { libc::raise(libc::SIGHUP) };
                unreachable!("the handler ends the process");
            }
            use std::os::unix::fs::PermissionsExt as _;
            use std::os::unix::process::CommandExt as _;
            let d = tempfile::tempdir().unwrap();
            let fake = d.path().join("osascript");
            std::fs::write(&fake, format!("#!/bin/sh\n[ \"${{1:-}}\" = --warm ] && exit 0\nexec /bin/sh '{}' \"$@\"\n", Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/osascript.sh").display())).unwrap();
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
            // macOS takes seconds over the first exec of a new file: paid here,
            // never inside the handler's wait for the clear.
            assert!(std::process::Command::new(&fake).arg("--warm").status().unwrap().success());
            let log = d.path().join("osa.log");
            let before = SIGNALS.map(disposition);
            let run = |hup: libc::sighandler_t| {
                let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
                cmd.args([TEST, "--exact", "--test-threads=1", "--nocapture"])
                    .env(PARENT, std::process::id().to_string())
                    .env(DIR, d.path())
                    .env("FAKE_OSA_LOG", &log)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped());
                // A session of its own, without a controlling terminal, SIGHUP
                // as `hup` whatever this test run inherited (`nohup` ignores it).
                // SAFETY: runs in the forked child before exec; setsid(2) and signal(3) are async-signal-safe.
                unsafe {
                    cmd.pre_exec(move || {
                        libc::setsid();
                        libc::signal(libc::SIGHUP, hup);
                        Ok(())
                    });
                }
                let child = {
                    // Held across the spawn, as every fork of these tests holds it (`test_locks`).
                    let _fork = crate::test_locks::forking();
                    cmd.spawn().unwrap()
                };
                child.wait_with_output().unwrap()
            };
            let start = crate::wire::time::unix_now();
            let out = run(libc::SIG_DFL);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(129), "{stderr}");
            assert!(stderr.ends_with("ai-env: second note\n  and the third line\n") && !stderr.contains("first note") && !stderr.contains("could not be cleared"), "{stderr}");
            assert_eq!(std::fs::read_to_string(&log).unwrap_or_default(), "clear cleared\n", "the janitor cleared the clipboard");
            let row = std::fs::read_to_string(d.path().join("audit.jsonl")).unwrap();
            let ts = row.strip_prefix("{\"ts\":\"").and_then(|r| r.strip_suffix("\",\"event\":\"creds_deployer_key\"}\n")).unwrap_or_else(|| panic!("{row}"));
            let at = crate::wire::time::parse_rfc3339_utc(ts).unwrap_or_else(|| panic!("{ts}"));
            assert!(start <= at && at <= crate::wire::time::unix_now(), "stamped when it stopped: {ts}");
            let out = run(libc::SIG_IGN);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(0), "{stderr}");
            assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed") && !stderr.contains("note"), "{stderr}");
            assert_eq!(SIGNALS.map(disposition), before, "this test process keeps its stop signals' dispositions");
        }

        /// The handler stamps its row as the audit writer does, without allocating.
        #[test]
        fn the_stop_row_is_stamped_as_the_audit_writer_stamps() {
            for secs in [0, 951_782_400, 1_791_980_750, 4_102_444_800, 253_402_300_799] {
                assert_eq!(std::str::from_utf8(&rfc3339(secs)).unwrap(), crate::wire::time::rfc3339_utc(secs), "{secs}");
            }
            assert_eq!(TS_PLACEHOLDER.len(), rfc3339(0).len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clipboard_marker_is_twelve_letters_and_digits() {
        let (a, b) = (marker().unwrap(), marker().unwrap());
        for m in [&a, &b] {
            assert!(m.len() == 12 && m.bytes().all(|c| c.is_ascii_alphanumeric()), "{m}");
        }
        assert_ne!(a, b, "random");
        let all: String = (0..62).map(alphanumeric).collect();
        assert_eq!(all.len(), 62);
        assert!(all.starts_with("ABC") && all.contains("Zab") && all.contains("z01") && all.ends_with("789"), "{all}");
        let unique: std::collections::BTreeSet<char> = all.chars().collect();
        assert!(unique.len() == 62 && all.bytes().all(|c| c.is_ascii_alphanumeric()), "each once: {all}");
    }

    #[test]
    fn errors_of_the_account_keep_their_class_and_name_the_command() {
        let e = prefixed(CliError::Usage("--account 12: expected the 12 digits of an AWS account".into()));
        assert_eq!((e.exit_code(), e.to_string().as_str()), (2, "creds deployer-key: --account 12: expected the 12 digits of an AWS account"));
        assert_eq!(prefixed(CliError::Msg("x".into())).to_string(), "creds deployer-key: x");
        assert_eq!(prefixed(CliError::Cancelled).exit_code(), 3);
        assert_eq!((Part::Id.name(), Part::Secret.name()), ("access key id", "secret access key"));
        assert_eq!((Part::Id.prompt(), Part::Secret.prompt()), ("access key id (from Strongbox): ", "secret access key (from Strongbox): "));
    }
}
