//! `ai-env creds account check [NAME…] [--json] [--model M]` (S10 addendum
//! A1, §6): one tiny turn per Claude account on this Mac's claude (the
//! Cursor bundle's, else PATH's), one Touch ID each, and the usage Anthropic
//! reports of the account: its 5-hour and weekly windows with their resets,
//! or the limit it hit. A setup-token cannot read its own limits (its scope
//! is `user:inference`), so a turn is the only way: `--model haiku`, the
//! cheapest that still reports both windows, by default.
//!
//! Before any Touch ID: the names (exit 2 for a bad or an unknown one) and
//! the model; `[creds]`; the accounts (reconciled, as every `creds account`
//! command; none, or a store that cannot be read: exit 1); the claude and
//! its version (none: exit 1); each account's file read once and its seal
//! looked up in the refusal record. A refused seal is shown with no Touch
//! ID, as is a `credentials/accounts/<name>.env` that is no container (a
//! plaintext file may hold a token in the clear: `not_checked`, design §4
//! step 5); a record that cannot be read refuses the whole check (exit 5,
//! M53).
//!
//! Then one account at a time, never two tokens held:
//! 1. its token unsealed (`credential::unseal_account`: one Touch ID under
//!    `state/unseal.lock`, the countdown and `[creds].unseal_timeout_s`, a
//!    stop closing the dialog; bytes sealed anew since they were read are
//!    refused before it);
//! 2. claude run once ([`run_claude`]): [`argv`] pinned (`--tools` is
//!    variadic, so `--tools ""` is followed by another option; never
//!    `--bare`, which ignores the token); an empty environment but
//!    [`run_env`]'s (`PATH`, a fresh `HOME` under
//!    `state/tmp/account-check-<pid>-*`, 0700 and removed after, with
//!    `CLAUDE_CONFIG_DIR` in it, `DISABLE_AUTOUPDATER=1`, `TZ=UTC`); stdin
//!    `/dev/null`; the token on fd 3
//!    (`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3`), or in its environment
//!    under `[creds] deliver = "env"`, dropped at the spawn (never in argv or
//!    a log); its own process group, ended when the run is dropped (a stop);
//!    60 s in all, 5 s to exit once its result came, then 2 s to drain;
//! 3. the verdict, first match ([`judge`]): Anthropic refusing the token
//!    (HTTP 401, `AuthWatch`) is `refused`, recorded against the seal
//!    (`credential::record_rejection`); a usage-limit result is `limited`;
//!    an answer is `checked`, with its `rate_limit_event`'s windows or none
//!    reported; anything else `failed`. `checked` and `limited` are recorded
//!    in the store's `[usage.<name>]` (`source = "check"`) and audited
//!    `account_check`.
//!
//! A dismissed dialog ends the check with 3, a Touch ID deadline with 5, a
//! missing keystore key with 4, Ctrl-C with 130, SIGTERM or SIGHUP with 143;
//! the accounts done are still shown. Otherwise it exits 5 when an account
//! was refused or could not be checked, else 1 when a run failed, else 0.
//!
//! LEAD (A1 merge): the parsing of the `rate_limit_event` and of the result
//! ([`info_of`], [`limit_of`], [`LIMIT_NAMES`], [`when`], [`pct`]) is a
//! private stand-in for slice B's `wire::ratelimit` (`parse_info`,
//! `parse_limit_result`, `LIMIT_NAMES`, `when`, `pct`), and [`record_usage`]
//! for its `accounts::usage::{apply, record_all}`: switch to them at the
//! merge, keeping these lines' formats.
use super::{audit_event, check_name, AccountFile};
use crate::bridge::agent::credential;
use crate::bridge::authwatch::{AuthWatch, Stream};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::setup_token::SetupToken;
use crate::bridge::signals::{stoppable, Stops};
use crate::bridge::vm::cmd::{audit_event as audit_row, runtime, Ctx};
use crate::bridge::voice;
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::Keystore;
use crate::wire::frame::Deliver;
use crate::wire::ndjson::LineSplitter;
use crate::wire::redact::scrub;
use crate::wire::time::{parse_rfc3339_utc, rfc3339_utc, unix_now};
use serde_json::Value;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt as _;

/// The one turn's prompt.
const PROMPT: &str = "Reply with exactly OK";
/// One run's bound, from its spawn.
const RUN_LIMIT: Duration = Duration::from_secs(60);
/// Once its result came: claude's time to exit before its group is ended.
const EXIT_GRACE: Duration = Duration::from_secs(5);
/// After its exit (or its end): how long what it wrote just before is still read.
const DRAIN: Duration = Duration::from_secs(2);
/// From TERM to KILL when its group is ended.
const KILL_AFTER: Duration = Duration::from_millis(500);
/// `claude --version`'s bound.
const VERSION_LIMIT: Duration = Duration::from_secs(10);
/// stdout's lines are cut at 1 MiB (a longer one is dropped).
const LINE_CAP: usize = 1 << 20;
/// What is kept of its stderr: the last 4 KiB.
const STDERR_KEEP: usize = 4096;
/// The `PATH` every run has, and nothing of ai-env's environment.
const RUN_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// Where a refusal the check saw is recorded as seen (`state/creds.toml`'s
/// `vm`, `credential_rejected`'s `id`): no VM.
const WHERE: &str = "this Mac (creds account check)";
/// The token's descriptor in the child.
const TOKEN_FD: libc::c_int = 3;

/// The limits by `rateLimitType`: how claude names each in "You've hit your
/// X · resets …" (2.1.305's bundle), and the word a `limited:` line uses.
pub const LIMIT_NAMES: [(&str, &str, &str); 6] = [
    ("five_hour", "session limit", "5-hour"),
    ("seven_day", "weekly limit", "weekly"),
    ("seven_day_opus", "Opus limit", "Opus"),
    ("seven_day_sonnet", "Sonnet limit", "Sonnet"),
    ("seven_day_overage_included", "Fable limit", "Fable"),
    ("overage", "usage credit limit", "usage credit"),
];

// ---- the command --------------------------------------------------------------------------

/// `ai-env creds account check [NAME…] [--json] [--model M]` (see the module doc).
pub fn cmd_check(store: &Keystore, names: &[String], json: bool, model: &str) -> Result<()> {
    // Before anything could listen: a signal ignored when ai-env started stays ignored (`signals`).
    crate::bridge::signals::note_dispositions();
    for name in names {
        check_name(name)?;
    }
    if !valid_model(model) {
        return Err(CliError::Usage(format!("--model {:?} is not a model name (1-64 of A-Z a-z 0-9 . [ ] _ -, the first a letter or a digit)", scrub(model))));
    }
    let paths = Paths::resolve()?;
    let _ = crate::bridge::logging::init(&crate::bridge::logging::LogOpts { path: paths.cli_log(), rust_log: std::env::var("RUST_LOG").ok() });
    let cfg = BridgeConfig::load(&paths)?.unwrap_or_default();
    cfg.creds.validate()?;
    let view = super::reconcile(&paths)?;
    let unsealed = super::unsealed_files(&paths).map_err(CliError::Msg)?;
    if view.files.is_empty() && unsealed.is_empty() {
        return Err(CliError::Msg("no Claude account is sealed: `ai-env creds account add NAME` seals one (what `claude setup-token` prints, logged in as that account)".into()));
    }
    let chosen = chosen(&view.files, &unsealed, view.state.active.as_deref(), names)?;
    let claude = crate::bridge::vm::lab_mac::mac_claude().ok_or_else(|| CliError::Msg("no claude on this Mac (the Cursor extension's, or one on PATH): the check runs one turn of it per account".into()))?;
    let version = claude_version(&paths, &claude);
    let mut planned = Vec::new();
    for pick in chosen {
        planned.push(plan(&paths, pick, view.state.active.as_deref() == Some(pick.name()))?);
    }
    let ctx = Ctx { paths, cfg, knobs: crate::bridge::lab::vm_knobs() };
    let active = ctx.knobs.active();
    if !active.is_empty() {
        voice::note(&format!("LAB KNOBS ACTIVE ({}): not the real service (debug build)", active.join(", ")));
    }
    let deliver = if ctx.cfg.creds.deliver == "env" { Deliver::Env } else { Deliver::Fd };
    let turn = Turn { claude: &claude, version: &version, model, deliver };
    let mut done = Vec::new();
    let stopped = runtime()?.block_on(check_all(store, &ctx, &turn, &planned, json, &mut done));
    let code = match &stopped {
        Some(e) => e.exit_code(),
        None if done.iter().any(|c| matches!(c.outcome, Outcome::Refused { .. } | Outcome::NotChecked { .. })) => 5,
        None if done.iter().any(|c| matches!(c.outcome, Outcome::Failed { .. })) => 1,
        None => 0,
    };
    if json {
        let now = unix_now();
        let doc = serde_json::json!({
            "claude": { "path": claude.display().to_string(), "version": version },
            "model": model,
            "checked_at": now,
            "exit": code,
            "accounts": done.iter().map(|c| c.json(&version, now)).collect::<Vec<_>>(),
        });
        outln!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
    }
    match stopped {
        Some(e) => Err(e),
        None if code != 0 => Err(CliError::Exit(code)),
        None => Ok(()),
    }
}

/// A model name: `[A-Za-z0-9][A-Za-z0-9.[]_-]{0,63}` (`haiku`,
/// `claude-haiku-4-5`, `opus[1m]`), so nothing else reaches claude's argv.
fn valid_model(model: &str) -> bool {
    let b = model.as_bytes();
    (1..=64).contains(&b.len()) && b[0].is_ascii_alphanumeric() && b.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'[' | b']' | b'_' | b'-'))
}

/// One account [`chosen`] for the check: its sealed file, or a
/// `credentials/accounts/<name>.env` that is no container (why: a plaintext
/// file, a link), which no account is, shown `not_checked` with no Touch ID
/// (design §4 step 5: it may hold a token in the clear).
#[derive(Debug, Clone, Copy)]
enum Pick<'a> {
    Sealed(&'a AccountFile),
    Unsealed(&'a str, &'a str),
}

impl Pick<'_> {
    fn name(&self) -> &str {
        match self {
            Pick::Sealed(f) => &f.name,
            Pick::Unsealed(name, _) => name,
        }
    }
}

/// The accounts to check, with the `<name>.env` files that are no container
/// (`unsealed`, by name, with why): every one (the active one first, then by
/// name) when none is named; else those named, in their order, each once. A
/// name no file has is exit 2, before any Touch ID.
fn chosen<'a>(files: &'a [AccountFile], unsealed: &'a [(String, String)], active: Option<&str>, names: &[String]) -> Result<Vec<Pick<'a>>> {
    let mut all: Vec<Pick<'a>> = files.iter().map(Pick::Sealed).chain(unsealed.iter().map(|(name, why)| Pick::Unsealed(name, why))).collect();
    if names.is_empty() {
        all.sort_by_key(|p| (Some(p.name()) != active, p.name().to_string()));
        return Ok(all);
    }
    let mut out: Vec<Pick<'a>> = Vec::new();
    for name in names {
        let pick = all.iter().find(|p| p.name() == name).ok_or_else(|| {
            CliError::Usage(format!("no Claude account {name} (Claude accounts: {})", files.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", ")))
        })?;
        if !out.iter().any(|p| p.name() == pick.name()) {
            out.push(*pick);
        }
    }
    Ok(out)
}

/// One account to check, as read before any Touch ID: its seal, as the
/// reconcile read its file (what is unsealed must still be those bytes:
/// `unseal_account` refuses others before their dialog; empty for a file
/// that is no container, which has none), and the outcome already decided,
/// if one is: a seal Anthropic refused, as recorded, or a file that is no
/// container (no Touch ID is asked for either). A refusal record that
/// cannot be read refuses the whole check (exit 5): which seals were
/// refused is unknown.
struct Planned {
    name: String,
    active: bool,
    path: PathBuf,
    tag: String,
    pre: Option<Outcome>,
}

fn plan(paths: &Paths, pick: Pick<'_>, active: bool) -> Result<Planned> {
    let file = match pick {
        Pick::Sealed(file) => file,
        Pick::Unsealed(name, why) => {
            let path = paths.account_env(name);
            let why = format!("{} {why}: it is no Claude account; move it away (and revoke what it holds); no Touch ID asked", path.display());
            return Ok(Planned { name: name.to_string(), active, path, tag: String::new(), pre: Some(Outcome::NotChecked { why }) });
        }
    };
    let pre = match credential::read_rejection(paths, &file.tag) {
        Ok(None) => None,
        Ok(Some(r)) => Some(Outcome::Refused { recorded: Some((r.at, r.vm)) }),
        Err(e) => return Err(CliError::AuthUnavailable(format!("{e}: which tokens Anthropic refused is unknown, so no Claude account is checked and nothing was unsealed; repair it, or remove it to forget every recorded refusal"))),
    };
    Ok(Planned { name: file.name.clone(), active, path: paths.account_env(&file.name), tag: file.tag.clone(), pre })
}

/// What every run of one check shares: the claude and its version, the
/// model, and how the token is delivered.
struct Turn<'a> {
    claude: &'a Path,
    version: &'a str,
    model: &'a str,
    deliver: Deliver,
}

/// Each planned account in turn, its result pushed onto `done` (and its
/// line printed, without `--json`) as it comes. `Some`: what ended the
/// check early (a dismissed dialog, a deadline, a missing key, a stop), the
/// accounts from that one on `not_checked`.
async fn check_all(store: &Keystore, ctx: &Ctx, turn: &Turn<'_>, planned: &[Planned], json: bool, done: &mut Vec<Checked>) -> Option<CliError> {
    for (i, p) in planned.iter().enumerate() {
        match check_one(store, ctx, turn, p, (i + 1, planned.len())).await {
            Ok(checked) => {
                if !json {
                    // A closed stdout: the check goes on, and its records are what it leaves.
                    let _ = crate::commands::outln(format_args!("{}", checked.line(turn.version, unix_now())));
                }
                done.push(checked);
            }
            Err(e) => {
                let why = format!("the check ended before it ({})", one_line(&e.to_string()));
                done.extend(planned[i..].iter().map(|q| Checked::of(q, Outcome::NotChecked { why: why.clone() })));
                return Some(e);
            }
        }
    }
    None
}

/// Does `e`, an unseal's failure, end the whole check (a dismissed dialog,
/// the deadline, a missing keystore key, a stop the unseal answered)?
/// Anything else is this account's alone.
fn ends_the_check(e: &CliError) -> bool {
    matches!(e, CliError::Cancelled | CliError::NoKey(_) | CliError::Exit(_)) || crate::bridge::unseal::is_deadline(e)
}

/// One account's check (see the module doc). `Err`: what ends the whole
/// check (a stop of its own, [`ends_the_check`]).
async fn check_one(store: &Keystore, ctx: &Ctx, turn: &Turn<'_>, p: &Planned, (n, of): (usize, usize)) -> Result<Checked> {
    if let Some(pre) = &p.pre {
        return Ok(Checked::of(p, pre.clone()));
    }
    // A refusal recorded meanwhile (a wrapper's, another check's) is honoured before the dialog.
    match credential::read_rejection(&ctx.paths, &p.tag) {
        Ok(None) => {}
        Ok(Some(r)) => return Ok(Checked::of(p, Outcome::Refused { recorded: Some((r.at, r.vm)) })),
        Err(e) => return Err(CliError::AuthUnavailable(format!("{e}: which tokens Anthropic refused is unknown, so the check stops here; repair it, or remove it to forget every recorded refusal"))),
    }
    voice::note(&format!("Claude account {} ({n} of {of}): one Touch ID, then one turn of {} on claude {}", p.name, turn.model, turn.version));
    let token = match credential::unseal_account(store, ctx, &p.name, &p.path, &p.tag).await {
        Ok((token, _)) => token,
        Err(e) if ends_the_check(&e) => return Err(e),
        // Sealed anew since it was read, or no token in it: unusable as it is (5); else this run failed.
        Err(e) if e.exit_code() == 5 => return Ok(Checked::of(p, Outcome::NotChecked { why: one_line(&e.to_string()) })),
        Err(e) => return Ok(Checked::of(p, Outcome::Failed { why: one_line(&e.to_string()) })),
    };
    let home = match scratch_home(&ctx.paths) {
        Ok(home) => home,
        Err(e) => return Ok(Checked::of(p, Outcome::Failed { why: one_line(&e.to_string()) })),
    };
    let mut stops = Stops::take()?;
    let ran = stoppable(&mut stops, run_claude(turn, home.path(), token, RUN_LIMIT)).await;
    stops.keep();
    drop(home);
    let run = match ran {
        Err(stop) => {
            voice::note(&format!("stopped while Claude account {}'s turn ran ({}): its claude was ended", p.name, stop.name()));
            return Err(CliError::Exit(stop.status()));
        }
        Ok(Err(e)) => return Ok(Checked::of(p, Outcome::Failed { why: one_line(&e.to_string()) })),
        Ok(Ok(run)) => run,
    };
    let outcome = judge(&run);
    let mut checked = Checked::of(p, outcome);
    checked.ms = Some(run.ms);
    checked.exit = run.code;
    checked.event = run.event.as_ref().map(|(line, _)| scrub(line).into_owned());
    checked.result = run.result.as_ref().map(|(line, _)| scrub(line).into_owned());
    let now = unix_now();
    match &checked.outcome {
        Outcome::Refused { recorded: None } => credential::record_rejection(&ctx.paths, WHERE, &p.tag, "text"),
        Outcome::Checked(_) | Outcome::Limited(_) => {
            if let Err(e) = record_usage(&ctx.paths, &p.name, &p.tag, &checked.outcome, now) {
                voice::warn(&format!("Claude account {}'s usage is not recorded: {e}", p.name));
            }
            audit_check(&ctx.paths, &checked, turn, &p.tag);
        }
        _ => {}
    }
    Ok(checked)
}

/// The first line of `text`, scrubbed and cut to 200 characters: what a
/// line of the check says of a failure.
fn one_line(text: &str) -> String {
    scrub(text.lines().next().unwrap_or_default()).chars().take(200).collect()
}

/// A fresh `HOME` for one run: `state/tmp/account-check-<pid>-*` (0700,
/// `state/tmp`'s naming, so a later process sweeps a crashed check's), with
/// its `.claude` (the run's `CLAUDE_CONFIG_DIR`); removed when dropped.
fn scratch_home(paths: &Paths) -> Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = paths.tmp();
    crate::bridge::registry::ensure_private_dir(&tmp)?;
    let dir = tempfile::Builder::new().prefix(&format!("account-check-{}-", std::process::id())).tempdir_in(&tmp).map_err(|e| CliError::Msg(format!("cannot create a scratch directory in {}: {e}", tmp.display())))?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    std::fs::create_dir(dir.path().join(".claude"))?;
    Ok(dir)
}

/// `claude --version`'s first word (`2.1.305`), run as the turns run it (an
/// empty environment but `PATH`, a fresh `HOME`), bounded to 10 s;
/// `unknown` when it says nothing usable.
fn claude_version(paths: &Paths, claude: &Path) -> String {
    use std::os::unix::process::CommandExt as _;
    let Ok(home) = scratch_home(paths) else { return "unknown".into() };
    let mut cmd = std::process::Command::new(claude);
    cmd.arg("--version").env_clear().envs(run_env(home.path(), None)).current_dir(home.path()).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).process_group(0);
    let Ok(mut child) = cmd.spawn() else { return "unknown".into() };
    let mut group = Group::of(Some(child.id()));
    let stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        if let Some(mut s) = stdout {
            let _ = std::io::Read::read_to_string(&mut std::io::Read::take(&mut s, 4096), &mut out);
        }
        out
    });
    let started = Instant::now();
    while started.elapsed() < VERSION_LIMIT && matches!(child.try_wait(), Ok(None)) {
        std::thread::sleep(Duration::from_millis(20));
    }
    group.end_now();
    let _ = child.wait();
    let out = reader.join().unwrap_or_default();
    out.split_whitespace().next().filter(|v| v.len() <= 32 && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))).map_or_else(|| "unknown".into(), str::to_string)
}

// ---- one run ------------------------------------------------------------------------------

/// claude's argv for the turn, in its pinned order: the prompt right after
/// `-p`, and `--tools ""` (no tool at all) followed by another option, since
/// `--tools` takes several values; never `--bare`, which ignores the token.
fn argv(model: &str) -> Vec<String> {
    [
        "-p",
        PROMPT,
        "--output-format",
        "stream-json",
        "--verbose",
        "--model",
        model,
        "--max-turns",
        "1",
        "--tools",
        "",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--no-session-persistence",
    ]
    .iter()
    .map(|a| (*a).to_string())
    .collect()
}

/// The run's whole environment but the token: `PATH`, `HOME`,
/// `CLAUDE_CONFIG_DIR` in it, `DISABLE_AUTOUPDATER=1`, `TZ=UTC`, and with fd
/// delivery the token's descriptor (`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3`).
fn run_env(home: &Path, deliver: Option<Deliver>) -> Vec<(&'static str, std::ffi::OsString)> {
    let mut env = vec![
        ("PATH", RUN_PATH.into()),
        ("HOME", home.as_os_str().to_owned()),
        ("CLAUDE_CONFIG_DIR", home.join(".claude").into_os_string()),
        ("DISABLE_AUTOUPDATER", "1".into()),
        ("TZ", "UTC".into()),
    ];
    if deliver == Some(Deliver::Fd) {
        env.push((crate::bridge::pump::TOKEN_FD_VAR, TOKEN_FD.to_string().into()));
    }
    env
}

/// The run's command, its token not in it yet: [`argv`], an empty
/// environment but [`run_env`]'s, `HOME` its directory, stdin `/dev/null`,
/// stdout and stderr piped, a process group of its own.
fn command(claude: &Path, home: &Path, model: &str, deliver: Deliver) -> std::process::Command {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new(claude);
    cmd.args(argv(model)).env_clear().envs(run_env(home, Some(deliver))).current_dir(home).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    cmd
}

/// A close-on-exec pipe already holding `value`, its write end closed: the
/// read end, for the child's fd 3 (the twin of the pump's; LEAD: one of the
/// two may go at the merge). A token is at most 4096 bytes and fits the
/// pipe's buffer, so the write never waits for a reader.
fn secret_pipe(value: &[u8]) -> std::io::Result<OwnedFd> {
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `fds` is an array of two ints for pipe(2) to fill.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both fds were just created and belong to nobody else.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&read, &write] {
        // SAFETY: a valid fd we own.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    std::io::Write::write_all(&mut std::fs::File::from(write), value)?;
    Ok(read)
}

/// In the forked child: `fd` onto [`TOKEN_FD`], without close-on-exec (a
/// pipe already there only loses the flag). Async-signal-safe.
fn onto_fd3(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: plain syscalls on integers.
    let rc = unsafe {
        if fd == TOKEN_FD {
            libc::fcntl(TOKEN_FD, libc::F_SETFD, 0)
        } else {
            libc::dup2(fd, TOKEN_FD)
        }
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// A run's process group (claude leads its own): ended when dropped, so a
/// stop that drops the run leaves nothing of it running: TERM, then KILL
/// [`KILL_AFTER`] later to whatever of it is left.
struct Group {
    pgid: Option<libc::pid_t>,
}

impl Group {
    fn of(pid: Option<u32>) -> Group {
        Group { pgid: pid.and_then(|p| libc::pid_t::try_from(p).ok()).filter(|p| *p > 1) }
    }

    fn signal(&self, sig: libc::c_int) {
        if let Some(pgid) = self.pgid {
            // SAFETY: killpg(2) on the group this run's child leads.
            unsafe {
                libc::killpg(pgid, sig);
            }
        }
    }

    /// Is any process of it left?
    fn alive(&self) -> bool {
        // SAFETY: signal 0 sends nothing; it only asks whether the group exists.
        self.pgid.is_some_and(|pgid| unsafe { libc::killpg(pgid, 0) } == 0)
    }

    /// TERM, [`KILL_AFTER`] for it to go, then KILL; done once.
    fn end_now(&mut self) {
        if self.alive() {
            self.signal(libc::SIGTERM);
            let until = Instant::now() + KILL_AFTER;
            while self.alive() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(20));
            }
            if self.alive() {
                self.signal(libc::SIGKILL);
            }
        }
        self.pgid = None;
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        self.end_now();
    }
}

/// What one run showed.
#[derive(Debug, Default)]
struct Run {
    /// Its exit code (none: killed).
    code: Option<i32>,
    /// No result came within the run's bound.
    timed_out: bool,
    ms: u128,
    /// The last `rate_limit_event` line, and what its info said.
    event: Option<(String, Info)>,
    /// The first `result` line, parsed.
    result: Option<(String, Value)>,
    /// The first line of what is kept of its stderr, scrubbed.
    stderr: Option<String>,
    /// Anthropic refused the token (`AuthWatch` at its exit: a 401 result
    /// or text, then exit 1).
    rejected: bool,
}

/// The run's stdout and stderr as they come.
struct Seen {
    split: LineSplitter,
    watch: AuthWatch,
    tail: Vec<u8>,
    event: Option<(String, Info)>,
    result: Option<(String, Value)>,
    result_at: Option<tokio::time::Instant>,
}

impl Seen {
    fn new() -> Seen {
        Seen { split: LineSplitter::with_cap(LINE_CAP), watch: AuthWatch::new(), tail: Vec::new(), event: None, result: None, result_at: None }
    }

    fn feed(&mut self, stream: Stream, bytes: &[u8]) {
        self.watch.feed(stream, bytes);
        match stream {
            Stream::Stdout => {
                self.split.push(bytes);
                while let Some(line) = self.split.next_line() {
                    if let Ok(line) = line {
                        self.line(&line);
                    }
                }
            }
            Stream::Stderr => {
                self.tail.extend_from_slice(bytes);
                let cut = self.tail.len().saturating_sub(STDERR_KEEP);
                self.tail.drain(..cut);
            }
        }
    }

    /// One stdout line: the last `rate_limit_event`, the first `result`.
    fn line(&mut self, line: &[u8]) {
        let Ok(v) = serde_json::from_slice::<Value>(line) else { return };
        let text = || String::from_utf8_lossy(line).into_owned();
        match v["type"].as_str() {
            Some("rate_limit_event") => self.event = Some((text(), info_of(&v["rate_limit_info"]))),
            Some("result") if self.result.is_none() => {
                self.result = Some((text(), v));
                self.result_at = Some(tokio::time::Instant::now());
            }
            _ => {}
        }
    }

    /// A last line without its newline.
    fn finish(&mut self) {
        if let Some(Ok(line)) = self.split.finish() {
            self.line(&line);
        }
    }
}

/// Run claude once for the turn (see the module doc), `token` going with
/// the spawn: on fd 3 (a pipe that holds it before the child exists), or
/// in the child's environment alone. `limit` bounds the whole run.
async fn run_claude(turn: &Turn<'_>, home: &Path, token: SetupToken, limit: Duration) -> Result<Run> {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = command(turn.claude, home, turn.model, turn.deliver);
    let pipe = match turn.deliver {
        Deliver::Fd => Some(secret_pipe(token.expose().as_bytes()).map_err(|e| CliError::Msg(format!("the token's pipe: {e}")))?),
        Deliver::Env => {
            // std keeps its own (unzeroized) copy until the command is dropped, right after the spawn.
            cmd.env(crate::bridge::setup_token::TOKEN_VAR, token.expose());
            None
        }
    };
    if let Some(fd) = pipe.as_ref().map(OwnedFd::as_raw_fd) {
        // SAFETY: the closure runs in the forked child before exec and makes only async-signal-safe calls
        // (dup2/fcntl) on an integer prepared here.
        unsafe {
            cmd.pre_exec(move || onto_fd3(fd));
        }
    }
    let mut cmd = tokio::process::Command::from(cmd);
    cmd.kill_on_drop(true);
    let started = Instant::now();
    let spawned = cmd.spawn();
    // The token goes with the spawn: the child has its own (the pipe's buffer, or its environment).
    drop(cmd);
    drop(pipe);
    drop(token);
    let mut child = spawned.map_err(|e| CliError::Msg(format!("{}: {e}", turn.claude.display())))?;
    let mut group = Group::of(child.id());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Stream, Vec<u8>)>();
    if let Some(out) = child.stdout.take() {
        tokio::spawn(read_into(out, Stream::Stdout, tx.clone()));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(read_into(err, Stream::Stderr, tx));
    }
    let mut seen = Seen::new();
    let deadline = tokio::time::Instant::from_std(started + limit);
    let mut open = true;
    let mut timed_out = false;
    let status = loop {
        let wake = seen.result_at.map_or(deadline, |at| (at + EXIT_GRACE).min(deadline));
        tokio::select! {
            piece = rx.recv(), if open => match piece {
                Some((stream, bytes)) => seen.feed(stream, &bytes),
                None => open = false,
            },
            status = child.wait() => break status.ok(),
            () = tokio::time::sleep_until(wake) => {
                timed_out = seen.result.is_none();
                group.signal(libc::SIGTERM);
                break match tokio::time::timeout(KILL_AFTER, child.wait()).await {
                    Ok(status) => status.ok(),
                    Err(_) => {
                        group.signal(libc::SIGKILL);
                        child.wait().await.ok()
                    }
                };
            }
        }
    };
    // What it wrote just before its end is still read, for a while.
    let drain_until = tokio::time::Instant::now() + DRAIN;
    while open {
        match tokio::time::timeout_at(drain_until, rx.recv()).await {
            Ok(Some((stream, bytes))) => seen.feed(stream, &bytes),
            Ok(None) | Err(_) => open = false,
        }
    }
    seen.finish();
    // Whatever of its group is left (a child holding its stdout): ended now.
    group.end_now();
    let code = status.and_then(|s| s.code());
    let rejected = seen.watch.rejected_at_exit(code);
    let stderr = std::str::from_utf8(&seen.tail).ok().and_then(|t| t.lines().find(|l| !l.trim().is_empty())).map(one_line);
    Ok(Run { code, timed_out, ms: started.elapsed().as_millis(), event: seen.event, result: seen.result, stderr, rejected })
}

/// One of the child's pipes into the run's channel, chunk by chunk, to its end.
async fn read_into(mut pipe: impl tokio::io::AsyncRead + Unpin, stream: Stream, tx: tokio::sync::mpsc::UnboundedSender<(Stream, Vec<u8>)>) {
    let mut buf = vec![0_u8; 8192];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if tx.send((stream, buf[..n].to_vec())).is_err() {
                    return;
                }
            }
        }
    }
}

// ---- the verdict --------------------------------------------------------------------------

/// A 5-hour or weekly window: how much of it is used (a fraction, as
/// given: past 1 when over), and when it resets (unix seconds).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Window {
    utilization: f64,
    resets_at: Option<u64>,
}

/// A `rate_limit_event`'s `rate_limit_info`, as far as the check reads it:
/// its status, the windows (from `unifiedWindows`, else the top-level
/// `utilization` and `resetsAt` for a `five_hour` or `seven_day`
/// `rateLimitType`), the type a warning or a rejection names and its reset,
/// and whether extra usage is in use.
#[derive(Debug, Clone, Default, PartialEq)]
struct Info {
    status: Option<String>,
    kind: Option<String>,
    resets_at: Option<u64>,
    five_hour: Option<Window>,
    seven_day: Option<Window>,
    overage: bool,
}

/// [`Info`] of a `rate_limit_info` object, leniently: a field of another
/// type reads as absent.
fn info_of(v: &Value) -> Info {
    let window = |w: &Value| Some(Window { utilization: w.get("utilization")?.as_f64()?, resets_at: w.get("resetsAt").and_then(epoch) });
    let kind = v.get("rateLimitType").and_then(Value::as_str).map(str::to_string);
    let unified = v.get("unifiedWindows").filter(|u| u.is_object());
    let pick = |name: &str| match unified {
        Some(u) => u.get(name).and_then(window),
        None => window(v).filter(|_| kind.as_deref() == Some(name)),
    };
    Info {
        status: v.get("status").and_then(Value::as_str).map(str::to_string),
        resets_at: v.get("resetsAt").and_then(epoch),
        five_hour: pick("five_hour"),
        seven_day: pick("seven_day"),
        overage: v.get("isUsingOverage").and_then(Value::as_bool) == Some(true),
        kind,
    }
}

/// A time as claude gives it: unix seconds (a number past 10^12 is
/// milliseconds), or RFC 3339.
fn epoch(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => {
            let n = n.as_u64().or_else(|| n.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))?;
            Some(if n > 1_000_000_000_000 { n / 1000 } else { n })
        }
        Value::String(s) => parse_rfc3339_utc(s),
        _ => None,
    }
}

/// A usage limit claude's result said was hit: its text (control
/// characters blanked, at most 300 characters), its kind (a
/// `rateLimitType`, or `unknown`), and its reset when known.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Limit {
    text: String,
    kind: String,
    resets_at: Option<u64>,
}

/// The limit a `result` says was hit: `is_error` with `api_error`
/// `usage_limit_reached`, or HTTP 429 with a text that starts "You've hit
/// your" (a 429 throttle is no limit). Its kind from
/// `api_error_params.rate_limit_info.rateLimitType`, else the limit the
/// text names ([`LIMIT_NAMES`]), else a `rejected` event's; its reset from
/// the params, else from that event.
fn limit_of(result: &Value, event: Option<&Info>) -> Option<Limit> {
    if result["type"] != "result" || result["is_error"] != true {
        return None;
    }
    let text = result["result"].as_str().unwrap_or_default();
    if !(result["api_error"] == "usage_limit_reached" || (result["api_error_status"] == 429 && text.starts_with("You've hit your"))) {
        return None;
    }
    let params = result.get("api_error_params").and_then(|p| p.get("rate_limit_info"));
    let rejected = event.filter(|i| i.status.as_deref() == Some("rejected"));
    let kind = params
        .and_then(|p| p.get("rateLimitType")?.as_str())
        .map(str::to_string)
        .or_else(|| kind_of_text(text).map(str::to_string))
        .or_else(|| rejected.and_then(|i| i.kind.clone()))
        .unwrap_or_else(|| "unknown".into());
    let resets_at = params.and_then(|p| p.get("resetsAt")).and_then(epoch).or_else(|| rejected.and_then(|i| i.resets_at));
    let text: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(300).collect();
    Some(Limit { text, kind, resets_at })
}

/// The `rateLimitType` the text "You've hit your X · …" names.
fn kind_of_text(text: &str) -> Option<&'static str> {
    let rest = text.strip_prefix("You've hit your ")?;
    LIMIT_NAMES.iter().find(|(_, name, _)| rest.starts_with(name)).map(|(kind, _, _)| *kind)
}

/// What a check came to.
#[derive(Debug, Clone, PartialEq)]
enum Outcome {
    /// It answered: the event's windows (none when it reported none).
    Checked(Info),
    /// The account is at a limit.
    Limited(Limit),
    /// Anthropic refused the token: this run (`None`), or a refusal recorded
    /// before it (`at`, `vm`), with no Touch ID asked.
    Refused { recorded: Option<(String, String)> },
    /// The run failed: why.
    Failed { why: String },
    /// Not run: why (a file sealed anew since it was read, the check ended before it).
    NotChecked { why: String },
}

impl Outcome {
    fn word(&self) -> &'static str {
        match self {
            Outcome::Checked(_) => "checked",
            Outcome::Limited(_) => "limited",
            Outcome::Refused { .. } => "refused",
            Outcome::Failed { .. } => "failed",
            Outcome::NotChecked { .. } => "not_checked",
        }
    }
}

/// The verdict on a run, the first that matches: Anthropic refused the
/// token (a 401, then exit 1); a usage limit; an answer; anything else
/// failed, saying why.
fn judge(run: &Run) -> Outcome {
    if run.rejected {
        return Outcome::Refused { recorded: None };
    }
    let event = run.event.as_ref().map(|(_, i)| i);
    if let Some(limit) = run.result.as_ref().and_then(|(_, v)| limit_of(v, event)) {
        return Outcome::Limited(limit);
    }
    if run.result.as_ref().is_some_and(|(_, v)| v["is_error"] == false) {
        return Outcome::Checked(event.cloned().unwrap_or_default());
    }
    let why = match (&run.result, run.code) {
        (Some((_, v)), _) => {
            let kind = v["api_error"].as_str().or_else(|| v["subtype"].as_str()).unwrap_or("an error");
            let status = v["api_error_status"].as_u64().map_or_else(String::new, |s| format!(" (HTTP {s})"));
            format!("claude's result was {kind}{status}: {}", one_line(v["result"].as_str().unwrap_or_default()))
        }
        (None, _) if run.timed_out => format!("no result within {} s", RUN_LIMIT.as_secs()),
        (None, Some(code)) => format!("claude exited {code} without a result{}", run.stderr.as_ref().map_or_else(String::new, |e| format!(": {e}"))),
        (None, None) => "claude ended without a result".to_string(),
    };
    Outcome::Failed { why }
}

// ---- what is shown and recorded -------------------------------------------------------------

/// One account's check, as shown and recorded.
#[derive(Debug, Clone, PartialEq)]
struct Checked {
    name: String,
    active: bool,
    tag: String,
    outcome: Outcome,
    ms: Option<u128>,
    exit: Option<i32>,
    /// The run's `rate_limit_event` and `result` lines, scrubbed (`--json`).
    event: Option<String>,
    result: Option<String>,
}

impl Checked {
    fn of(p: &Planned, outcome: Outcome) -> Checked {
        Checked { name: p.name.clone(), active: p.active, tag: p.tag.clone(), outcome, ms: None, exit: None, event: None, result: None }
    }

    /// Its line (see the module doc's formats), at `now`.
    fn line(&self, version: &str, now: u64) -> String {
        let name = format!("{}{}", self.name, if self.active { " (active)" } else { "" });
        match &self.outcome {
            Outcome::Checked(info) => format!("{name}: {}", usage_text(info, version, now)),
            Outcome::Limited(l) => {
                let phrase = l.text.split_once(" · ").map_or(l.text.as_str(), |(_, rest)| rest);
                let at = l.resets_at.map_or_else(String::new, |at| format!(" ({})", when(at, now)));
                format!("{name}: limited: {}, {phrase:?}{at}", kind_word(&l.kind))
            }
            Outcome::Refused { recorded: None } => {
                format!("{name}: refused by Anthropic (HTTP 401): seal a fresh token for it (claude setup-token, then ai-env creds account add {})", self.name)
            }
            Outcome::Refused { recorded: Some((at, vm)) } => format!("{name}: not checked: refused by Anthropic on {at} ({vm}); no Touch ID asked"),
            Outcome::Failed { why } => format!("{name}: check failed: {why}"),
            Outcome::NotChecked { why } => format!("{name}: not checked: {why}"),
        }
    }

    /// Its `--json` object.
    fn json(&self, version: &str, now: u64) -> Value {
        let window = |w: Option<Window>| w.map(|w| serde_json::json!({ "utilization": w.utilization, "resets_at": w.resets_at }));
        let (status, five_hour, seven_day, limited, why) = match &self.outcome {
            Outcome::Checked(i) => (i.status.clone().or_else(|| Some("allowed".into())), window(i.five_hour), window(i.seven_day), None, None),
            Outcome::Limited(l) => (Some("rejected".to_string()), None, None, Some(serde_json::json!({ "text": l.text, "kind": l.kind, "resets_at": l.resets_at })), None),
            Outcome::Refused { recorded } => (None, None, None, None, recorded.as_ref().map(|(at, vm)| format!("refused by Anthropic on {at} ({vm})"))),
            Outcome::Failed { why } | Outcome::NotChecked { why } => (None, None, None, None, Some(why.clone())),
        };
        serde_json::json!({
            "name": self.name,
            "active": self.active,
            // None for a file that is no container: it has no seal.
            "tag": (!self.tag.is_empty()).then_some(self.tag.as_str()),
            "outcome": self.outcome.word(),
            "status": status,
            "five_hour": five_hour,
            "seven_day": seven_day,
            "limited": limited,
            "why": why,
            "ms": self.ms,
            "exit": self.exit,
            "line": self.line(version, now),
            "lines": { "rate_limit_event": self.event, "result": self.result },
        })
    }
}

/// An answer's usage: `5h 23% (resets 14:00Z), 7d 81% (resets Thu 10:00Z)`,
/// then `; near its weekly limit` (`allowed_warning`) and `; using extra
/// usage`; or that none was reported.
fn usage_text(info: &Info, version: &str, now: u64) -> String {
    let part = |label: &str, w: Option<Window>| w.map(|w| format!("{label} {}{}", pct(w.utilization), w.resets_at.map_or_else(String::new, |at| format!(" (resets {})", when(at, now)))));
    let parts: Vec<String> = [part("5h", info.five_hour), part("7d", info.seven_day)].into_iter().flatten().collect();
    let mut text = if parts.is_empty() {
        let status = info.status.as_deref().map_or_else(|| "no rate_limit_event".to_string(), |s| format!("status {s}"));
        format!("answered; claude {version} reported no usage windows ({status})")
    } else {
        parts.join(", ")
    };
    if info.status.as_deref() == Some("allowed_warning") {
        let limit = info.kind.as_deref().and_then(|k| LIMIT_NAMES.iter().find(|(kind, _, _)| *kind == k)).map_or("a limit".to_string(), |(_, name, _)| format!("its {name}"));
        text.push_str(&format!("; near {limit}"));
    }
    if info.overage {
        text.push_str("; using extra usage");
    }
    text
}

/// The word a `limited:` line uses for a kind ([`LIMIT_NAMES`]), else the kind itself.
fn kind_word(kind: &str) -> &str {
    LIMIT_NAMES.iter().find(|(k, _, _)| *k == kind).map_or(kind, |(_, _, word)| word)
}

/// A utilization as a whole percentage: `0.23` is `23%`, `1.02` is `102%`.
fn pct(utilization: f64) -> String {
    format!("{:.0}%", (utilization * 100.0).max(0.0).round())
}

/// When `at` (unix seconds) is, seen at `now`, in UTC: `HH:MMZ` within 20
/// hours, `Ddd HH:MMZ` within 6 days, else `Mon DD HH:MMZ`.
fn when(at: u64, now: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let stamp = rfc3339_utc(at);
    let hm = &stamp[11..16];
    if at <= now + 20 * 3600 {
        return format!("{hm}Z");
    }
    if at <= now + 6 * 86_400 {
        let day = usize::try_from((at / 86_400 + 4) % 7).unwrap_or(0);
        return format!("{} {hm}Z", DAYS[day]);
    }
    let month = stamp[5..7].parse::<usize>().ok().and_then(|m| MONTHS.get(m.wrapping_sub(1))).copied().unwrap_or("?");
    format!("{month} {} {hm}Z", &stamp[8..10])
}

/// The record of an answer or a limit in the store's `[usage.<name>]`
/// (source `check`): `seen_at`, `source`, `status`, the windows the event
/// reported (one not reported is kept until its reset has passed, when it
/// goes), and `limited` (set by a limit, cleared by an answer). Written only
/// while the store's row of `name` still names `tag` (one sealed anew since
/// is another seal's), never creating the store. Whether it wrote.
///
/// LEAD (A1 merge): slice B's `accounts::usage::{apply, record_all}`
/// replace this; it writes their record's shape (L-3: times in unix
/// seconds).
fn record_usage(paths: &Paths, name: &str, tag: &str, outcome: &Outcome, now: u64) -> std::result::Result<bool, String> {
    let int = |n: u64| toml::Value::Integer(i64::try_from(n).unwrap_or(i64::MAX));
    let window = |w: Window| {
        let mut t = toml::map::Map::new();
        t.insert("utilization".into(), toml::Value::Float(w.utilization));
        if let Some(at) = w.resets_at {
            t.insert("resets_at".into(), int(at));
        }
        toml::Value::Table(t)
    };
    super::update(paths, |s| {
        if !s.account.iter().any(|r| r.name == name && r.tag == tag) {
            return false;
        }
        let mut rec = match s.usage.get(name) {
            Some(toml::Value::Table(t)) => t.clone(),
            _ => toml::map::Map::new(),
        };
        for key in ["five_hour", "seven_day"] {
            let passed = rec.get(key).and_then(|w| w.get("resets_at")).and_then(toml::Value::as_integer).is_some_and(|at| u64::try_from(at).is_ok_and(|at| at <= now));
            if passed {
                rec.remove(key);
            }
        }
        rec.insert("seen_at".into(), int(now));
        rec.insert("source".into(), toml::Value::String("check".into()));
        match outcome {
            Outcome::Checked(info) => {
                rec.insert("status".into(), toml::Value::String(info.status.clone().unwrap_or_else(|| "allowed".into())));
                for (key, w) in [("five_hour", info.five_hour), ("seven_day", info.seven_day)] {
                    if let Some(w) = w {
                        rec.insert(key.into(), window(w));
                    }
                }
                rec.remove("limited");
            }
            Outcome::Limited(l) => {
                rec.insert("status".into(), toml::Value::String("rejected".into()));
                let mut limited = toml::map::Map::new();
                limited.insert("at".into(), int(now));
                limited.insert("text".into(), toml::Value::String(l.text.clone()));
                limited.insert("kind".into(), toml::Value::String(l.kind.clone()));
                if let Some(at) = l.resets_at {
                    limited.insert("resets_at".into(), int(at));
                }
                rec.insert("limited".into(), toml::Value::Table(limited));
            }
            _ => return false,
        }
        s.usage.insert(name.to_string(), toml::Value::Table(rec));
        true
    })
}

/// The `account_check` audit row of an answer or a limit.
fn audit_check(paths: &Paths, c: &Checked, turn: &Turn<'_>, tag: &str) {
    let whole = |w: Option<Window>| w.map_or_else(|| "-".to_string(), |w| pct(w.utilization));
    let (status, five_hour, seven_day, kind, resets_at) = match &c.outcome {
        Outcome::Checked(i) => (i.status.clone().unwrap_or_else(|| "allowed".into()), whole(i.five_hour), whole(i.seven_day), i.kind.clone().unwrap_or_else(|| "-".into()), i.resets_at),
        Outcome::Limited(l) => ("rejected".to_string(), "-".to_string(), "-".to_string(), l.kind.clone(), l.resets_at),
        _ => return,
    };
    audit_row(
        paths,
        audit_event::CHECK,
        &[
            ("account", c.name.clone()),
            ("tag", tag.to_string()),
            ("outcome", c.outcome.word().into()),
            ("status", status),
            ("five_hour", five_hour),
            ("seven_day", seven_day),
            ("kind", kind),
            ("resets_at", resets_at.map_or_else(|| "-".to_string(), rfc3339_utc)),
            ("model", turn.model.to_string()),
            ("claude", turn.version.to_string()),
            ("exit", c.exit.map_or_else(|| "-".to_string(), |e| e.to_string())),
            ("ms", c.ms.map_or_else(|| "-".to_string(), |ms| ms.to_string())),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-21T12:00:00Z, a Wednesday.
    const NOW: u64 = 1_792_584_000;

    fn json(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    /// The argv is pinned in its order (the prompt after `-p`, `--tools ""`
    /// followed by another option, no `--bare`); the environment is exactly
    /// `run_env`'s (fd delivery names the descriptor, nothing names the
    /// token), and the command's HOME is its directory.
    #[test]
    fn the_argv_and_the_environment_are_exact() {
        let a = argv("haiku");
        assert_eq!(
            a,
            ["-p", "Reply with exactly OK", "--output-format", "stream-json", "--verbose", "--model", "haiku", "--max-turns", "1", "--tools", "", "--strict-mcp-config", "--disable-slash-commands", "--no-session-persistence"]
        );
        assert!(!a.iter().any(|w| w == "--bare"));
        let tools = a.iter().position(|w| w == "--tools").unwrap();
        assert!(a[tools + 1].is_empty() && a[tools + 2].starts_with("--"), "--tools \"\" is followed by an option");
        let home = Path::new("/b/state/tmp/account-check-1-x");
        let cmd = command(Path::new("/c/claude"), home, "haiku", Deliver::Fd);
        let envs: Vec<(String, Option<String>)> = cmd.get_envs().map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned()))).collect();
        let want = [
            ("PATH", RUN_PATH),
            ("HOME", "/b/state/tmp/account-check-1-x"),
            ("CLAUDE_CONFIG_DIR", "/b/state/tmp/account-check-1-x/.claude"),
            ("DISABLE_AUTOUPDATER", "1"),
            ("TZ", "UTC"),
            ("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "3"),
        ];
        for (k, v) in want {
            assert!(envs.iter().any(|(ek, ev)| ek == k && ev.as_deref() == Some(v)), "{k}={v} in {envs:?}");
        }
        assert_eq!(envs.len(), want.len(), "nothing else: {envs:?}");
        assert!(!envs.iter().any(|(k, _)| k == "CLAUDE_CODE_OAUTH_TOKEN"));
        assert_eq!(cmd.get_current_dir(), Some(home));
        let env = command(Path::new("/c/claude"), home, "haiku", Deliver::Env);
        assert!(!env.get_envs().any(|(k, _)| k == "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"), "env delivery names no descriptor (its token is added at the spawn)");
    }

    #[test]
    fn names_and_models_are_checked() {
        for ok in ["haiku", "sonnet", "claude-haiku-4-5", "opus[1m]", "a.b_c"] {
            assert!(valid_model(ok), "{ok}");
        }
        for bad in ["", "-x", "a b", "a;b", "a$b", &"m".repeat(65)] {
            assert!(!valid_model(bad), "{bad:?}");
        }
        let f = |n: &str| AccountFile { name: n.into(), text: String::new(), tag: format!("{n}-tag"), sealed: None };
        let files = [f("default"), f("spare"), f("work")];
        let names = |v: Vec<Pick>| v.iter().map(|p| p.name().to_string()).collect::<Vec<_>>();
        assert_eq!(names(chosen(&files, &[], Some("work"), &[]).unwrap()), ["work", "default", "spare"], "the active one first");
        assert_eq!(names(chosen(&files, &[], None, &["spare".into(), "default".into(), "spare".into()]).unwrap()), ["spare", "default"], "named, in order, once");
        let e = chosen(&files, &[], None, &["nope".into()]).unwrap_err();
        assert_eq!((e.exit_code(), e.to_string().as_str()), (2, "no Claude account nope (Claude accounts: default, spare, work)"));
        // A file that is no container is chosen too, by name or with every one, and planned not_checked with no seal.
        let unsealed = [("plain".to_string(), "is not an ai-env container (plaintext?)".to_string())];
        assert_eq!(names(chosen(&files, &unsealed, Some("work"), &[]).unwrap()), ["work", "default", "plain", "spare"]);
        let picked = chosen(&files, &unsealed, None, &["plain".into()]).unwrap();
        assert!(matches!(picked[..], [Pick::Unsealed("plain", _)]), "{picked:?}");
        let paths = Paths::from_root_and_env(PathBuf::from("/b"), None);
        let p = plan(&paths, picked[0], false).unwrap();
        let why = "/b/credentials/accounts/plain.env is not an ai-env container (plaintext?): it is no Claude account; move it away (and revoke what it holds); no Touch ID asked";
        assert_eq!((p.tag.as_str(), p.pre.clone()), ("", Some(Outcome::NotChecked { why: why.into() })));
        let c = Checked::of(&p, p.pre.clone().unwrap());
        assert_eq!(c.line("2.1.305", NOW), format!("plain: not checked: {why}"));
        assert_eq!((c.json("2.1.305", NOW)["tag"].clone(), c.json("2.1.305", NOW)["outcome"].clone()), (Value::Null, Value::from("not_checked")));
    }

    /// The constructed full event (B's schema: both unified windows, the
    /// top-level fields beside), the trimmed one of B16 (a status alone),
    /// the top-level fallback for a `five_hour` or `seven_day` type when
    /// `unifiedWindows` is absent, and wrong types read as absent.
    #[test]
    fn the_rate_limit_info_is_read_leniently() {
        let full = json(r#"{"status":"allowed_warning","resetsAt":1792605600,"rateLimitType":"seven_day","utilization":0.81,"unifiedWindows":{"five_hour":{"utilization":0.23,"resetsAt":1792591200},"seven_day":{"utilization":0.81,"resetsAt":1792836000}},"isUsingOverage":false,"surpassedThreshold":0.75}"#);
        let i = info_of(&full);
        assert_eq!(i.status.as_deref(), Some("allowed_warning"));
        assert_eq!(i.five_hour, Some(Window { utilization: 0.23, resets_at: Some(1_792_591_200) }));
        assert_eq!(i.seven_day, Some(Window { utilization: 0.81, resets_at: Some(1_792_836_000) }));
        assert_eq!(info_of(&json(r#"{"status":"allowed"}"#)), Info { status: Some("allowed".into()), ..Info::default() });
        let top = info_of(&json(r#"{"status":"allowed","rateLimitType":"five_hour","utilization":0.4,"resetsAt":"2026-10-21T14:00:00Z"}"#));
        assert_eq!((top.five_hour, top.seven_day), (Some(Window { utilization: 0.4, resets_at: Some(1_792_591_200) }), None));
        let odd = info_of(&json(r#"{"status":5,"unifiedWindows":{"five_hour":{"utilization":"x"},"seven_day":{"utilization":1,"resetsAt":1792836000000}},"isUsingOverage":"yes"}"#));
        assert_eq!(odd, Info { seven_day: Some(Window { utilization: 1.0, resets_at: Some(1_792_836_000) }), ..Info::default() }, "an integer utilization, a reset in ms");
    }

    /// The usage-limit result (B2's shape, keys alphabetical: `api_error`
    /// `usage_limit_reached`, 429) is a limit whose kind the text names;
    /// the params' type and reset win; a `rejected` event gives them when
    /// the result does not; a 429 throttle, B7's 401 and an answer are none.
    #[test]
    fn a_usage_limit_result_is_a_limit_and_nothing_else_is() {
        let b2 = json(r#"{"api_error":"usage_limit_reached","api_error_status":429,"duration_api_ms":0,"duration_ms":1361,"is_error":true,"num_turns":1,"result":"You've hit your weekly limit · resets 10am (UTC)","session_id":"0a403528-1afc-4bdf-97a7-d9a67c42d89a","subtype":"success","type":"result"}"#);
        assert_eq!(limit_of(&b2, None), Some(Limit { text: "You've hit your weekly limit · resets 10am (UTC)".into(), kind: "seven_day".into(), resets_at: None }));
        let mut with = b2.clone();
        with["api_error_params"] = json(r#"{"rate_limit_info":{"rateLimitType":"seven_day_opus","resetsAt":1792836000}}"#);
        assert_eq!(limit_of(&with, None).map(|l| (l.kind, l.resets_at)), Some(("seven_day_opus".into(), Some(1_792_836_000))));
        let mut bare = b2.clone();
        bare["result"] = json(r#""limit reached""#);
        let rejected = Info { status: Some("rejected".into()), kind: Some("five_hour".into()), resets_at: Some(1_792_591_200), ..Info::default() };
        assert_eq!(limit_of(&bare, Some(&rejected)).map(|l| (l.kind, l.resets_at)), Some(("five_hour".into(), Some(1_792_591_200))));
        let throttle = json(r#"{"type":"result","is_error":true,"api_error":"rate_limit","api_error_status":429,"result":"Rate limited"}"#);
        let refused = json(r#"{"type":"result","is_error":true,"api_error_status":401,"result":"Failed to authenticate. API Error: 401"}"#);
        let answered = json(r#"{"type":"result","subtype":"success","is_error":false,"result":"OK"}"#);
        for v in [throttle, refused, answered] {
            assert_eq!(limit_of(&v, None), None, "{v}");
        }
        for (kind, name, _) in LIMIT_NAMES {
            assert_eq!(kind_of_text(&format!("You've hit your {name} · resets 3pm")), Some(kind));
        }
        assert_eq!(kind_of_text("You've hit your lunch limit"), None);
    }

    /// The times and percentages of the lines, at a fixed now (a Wednesday).
    #[test]
    fn when_and_pct_say_it_shortly() {
        assert_eq!(when(NOW + 2 * 3600, NOW), "14:00Z");
        assert_eq!(when(NOW + 22 * 3600, NOW), "Thu 10:00Z");
        assert_eq!(when(NOW + 8 * 86_400, NOW), "Oct 29 12:00Z");
        assert_eq!((pct(0.23), pct(0.805), pct(1.02), pct(0.0)), ("23%".into(), "81%".into(), "102%".into(), "0%".into()));
    }

    fn run(code: Option<i32>, event: Option<&str>, result: Option<&str>) -> Run {
        Run {
            code,
            event: event.map(|e| (e.to_string(), info_of(&json(e)["rate_limit_info"]))),
            result: result.map(|r| (r.to_string(), json(r))),
            ..Run::default()
        }
    }

    /// The verdicts, first match, and their lines exactly (the module
    /// doc's formats): checked with both windows and a warning, checked
    /// with none reported, limited (with the reset known), refused, failed.
    #[test]
    fn the_verdicts_and_their_lines() {
        let p = Planned { name: "work".into(), active: true, path: PathBuf::new(), tag: "t".into(), pre: None };
        let line = |o: Outcome| Checked::of(&p, o).line("2.1.305", NOW);
        let event = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","rateLimitType":"seven_day","unifiedWindows":{"five_hour":{"utilization":0.23,"resetsAt":1792591200},"seven_day":{"utilization":0.81,"resetsAt":1792663200}},"isUsingOverage":true}}"#;
        let answered = r#"{"type":"result","subtype":"success","is_error":false,"result":"OK"}"#;
        assert_eq!(line(judge(&run(Some(0), Some(event), Some(answered)))), "work (active): 5h 23% (resets 14:00Z), 7d 81% (resets Thu 10:00Z); near its weekly limit; using extra usage");
        assert_eq!(line(judge(&run(Some(0), Some(r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed"}}"#), Some(answered)))), "work (active): answered; claude 2.1.305 reported no usage windows (status allowed)");
        assert_eq!(line(judge(&run(Some(0), None, Some(answered)))), "work (active): answered; claude 2.1.305 reported no usage windows (no rate_limit_event)");
        let limited = r#"{"api_error":"usage_limit_reached","api_error_status":429,"is_error":true,"result":"You've hit your weekly limit · resets 10am (UTC)","type":"result"}"#;
        assert_eq!(line(judge(&run(Some(1), None, Some(limited)))), "work (active): limited: weekly, \"resets 10am (UTC)\"");
        let rejected = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","rateLimitType":"seven_day","resetsAt":1792663200}}"#;
        assert_eq!(line(judge(&run(Some(1), Some(rejected), Some(limited)))), "work (active): limited: weekly, \"resets 10am (UTC)\" (Thu 10:00Z)");
        assert_eq!(line(judge(&Run { rejected: true, ..run(Some(1), None, None) })), "work (active): refused by Anthropic (HTTP 401): seal a fresh token for it (claude setup-token, then ai-env creds account add work)");
        assert_eq!(line(Outcome::Refused { recorded: Some(("2026-10-07T12:00:00Z".into(), "microvm-1".into())) }), "work (active): not checked: refused by Anthropic on 2026-10-07T12:00:00Z (microvm-1); no Touch ID asked");
        assert_eq!(line(judge(&Run { timed_out: true, ..Run::default() })), "work (active): check failed: no result within 60 s");
        assert_eq!(line(judge(&Run { stderr: Some("Error: boom".into()), ..run(Some(2), None, None) })), "work (active): check failed: claude exited 2 without a result: Error: boom");
        let error = r#"{"type":"result","subtype":"error_during_execution","is_error":true,"api_error_status":500,"result":"Internal"}"#;
        assert_eq!(line(judge(&run(Some(1), None, Some(error)))), "work (active): check failed: claude's result was error_during_execution (HTTP 500): Internal");
    }

    /// The record keeps its shape (L-3): an answer sets the windows it
    /// carries and clears `limited`, keeps a window it does not carry until
    /// its reset passed; a limit sets `limited`; nothing is written for a
    /// name whose row names another seal, nor into an absent store.
    #[test]
    fn the_usage_record_follows_what_the_check_saw() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let limit = Outcome::Limited(Limit { text: "You've hit your weekly limit · resets 10am (UTC)".into(), kind: "seven_day".into(), resets_at: Some(NOW + 3600) });
        assert_eq!(record_usage(&paths, "work", "t1", &limit, NOW), Ok(false));
        assert!(!paths.accounts_state().exists(), "no store, none created");
        super::super::update(&paths, |s| s.account.push(super::super::AccountRow { name: "work".into(), tag: "t1".into(), ..Default::default() })).unwrap();
        assert_eq!(record_usage(&paths, "work", "t1", &limit, NOW), Ok(true));
        let rec = |paths: &Paths| super::super::read(paths).unwrap().unwrap().usage["work"].clone();
        let r = rec(&paths);
        assert_eq!((r["source"].as_str(), r["status"].as_str(), r["limited"]["kind"].as_str(), r["limited"]["resets_at"].as_integer()), (Some("check"), Some("rejected"), Some("seven_day"), Some(i64::try_from(NOW + 3600).unwrap())));
        let both = Info { status: Some("allowed".into()), five_hour: Some(Window { utilization: 0.2, resets_at: Some(NOW + 60) }), seven_day: Some(Window { utilization: 0.5, resets_at: Some(NOW + 86_400) }), ..Info::default() };
        assert_eq!(record_usage(&paths, "work", "t1", &Outcome::Checked(both), NOW), Ok(true));
        let only = Info { status: Some("allowed".into()), seven_day: Some(Window { utilization: 0.6, resets_at: Some(NOW + 86_400) }), ..Info::default() };
        assert_eq!(record_usage(&paths, "work", "t1", &Outcome::Checked(only.clone()), NOW + 30), Ok(true));
        let r = rec(&paths);
        assert!(r.get("limited").is_none() && r["five_hour"]["utilization"].as_float() == Some(0.2) && r["seven_day"]["utilization"].as_float() == Some(0.6), "{r}");
        assert_eq!(record_usage(&paths, "work", "t1", &Outcome::Checked(only.clone()), NOW + 120), Ok(true));
        assert!(rec(&paths).get("five_hour").is_none(), "its reset passed");
        assert_eq!(record_usage(&paths, "work", "t2", &Outcome::Checked(only), NOW), Ok(false), "sealed anew since");
    }

    /// A hanging claude is ended at the run's bound, its group with it (a
    /// child it started too), and the output it wrote before is read; the
    /// token is on fd 3 and nowhere else.
    #[test]
    fn a_hanging_claude_is_ended_with_its_group() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let claude = d.path().join("claude");
        let pids = d.path().join("pids");
        std::fs::write(&claude, format!("#!/bin/sh\nprintf '%s\\n' '{{\"type\":\"system\",\"subtype\":\"init\"}}'\ncat <&3 > \"{}/got\"\nenv > \"{}/env\"\nsleep 30 &\necho $! > \"{}\"\nwait\n", d.path().display(), d.path().display(), pids.display())).unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = d.path().join("home");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let token = crate::bridge::setup_token::parse_token(&format!("sk-ant-oat01-{}hang", "Hg7_".repeat(20))).unwrap();
        let value = token.expose().to_string();
        let turn = Turn { claude: &claude, version: "2.1.305", model: "haiku", deliver: Deliver::Fd };
        let started = Instant::now();
        let ran = runtime().unwrap().block_on(run_claude(&turn, &home, token, Duration::from_secs(2))).unwrap();
        assert!(started.elapsed() < Duration::from_secs(10), "ended at its bound: {:?}", started.elapsed());
        assert!(ran.timed_out && ran.result.is_none() && ran.code.is_none(), "{ran:?}");
        assert!(matches!(judge(&ran), Outcome::Failed { why } if why == "no result within 60 s"));
        assert_eq!(std::fs::read_to_string(d.path().join("got")).unwrap(), value, "the token on fd 3");
        let env = std::fs::read_to_string(d.path().join("env")).unwrap();
        assert!(!env.contains(&value[13..]) && env.contains("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3"), "never in the environment");
        let child: i32 = std::fs::read_to_string(&pids).unwrap().trim().parse().unwrap();
        // SAFETY: signal 0 only asks whether the pid exists.
        let alive = || unsafe { libc::kill(child, 0) } == 0;
        let until = Instant::now() + Duration::from_secs(5);
        while alive() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!alive(), "the group's other process is gone too");
    }

    /// What a claude wrote just before its exit is read (its output's last
    /// line without a newline too), and an answer is checked.
    #[test]
    fn what_claude_wrote_before_its_exit_is_read() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let claude = d.path().join("claude");
        let lines = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","unifiedWindows":{"five_hour":{"utilization":0.1,"resetsAt":1792591200}}}}"#;
        std::fs::write(&claude, format!("#!/bin/sh\nprintf '%s\\n' '{lines}'\nprintf '%s' '{{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"OK\"}}'\nexit 0\n")).unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = d.path().join("home");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let token = crate::bridge::setup_token::parse_token(&format!("sk-ant-oat01-{}done", "Dn7_".repeat(20))).unwrap();
        let turn = Turn { claude: &claude, version: "2.1.305", model: "haiku", deliver: Deliver::Env };
        let ran = runtime().unwrap().block_on(run_claude(&turn, &home, token, Duration::from_secs(20))).unwrap();
        assert_eq!(ran.code, Some(0));
        let Outcome::Checked(info) = judge(&ran) else { panic!("{ran:?}") };
        assert_eq!(info.five_hour.map(|w| w.utilization), Some(0.1));
    }
}
