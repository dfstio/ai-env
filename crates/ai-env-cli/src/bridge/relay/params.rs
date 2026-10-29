//! The relay's three lists (S13, WM-R41 to WM-R45, WM-R7): `/ai-env/relay/workers` (the whitelist of worker
//! keys and the source names each may register), `/ai-env/relay/token-signers` (the keys whose VM session tokens
//! the relay takes: each Mac's session key) and `/ai-env/relay/grants` (the source and op rules a token's grant
//! reaches). Each is one SSM String parameter holding a compact JSON array, rendered and parsed by
//! `ai_env_worker::policy` (the relay reads them with the same code), and written only by ai-env-deployer.
//!
//! - The identity gate (WM-R41): no marker (the resolver would pick `credentials/ops.env`) and an ops marker are
//!   refused, exit 9, before any unseal or AWS call: the lists decide who reaches private data. A deployer,
//!   root or ambient marker passes (IAM decides for those); a marker the resolver refuses keeps its own refusal.
//!   `relay tls init|rotate` refuse a root or ambient marker too ([`tls_gate`]): the relay's private key rides
//!   on their aws child's stdin, and that child would read the user's own aws config.
//! - The read-modify-write (WM-R42), under `state/relay.lock`: one `get-parameters`, a list that does not parse
//!   never overwritten (exit 1), the edit, the limits before any write (exit 1), then the write: a missing
//!   parameter created by [`create_parameter`] (`--type String`, no `--overwrite`: a parameter created meanwhile
//!   is exit 7), an existing one overwritten; the version it answers must be the read one plus one (exit 7
//!   otherwise: another writer). The lists are created at their first write, never by Pulumi (B-4).
//! - One key, one id and one role (WM-R43, Q-WM18): a key another id holds in the same list, or that the other
//!   list holds, is refused (exit 9): a worker key allowed as a token signer would let a server mint tokens.
use super::cli::{audit, runtime, say, shell_word, RelayCtx};
use crate::bridge::audit::event::{RELAY_ALLOW, RELAY_GRANT, RELAY_REVOKE};
use crate::bridge::awscli::{aws_cmd_as, CALL_TIMEOUT};
use crate::bridge::doctor::run_capture_cmd;
use crate::bridge::egress::ops;
use crate::bridge::identity::{self, Operator, Role};
use crate::bridge::registry::ensure_private_dir;
use crate::bridge::vm::lock::lock_exclusive;
use crate::errors::{CliError, Result};
use crate::wire::time::{parse_rfc3339_utc, rfc3339_utc, unix_now};
use ai_env_worker::globs::{valid_glob, valid_id, valid_rule};
use ai_env_worker::keys::PublicKey;
use ai_env_worker::policy::{self, Grant, SignerEntry, WorkerEntry, ENTRIES_MAX, GRANTS, PARAMETER_MAX, RULES_MAX, SOURCES_MAX, TOKEN_SIGNERS, WORKERS};
use serde_json::Value;
use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

/// How long a writer waits for `state/relay.lock` (WM-R42).
const LOCK_BUDGET: Duration = Duration::from_secs(60);
/// `--not-after`'s farthest day, from today (WM-R43).
const NOT_AFTER_MAX_DAYS: u64 = 731;
/// `--not-after`'s default, from today.
const NOT_AFTER_DEFAULT_DAYS: u64 = 365;
const DAY_S: u64 = 86_400;

/// The type `put-parameter` creates a parameter with: the lists are Strings (a second SecureString would fail the
/// relay's whole fetch on `NoOtherDecrypt`, I §5.2); `tls` alone is a SecureString under `alias/aws/ssm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    String,
    SecureString,
}

/// `put-parameter` of a parameter that does not exist yet, without `--overwrite` (`--type`, `--tier Standard`,
/// `--key-id alias/aws/ssm` for a SecureString), as `op` (WM-R42, WM-R60); the value is never in an argument list.
/// A String's value goes through a 0600 temp file in the private `state/` directory (`--value file://…`, as
/// `egress::ops::put_parameter`), removed on every path; a SecureString's never touches the disk: it goes on the
/// aws child's stdin (`put_secure`, plans/s13-contracts.md §Q.8 F5). `Ok` is the new version; `Err` exit 7
/// with aws's error (`ParameterAlreadyExists` when another writer created it meanwhile).
pub fn create_parameter(op: &Operator, name: &str, value: &str, kind: ParamType) -> Result<u64> {
    let paths = crate::bridge::config::Paths::resolve()?;
    create_parameter_in(&super::cli::state_dir(&paths), op, name, value, kind).map_err(CliError::Aws)
}

/// [`create_parameter`] with a String's temp file directory given (a SecureString uses none).
fn create_parameter_in(dir: &Path, op: &Operator, name: &str, value: &str, kind: ParamType) -> std::result::Result<u64, String> {
    if kind == ParamType::SecureString {
        return put_secure(op, name, value, false);
    }
    ensure_private_dir(dir).map_err(|e| format!("cannot prepare {}: {e}", dir.display()))?;
    let mut tmp = tempfile::Builder::new().prefix(".param.").suffix(".tmp").tempfile_in(dir).map_err(|e| format!("cannot create a temp file for {name} in {}: {e}", dir.display()))?;
    tmp.write_all(value.as_bytes()).and_then(|()| tmp.flush()).map_err(|e| format!("cannot write the temp file for {name}: {e}"))?;
    let file_arg = format!("file://{}", tmp.path().display());
    let args = ["put-parameter", "--name", name, "--value", &file_arg, "--type", "String", "--tier", "Standard"];
    let cmd = aws_cmd_as("ssm", &args, op)?;
    let out = run_capture_cmd(cmd, None, CALL_TIMEOUT).map_err(|e| format!("aws ssm put-parameter: {e}"));
    drop(tmp);
    version_of(&out?)
}

/// What the aws CLI reads a SecureString's value from: its own stdin.
const STDIN_VALUE: &str = "file:///dev/stdin";

/// `put-parameter` of the SecureString `name` as `op`, its value written to the aws child's stdin (`--value
/// file:///dev/stdin`): it never touches the disk, nor an argument list (WM-R54, WM-R60; §Q.8 F5). Always
/// `--type SecureString --key-id alias/aws/ssm`: created with `--tier Standard` and no `--overwrite`, or with
/// `overwrite` overwritten (`--overwrite`; SSM never changes a parameter's type, so a `name` that is not a
/// SecureString is refused with `HierarchyTypeMismatchException` rather than given the value). The child's
/// `AWS_CLI_AUTO_PROMPT` is `off`: the CLI's prompt, `on` in the environment or the user's config, would read its
/// keystrokes from that stdin. `Ok` is the new version; `Err` aws's error.
pub(crate) fn put_secure(op: &Operator, name: &str, value: &str, overwrite: bool) -> std::result::Result<u64, String> {
    let mut args = vec!["put-parameter", "--name", name, "--value", STDIN_VALUE, "--type", "SecureString", "--key-id", "alias/aws/ssm"];
    if overwrite {
        args.push("--overwrite");
    } else {
        args.extend(["--tier", "Standard"]);
    }
    let mut cmd = aws_cmd_as("ssm", &args, op)?;
    cmd.env("AWS_CLI_AUTO_PROMPT", "off");
    let out = run_capture_cmd(cmd, Some(value.as_bytes()), CALL_TIMEOUT).map_err(|e| format!("aws ssm put-parameter: {e}"))?;
    version_of(&out)
}

/// The `Version` of a `put-parameter` answer (0 when it names none).
fn version_of(out: &str) -> std::result::Result<u64, String> {
    let doc: Value = serde_json::from_str(out).map_err(|e| format!("aws ssm put-parameter: unexpected output: {e}"))?;
    Ok(doc.get("Version").and_then(Value::as_u64).unwrap_or(0))
}

// ---- the gate ---------------------------------------------------------------------------------

/// Whether a writer of the relay's lists or TLS is refused before any unseal or AWS call (WM-R41,
/// `egress::cli::allow_refused`'s rule): no marker (the resolver would pick `credentials/ops.env`) or a valid
/// ops marker is refused; the deployer, root and ambient markers pass (IAM decides for them), and a marker the
/// resolver refuses is left to its own refusal.
fn refused(declared: Option<&std::result::Result<Operator, String>>) -> bool {
    match declared {
        None => true,
        Some(Ok(op)) => op.role() == Some(Role::Ops),
        Some(Err(_)) => false,
    }
}

/// `<cmd> <args>` as given, each argument a shell word: what a refusal names after `ai-env relay`.
fn as_given(cmd: &str, args: &[String]) -> String {
    let shown: Vec<String> = args.iter().map(|a| shell_word(a)).collect();
    std::iter::once(cmd.to_string()).chain(shown).collect::<Vec<_>>().join(" ")
}

/// [`refused`]'s refusal of `relay <cmd> <args>` (exit 9), naming the command to run instead, as given.
pub(crate) fn gate(cmd: &str, args: &[String]) -> Result<()> {
    if !refused(identity::declared().as_ref()) {
        return Ok(());
    }
    let given = as_given(cmd, args);
    Err(CliError::Policy(format!(
        "relay {cmd}: the relay's whitelist and grants decide who reaches private data, and only ai-env-deployer writes them: run ai-env as deployer -- ai-env relay {given}"
    )))
}

/// Whether `relay tls init|rotate` is refused under a marker [`refused`] passes: a root or ambient one
/// (plans/s13-contracts.md §Q.8 F5). Their aws child keeps the user's own aws config (identity's
/// `AMBIENT_PINS`), whose `cli_history = enabled` would record each call's parameters in
/// `~/.aws/cli/history/history.db`, the `tls` value with the relay's private key among them; a deployer's child
/// reads no config (`AWS_CONFIG_FILE=/dev/null`).
fn tls_refused(declared: Option<&std::result::Result<Operator, String>>) -> bool {
    matches!(declared, Some(Ok(Operator::Ambient { .. })))
}

/// [`gate`], then [`tls_refused`]'s refusal of `relay <cmd> <args>` (exit 9), both before any unseal or AWS call.
pub(crate) fn tls_gate(cmd: &str, args: &[String]) -> Result<()> {
    gate(cmd, args)?;
    if !tls_refused(identity::declared().as_ref()) {
        return Ok(());
    }
    let given = as_given(cmd, args);
    Err(CliError::Policy(format!(
        "relay {cmd}: under ai-env as root or ambient the aws CLI reads your own aws config, whose cli_history would record the relay's private key: run ai-env as deployer -- ai-env relay {given}"
    )))
}

// ---- the pure edits ---------------------------------------------------------------------------

/// A list entry of `workers` or `token-signers`.
pub(crate) trait Entry: Clone + PartialEq {
    fn id(&self) -> &str;
    fn key_b64(&self) -> &str;
}

impl Entry for WorkerEntry {
    fn id(&self) -> &str {
        &self.worker_id
    }
    fn key_b64(&self) -> &str {
        &self.public_key
    }
}

impl Entry for SignerEntry {
    fn id(&self) -> &str {
        &self.signer_id
    }
    fn key_b64(&self) -> &str {
        &self.public_key
    }
}

/// What an allow did to its list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Allowed {
    Added,
    /// The id's entry changed; its old key when the key itself changed.
    Replaced { old_key: Option<PublicKey> },
    Unchanged,
}

impl Allowed {
    fn word(&self) -> &'static str {
        match self {
            Allowed::Added => "added",
            Allowed::Replaced { .. } => "replaced",
            Allowed::Unchanged => "unchanged",
        }
    }
}

/// `entry` in `list` (WM-R43): a key another id holds is refused (`Err` that id: one key, one id); the id's entry
/// is replaced, or the entry added; the same entry again changes nothing.
pub(crate) fn upsert<E: Entry>(list: &mut Vec<E>, entry: E) -> std::result::Result<Allowed, String> {
    if let Some(other) = list.iter().find(|e| e.key_b64() == entry.key_b64() && e.id() != entry.id()) {
        return Err(other.id().to_string());
    }
    match list.iter_mut().find(|e| e.id() == entry.id()) {
        Some(e) if *e == entry => Ok(Allowed::Unchanged),
        Some(e) => {
            let old_key = (e.key_b64() != entry.key_b64()).then(|| PublicKey::parse_b64(e.key_b64()).ok()).flatten();
            *e = entry;
            Ok(Allowed::Replaced { old_key })
        }
        None => {
            list.push(entry);
            Ok(Allowed::Added)
        }
    }
}

/// The id of the entry of `list` holding `key_b64`, if any (Q-WM18: the other list's).
pub(crate) fn holder<E: Entry>(list: &[E], key_b64: &str) -> Option<String> {
    list.iter().find(|e| e.key_b64() == key_b64).map(|e| e.id().to_string())
}

/// `id`'s entry out of `list`: whether there was one.
pub(crate) fn remove<E: Entry>(list: &mut Vec<E>, id: &str) -> bool {
    let before = list.len();
    list.retain(|e| e.id() != id);
    list.len() != before
}

/// `rules` sorted, each once (WM-R45).
pub(crate) fn normalized(rules: &[String]) -> Vec<String> {
    let mut v = rules.to_vec();
    v.sort();
    v.dedup();
    v
}

/// The grant `grant_id`'s rules become exactly `rules`, sorted and deduplicated: whether the list changed.
pub(crate) fn set_grant(list: &mut Vec<Grant>, grant_id: &str, rules: &[String]) -> bool {
    let allow = normalized(rules);
    match list.iter_mut().find(|g| g.grant_id == grant_id) {
        Some(g) if g.allow == allow => false,
        Some(g) => {
            g.allow = allow;
            true
        }
        None => {
            list.push(Grant { grant_id: grant_id.to_string(), allow });
            true
        }
    }
}

/// The grant `grant_id` out of `list`: whether there was one.
pub(crate) fn remove_grant(list: &mut Vec<Grant>, grant_id: &str) -> bool {
    let before = list.len();
    list.retain(|g| g.grant_id != grant_id);
    list.len() != before
}

// ---- the lists in SSM -------------------------------------------------------------------------

/// One list as SSM holds it now: a missing parameter reads as `[]` at version 0 (B-4).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    name: &'static str,
    value: String,
    version: u64,
    exists: bool,
}

/// `names` in one `get-parameters` (WM-R42): exit 7 when it fails.
fn read(what: &str, names: &[&'static str]) -> Result<Vec<Held>> {
    let wanted: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    let (mut got, _missing) = ops::get_parameters(&wanted).map_err(|e| CliError::Aws(format!("relay {what}: {e}")))?;
    Ok(names
        .iter()
        .map(|n| match got.remove(*n) {
            Some(p) => Held { name: n, value: p.value, version: p.version, exists: true },
            None => Held { name: n, value: "[]".into(), version: 0, exists: false },
        })
        .collect())
}

/// A list that does not parse: exit 1, nothing written.
fn unparsed(what: &str, name: &str, e: &policy::PolicyError) -> CliError {
    CliError::Msg(format!("relay {what}: {name} does not parse ({e}); nothing was written: correct it first (aws ssm put-parameter)"))
}

/// `list` rendered by `render` within the parameter's limits (64 entries, 4096 bytes), else exit 1 naming the
/// count or the size; nothing is written either way.
fn rendered<T: serde::Serialize>(what: &str, name: &str, list: &[T], render: impl Fn(&[T]) -> std::result::Result<String, policy::PolicyError>) -> Result<String> {
    if list.len() > ENTRIES_MAX {
        return Err(CliError::Msg(format!("relay {what}: {name} would be {} entries, over its limit of {ENTRIES_MAX}; nothing was written", list.len())));
    }
    match render(list) {
        Ok(text) if text.len() <= PARAMETER_MAX => Ok(text),
        Ok(text) => Err(CliError::Msg(format!("relay {what}: {name} would be {} bytes, over its limit of {PARAMETER_MAX}; nothing was written", text.len()))),
        Err(e) => {
            let bytes = serde_json::to_string(list).map_or(0, |t| t.len());
            if bytes > PARAMETER_MAX {
                Err(CliError::Msg(format!("relay {what}: {name} would be {bytes} bytes, over its limit of {PARAMETER_MAX}; nothing was written")))
            } else {
                Err(CliError::Msg(format!("relay {what}: {name} would not render ({e}); nothing was written")))
            }
        }
    }
}

/// Write `value` to `held`'s parameter as `op` (WM-R42): created when it was missing (`ParameterAlreadyExists`:
/// exit 7, another writer), else overwritten; the version answered must be the read one plus one, else exit 7
/// naming both. `Ok` is the new version.
fn write(ctx: &RelayCtx, op: &Operator, what: &str, held: &Held, value: &str) -> Result<u64> {
    let version = if held.exists {
        ops::put_parameter(&ctx.state_dir(), held.name, value).map_err(|e| CliError::Aws(format!("relay {what}: {e}")))?
    } else {
        create_parameter_in(&ctx.state_dir(), op, held.name, value, ParamType::String).map_err(|e| {
            if e.contains("ParameterAlreadyExists") {
                CliError::Aws(format!("relay {what}: {} was created meanwhile (another writer): run the command again", held.name))
            } else {
                CliError::Aws(format!("relay {what}: {e}"))
            }
        })?
    };
    if version != held.version + 1 {
        return Err(CliError::Aws(format!(
            "relay {what}: {} moved from v{} to v{version} while it was written (another writer): run the command again to see what it holds",
            held.name, held.version
        )));
    }
    Ok(version)
}

/// `f` under `state/relay.lock` (WM-R42): every read-modify-write of the lists, so two deployers never lose
/// each other's edit.
fn locked<T>(ctx: &RelayCtx, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let rt = runtime()?;
    let guard = rt.block_on(lock_exclusive(&ctx.paths.relay_lock(), LOCK_BUDGET, "the relay lock"))?;
    let out = f();
    drop(guard);
    out
}

// ---- allow --------------------------------------------------------------------------------------

/// `--not-after` (WM-R43): a real UTC day, today or later, at most 731 days ahead; none is today plus 365.
/// `Err` is the usage error's text.
fn not_after_day(given: Option<&str>, now: u64) -> std::result::Result<String, String> {
    let today = now - now % DAY_S;
    let Some(day) = given else {
        return Ok(rfc3339_utc(today + NOT_AFTER_DEFAULT_DAYS * DAY_S)[..10].to_string());
    };
    let at = (day.len() == 10).then(|| parse_rfc3339_utc(&format!("{day}T00:00:00Z"))).flatten().ok_or_else(|| format!("--not-after {day:?} is not a day (YYYY-MM-DD, UTC)"))?;
    if at < today {
        return Err(format!("--not-after {day} is before today ({})", &rfc3339_utc(today)[..10]));
    }
    if at > today + NOT_AFTER_MAX_DAYS * DAY_S {
        return Err(format!("--not-after {day} is more than {NOT_AFTER_MAX_DAYS} days ahead"));
    }
    Ok(day.to_string())
}

/// The kind of an allowed or revoked entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Worker,
    TokenSigner,
}

impl Kind {
    fn of(token_signer: bool) -> Kind {
        if token_signer {
            Kind::TokenSigner
        } else {
            Kind::Worker
        }
    }

    /// The audit's word.
    fn word(self) -> &'static str {
        match self {
            Kind::Worker => "worker",
            Kind::TokenSigner => "token_signer",
        }
    }

    /// What the lines say.
    fn noun(self) -> &'static str {
        match self {
            Kind::Worker => "worker",
            Kind::TokenSigner => "token signer",
        }
    }

    fn param(self) -> &'static str {
        match self {
            Kind::Worker => WORKERS,
            Kind::TokenSigner => TOKEN_SIGNERS,
        }
    }

    fn other(self) -> Kind {
        match self {
            Kind::Worker => Kind::TokenSigner,
            Kind::TokenSigner => Kind::Worker,
        }
    }
}

/// `allow`'s arguments, as given (for the gate's refusal).
fn allow_args(id: &str, key: &str, sources: &[String], token_signer: bool, not_after: Option<&str>) -> Vec<String> {
    let mut args = vec![id.to_string(), "--key".into(), key.to_string()];
    if token_signer {
        args.push("--token-signer".into());
    } else {
        args.extend(["--sources".to_string(), sources.join(",")]);
    }
    if let Some(day) = not_after {
        args.extend(["--not-after".to_string(), day.to_string()]);
    }
    args
}

/// `ai-env relay allow <id> --key <text> (--sources <globs> | --token-signer) [--not-after <YYYY-MM-DD>]`
/// (WM-R43): the arguments checked first (exit 2), then the gate (exit 9), then the lists.
pub fn cmd_allow(id: &str, key: &str, sources: &[String], token_signer: bool, not_after: Option<&str>) -> Result<()> {
    let usage = |why: String| CliError::Usage(format!("relay allow: {why}"));
    if !valid_id(id) {
        return Err(usage(format!("{id:?} is not an id ({})", ai_env_worker::ai_env_source::names::NAME_RULE)));
    }
    let public = PublicKey::parse_text(key).map_err(|_| usage("--key is not a public key's text, ed25519:<base64 of 32 bytes> (52 characters), as keygen prints it".into()))?;
    if token_signer && !sources.is_empty() {
        return Err(usage("--sources and --token-signer: a token signer registers no source".into()));
    }
    let mut globs: Vec<String> = sources.to_vec();
    globs.sort();
    globs.dedup();
    if !token_signer {
        if globs.is_empty() || globs.len() > SOURCES_MAX {
            return Err(usage(format!("--sources names {} glob(s): 1 to {SOURCES_MAX}", globs.len())));
        }
        if let Some(bad) = globs.iter().find(|g| !valid_glob(g)) {
            return Err(usage(format!("--sources {bad:?} is not a glob (1 to 64 of [a-z0-9._-*], starting with [a-z0-9*], at most 4 *)")));
        }
    }
    let day = not_after_day(not_after, unix_now()).map_err(usage)?;
    let until = policy::not_after_of_day(&day).map_err(|e| usage(format!("--not-after {day}: {e}")))?;
    gate("allow", &allow_args(id, key, sources, token_signer, not_after))?;
    let ctx = RelayCtx::load()?;
    let op = ctx.operator("relay allow")?;
    let kind = Kind::of(token_signer);
    let fp = public.fingerprint();
    locked(&ctx, || {
        let lists = read("allow", &[kind.param(), kind.other().param()])?;
        let (mine, theirs) = (&lists[0], &lists[1]);
        // Q-WM18: one key, one role: the other list must not hold this key.
        let elsewhere = match kind {
            Kind::Worker => holder(&policy::parse_signers(&theirs.value).map_err(|e| unparsed("allow", theirs.name, &e))?, &public.b64()),
            Kind::TokenSigner => holder(&policy::parse_workers(&theirs.value).map_err(|e| unparsed("allow", theirs.name, &e))?, &public.b64()),
        };
        if let Some(other) = elsewhere {
            return Err(CliError::Policy(format!("relay allow: the key fp {fp} is already allowed as {} {other}: one key, one role", kind.other().noun())));
        }
        let (outcome, value, count) = match kind {
            Kind::Worker => {
                let mut list = policy::parse_workers(&mine.value).map_err(|e| unparsed("allow", mine.name, &e))?;
                let entry = WorkerEntry { worker_id: id.to_string(), alg: "ed25519".into(), public_key: public.b64(), sources: globs.clone(), not_after: until.clone() };
                let outcome = upsert(&mut list, entry).map_err(|other| CliError::Policy(format!("relay allow: the key fp {fp} is already allowed as {other}: one key, one id")))?;
                (outcome, rendered("allow", mine.name, &list, policy::render_workers)?, list.len())
            }
            Kind::TokenSigner => {
                let mut list = policy::parse_signers(&mine.value).map_err(|e| unparsed("allow", mine.name, &e))?;
                let entry = SignerEntry { signer_id: id.to_string(), alg: "ed25519".into(), public_key: public.b64(), not_after: until.clone() };
                let outcome = upsert(&mut list, entry).map_err(|other| CliError::Policy(format!("relay allow: the key fp {fp} is already allowed as {other}: one key, one id")))?;
                (outcome, rendered("allow", mine.name, &list, policy::render_signers)?, list.len())
            }
        };
        let scope = match kind {
            Kind::Worker => format!(" for sources {}", globs.join(",")),
            Kind::TokenSigner => String::new(),
        };
        let mut pairs = vec![("kind", kind.word().to_string()), ("id", id.to_string()), ("fp", fp.clone()), ("outcome", outcome.word().to_string())];
        if kind == Kind::Worker {
            pairs.push(("sources", globs.len().to_string()));
        }
        pairs.push(("not_after", day.clone()));
        if outcome == Allowed::Unchanged {
            say(&format!("{} {id} (key fp {fp}) is already allowed{scope} until {day} ({} v{}); nothing written", kind.noun(), mine.name, mine.version));
            pairs.push(("version", mine.version.to_string()));
            audit(&ctx.paths, RELAY_ALLOW, &pairs);
            return Ok(());
        }
        let version = write(&ctx, &op, "allow", mine, &value)?;
        pairs.push(("version", version.to_string()));
        audit(&ctx.paths, RELAY_ALLOW, &pairs);
        let replaced = match &outcome {
            Allowed::Replaced { old_key: Some(old) } => format!("; replaced its key fp {} by fp {fp}", old.fingerprint()),
            _ => String::new(),
        };
        let applies = match kind {
            Kind::Worker => "the relay applies it within 60 s",
            Kind::TokenSigner => "the relay takes its tokens within 60 s",
        };
        say(&format!("allowed {} {id} (key fp {fp}){scope} until {day} ({} v{version}, {count} {}(s)){replaced}; {applies}", kind.noun(), mine.name, kind.noun()));
        if kind == Kind::Worker && globs.iter().any(|g| g == "*") {
            say("this worker may register any source name");
        }
        Ok(())
    })
}

// ---- revoke -------------------------------------------------------------------------------------

/// `ai-env relay revoke <id> [--token-signer]` (WM-R44): the entry removed; one not listed (a missing list
/// too, B-4) writes nothing and exits 0.
pub fn cmd_revoke(id: &str, token_signer: bool) -> Result<()> {
    if !valid_id(id) {
        return Err(CliError::Usage(format!("relay revoke: {id:?} is not an id ({})", ai_env_worker::ai_env_source::names::NAME_RULE)));
    }
    let mut args = vec![id.to_string()];
    if token_signer {
        args.push("--token-signer".into());
    }
    gate("revoke", &args)?;
    let ctx = RelayCtx::load()?;
    let op = ctx.operator("relay revoke")?;
    let kind = Kind::of(token_signer);
    locked(&ctx, || {
        let held = read("revoke", &[kind.param()])?.remove(0);
        let (removed, value) = match kind {
            Kind::Worker => {
                let mut list = policy::parse_workers(&held.value).map_err(|e| unparsed("revoke", held.name, &e))?;
                let removed = remove(&mut list, id);
                (removed, if removed { rendered("revoke", held.name, &list, policy::render_workers)? } else { String::new() })
            }
            Kind::TokenSigner => {
                let mut list = policy::parse_signers(&held.value).map_err(|e| unparsed("revoke", held.name, &e))?;
                let removed = remove(&mut list, id);
                (removed, if removed { rendered("revoke", held.name, &list, policy::render_signers)? } else { String::new() })
            }
        };
        let mut pairs = vec![("kind", kind.word().to_string()), ("id", id.to_string())];
        if !removed {
            say(&format!("{id} is not listed in {}; nothing written", held.name));
            pairs.push(("outcome", "absent".to_string()));
            audit(&ctx.paths, RELAY_REVOKE, &pairs);
            return Ok(());
        }
        let version = write(&ctx, &op, "revoke", &held, &value)?;
        pairs.extend([("outcome", "revoked".to_string()), ("version", version.to_string())]);
        audit(&ctx.paths, RELAY_REVOKE, &pairs);
        match kind {
            Kind::Worker => say(&format!("revoked worker {id} ({} v{version}): the relay closes its tunnel within 60 s", held.name)),
            Kind::TokenSigner => say(&format!("revoked token signer {id} ({} v{version}): the relay refuses its tokens within 60 s", held.name)),
        }
        Ok(())
    })
}

// ---- grant --------------------------------------------------------------------------------------

/// `ai-env relay grant <grant-id> <rule>… | --remove` (WM-R45): the grant's rules become exactly the sorted,
/// deduplicated set; `--remove` deletes the grant (absent, a missing list too: nothing written, exit 0).
pub fn cmd_grant(grant_id: &str, rules: &[String], remove: bool) -> Result<()> {
    let usage = |why: String| CliError::Usage(format!("relay grant: {why}"));
    if !valid_id(grant_id) {
        return Err(usage(format!("{grant_id:?} is not an id ({})", ai_env_worker::ai_env_source::names::NAME_RULE)));
    }
    if remove && !rules.is_empty() {
        return Err(usage("--remove takes no rule".into()));
    }
    let set = normalized(rules);
    if !remove {
        if let Some(bad) = set.iter().find(|r| !valid_rule(r)) {
            return Err(usage(format!("{bad:?} is not a rule (<source-glob>/<op-glob>)")));
        }
        if set.is_empty() || set.len() > RULES_MAX {
            return Err(usage(format!("{} rule(s): 1 to {RULES_MAX}", set.len())));
        }
    }
    let mut args = vec![grant_id.to_string()];
    if remove {
        args.push("--remove".into());
    } else {
        args.extend(rules.iter().cloned());
    }
    gate("grant", &args)?;
    let ctx = RelayCtx::load()?;
    let op = ctx.operator("relay grant")?;
    locked(&ctx, || {
        let held = read("grant", &[GRANTS])?.remove(0);
        let mut list = policy::parse_grants(&held.value).map_err(|e| unparsed("grant", held.name, &e))?;
        let changed = if remove { remove_grant(&mut list, grant_id) } else { set_grant(&mut list, grant_id, &set) };
        let mut pairs = vec![("id", grant_id.to_string())];
        if !changed {
            if remove {
                say(&format!("grant {grant_id} is not in {}; nothing written", held.name));
                pairs.push(("outcome", "absent".to_string()));
            } else {
                say(&format!("grant {grant_id}: {} rule(s) ({} v{}); nothing written", set.len(), held.name, held.version));
                pairs.extend([("outcome", "unchanged".to_string()), ("rules", set.len().to_string()), ("version", held.version.to_string())]);
            }
            audit(&ctx.paths, RELAY_GRANT, &pairs);
            return Ok(());
        }
        let value = rendered("grant", held.name, &list, policy::render_grants)?;
        let version = write(&ctx, &op, "grant", &held, &value)?;
        if remove {
            pairs.extend([("outcome", "removed".to_string()), ("version", version.to_string())]);
            audit(&ctx.paths, RELAY_GRANT, &pairs);
            say(&format!("removed grant {grant_id} ({} v{version}): tokens naming it are refused within 60 s", held.name));
        } else {
            pairs.extend([("outcome", "set".to_string()), ("rules", set.len().to_string()), ("version", version.to_string())]);
            audit(&ctx.paths, RELAY_GRANT, &pairs);
            let every = if set.iter().any(|r| r == "*/*") { "; this grant reaches every source and op" } else { "" };
            say(&format!("grant {grant_id}: {} rule(s) ({} v{version}){every}", set.len(), held.name));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::identity::{declared_operator, Marker};

    fn key(seed: u8) -> PublicKey {
        ai_env_worker::keys::SigningKey::from_seed(&[seed; 32]).unwrap().public_key()
    }

    fn worker(id: &str, seed: u8, sources: &[&str]) -> WorkerEntry {
        WorkerEntry { worker_id: id.into(), alg: "ed25519".into(), public_key: key(seed).b64(), sources: sources.iter().map(|s| (*s).to_string()).collect(), not_after: "2027-10-29T23:59:59Z".into() }
    }

    fn signer(id: &str, seed: u8) -> SignerEntry {
        SignerEntry { signer_id: id.into(), alg: "ed25519".into(), public_key: key(seed).b64(), not_after: "2027-10-29T23:59:59Z".into() }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    /// WM-T35: the pure edits. An allow adds; a second allow with a new key replaces and names the old key; the
    /// same allow is unchanged; a key another id holds is refused (one key, one id); the other list's holder is
    /// found (Q-WM18: one key, one role); revoke removes, then finds nothing; a grant's rules come out sorted and
    /// deduplicated, the same set again changes nothing, `--remove` removes; `refused` is true for no marker and
    /// an ops marker, false for the deployer, root and ambient markers and for a marker the resolver refuses;
    /// `tls_refused` is true for the root and ambient markers, false for the deployer and a refused marker.
    #[test]
    fn edits_upsert_remove_and_set_exactly() {
        let mut workers = Vec::new();
        assert_eq!(upsert(&mut workers, worker("worker-a", 1, &["example-*"])), Ok(Allowed::Added));
        assert_eq!(upsert(&mut workers, worker("worker-a", 2, &["example-*"])), Ok(Allowed::Replaced { old_key: Some(key(1)) }), "a new key replaces, naming the old");
        assert_eq!(workers, [worker("worker-a", 2, &["example-*"])]);
        assert_eq!(upsert(&mut workers, worker("worker-a", 2, &["example-*"])), Ok(Allowed::Unchanged));
        assert_eq!(upsert(&mut workers, worker("worker-a", 2, &["other-*"])), Ok(Allowed::Replaced { old_key: None }), "new globs, the same key");
        assert_eq!(upsert(&mut workers, worker("worker-b", 2, &["example-*"])), Err("worker-a".to_string()), "one key, one id");
        assert_eq!(workers.len(), 1, "nothing changed by the refusal");
        assert_eq!(upsert(&mut workers, worker("worker-b", 3, &["example-*"])), Ok(Allowed::Added));
        // Q-WM18: a worker key is not a token signer's, nor the reverse.
        let signers = vec![signer("mac", 7)];
        assert_eq!(holder(&signers, &key(7).b64()), Some("mac".to_string()));
        assert_eq!(holder(&workers, &key(3).b64()), Some("worker-b".to_string()));
        assert_eq!(holder(&signers, &key(3).b64()), None);
        let mut signers = signers;
        assert_eq!(upsert(&mut signers, signer("mac", 7)), Ok(Allowed::Unchanged));
        assert!(remove(&mut workers, "worker-a"));
        assert!(!remove(&mut workers, "worker-a"), "absent the second time");
        assert_eq!(workers, [worker("worker-b", 3, &["example-*"])]);
        let mut grants = Vec::new();
        assert!(set_grant(&mut grants, "default", &s(&["example-*/list", "example-*/get", "example-*/list"])));
        assert_eq!(grants, [Grant { grant_id: "default".into(), allow: s(&["example-*/get", "example-*/list"]) }], "sorted, each once");
        assert!(!set_grant(&mut grants, "default", &s(&["example-*/get", "example-*/list"])), "the same set: unchanged");
        assert!(set_grant(&mut grants, "default", &s(&["*/*"])));
        assert_eq!(grants[0].allow, s(&["*/*"]), "exactly the new set");
        assert!(remove_grant(&mut grants, "default") && grants.is_empty());
        assert!(!remove_grant(&mut grants, "default"));
        // The gate.
        let key_env = |role: &str| -> std::result::Result<Operator, String> {
            let id = format!("{}{}{}", "AKIA", "FAKE", "000000009002");
            declared_operator(Marker::parse(&format!("{role}:9002")), Some(&id), Some(&"Dm7/".repeat(10)))
        };
        assert!(refused(None), "no marker: the resolver would pick credentials/ops.env");
        assert!(refused(Some(&key_env("ops"))), "an ops marker");
        assert!(!refused(Some(&key_env("deployer"))), "the deployer");
        for word in ["root", "ambient"] {
            assert!(!refused(Some(&declared_operator(Marker::parse(word), None, None))), "{word}");
        }
        assert!(!refused(Some(&Err("a refused marker".to_string()))), "left to its own refusal");
        // `tls init|rotate` also refuse root and ambient (§Q.8 F5): their aws child reads the user's aws config.
        for word in ["root", "ambient"] {
            assert!(tls_refused(Some(&declared_operator(Marker::parse(word), None, None))), "tls as {word}");
        }
        assert!(!tls_refused(Some(&key_env("deployer"))) && !tls_refused(Some(&Err("a refused marker".to_string()))), "tls: the deployer, and a marker left to its own refusal");
    }

    /// `--not-after`: a real day, today to 731 days ahead; none is a year from today.
    #[test]
    fn the_not_after_day_is_a_real_day_within_two_years() {
        let now = 1_793_232_000 + 3600; // 2026-10-29T01:00:00Z
        assert_eq!(rfc3339_utc(now), "2026-10-29T01:00:00Z");
        assert_eq!(not_after_day(None, now).unwrap(), "2027-10-29");
        assert_eq!(not_after_day(Some("2026-10-29"), now).unwrap(), "2026-10-29", "today");
        assert_eq!(not_after_day(Some("2028-10-29"), now).unwrap(), "2028-10-29", "731 days");
        for bad in ["2026-10-28", "2028-10-30", "2027-13-01", "2027-02-29", "27-10-29", "2027-10-29T00:00:00Z", ""] {
            assert!(not_after_day(Some(bad), now).is_err(), "{bad:?}");
        }
        assert_eq!(policy::not_after_of_day("2027-10-29").unwrap(), "2027-10-29T23:59:59Z");
    }
}
