//! The relay's five lists (S13, WM-R41 to WM-R45, WM-R7; the relay security plan, §RS.4, §RS.13): `/ai-env/relay/workers`
//! (the whitelist of worker keys and the source names each may register), `/ai-env/relay/token-signers` (the keys
//! whose VM session tokens the relay takes: each Mac's session key), `/ai-env/relay/grants` (the source and op rules
//! a token's grant reaches), `/ai-env/relay/peers` (the networks the public face admits) and `/ai-env/relay/access`
//! (the grants each chat holds beyond its token's own). Each is one SSM String parameter holding a compact JSON array,
//! rendered and parsed by `ai_env_worker::policy` (the relay reads them with the same code), the first four written
//! only by ai-env-deployer and the access list by ai-env-ops too.
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
//! - A worker's client certificate (§RS.4.2, R-131): `allow --tls-key` unseals the relay CA's key (one Touch ID, the
//!   deployer alone: a root or ambient marker is refused too), issues a certificate for the worker's P-256 point up
//!   to the entry's `not_after`, prints it on stdout and writes its SHA-256 as the entry's `tls_fp`; stdout holds the
//!   only copy, so a failed print is a failed run. `allow` without it keeps the entry's `tls_fp`, and that certificate
//!   keeps the end it was issued with.
//! - A token signer's grants (§RS.4.2, R-134): `allow --token-signer --grants` makes the entry's `grants` exactly the
//!   sorted set; without `--grants` the entry keeps its own, so a key rotation narrows and widens nothing, and a new
//!   entry has none, which reaches every grant. A relay older than wave 4 refuses a list with `grants`, and every token
//!   then fails: `--grants` is written only after that relay runs (RO-6), which its note says.
//! - One network, one label (§RS.4.2, R-86): `allow-ip` is an upsert by label, `revoke-ip` a removal by network or
//!   by label. A prefix under 16 needs `--wide`: a typo such as `/0` must not lift the allowlist (Q-R22). `--mine`
//!   asks checkip.amazonaws.com for this Mac's address and writes it as the `/32` of the label `mac`.
//! - One chat's access (§RS.13, R-150): `access` names no marker of its own, so no gate: IAM decides, and of the relay's
//!   lists ops writes this one alone (`WriteRelayAccess`). A Touch ID approves a chat the row of a session on this Mac names, for
//!   a grant `[relay].offer` names and `/ai-env/relay/grants` holds; every write prunes the lapsed entries. `state/relay-access.json`
//!   keeps what was last read for the panel to show (R-152): the relay alone is the gate, and a write that reports failure,
//!   which may have landed, leaves no cache.
use super::cli::{audit, note, runtime, say, shell_word, RelayCtx};
use crate::bridge::audit::event::{RELAY_ACCESS, RELAY_ALLOW, RELAY_ALLOW_IP, RELAY_GRANT, RELAY_REVOKE, RELAY_REVOKE_IP};
use crate::bridge::awscli::{aws_cmd_as, CALL_TIMEOUT};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::doctor::run_capture_cmd;
use crate::bridge::egress::ops;
use crate::bridge::identity::{self, Operator, Role};
use crate::bridge::registry::{self, ensure_private_dir};
use crate::bridge::vm::lock::lock_exclusive;
use crate::errors::{CliError, Result};
use crate::store::Keystore;
use crate::wire::time::{parse_rfc3339_utc, rfc3339_utc, unix_now};
use ai_env_worker::certs::{self, ClientPoint};
use ai_env_worker::globs::{glob_match, valid_glob, valid_id, valid_rule};
use ai_env_worker::keys::PublicKey;
use ai_env_worker::policy::{self, AccessEntry, Grant, PeerEntry, SignerEntry, WorkerEntry, ACCESS, ENTRIES_MAX, GRANTS, PARAMETER_MAX, PEERS, RULES_MAX, SIGNER_GRANTS_MAX, SOURCES_MAX, TOKEN_SIGNERS, WORKERS};
use serde_json::Value;
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

/// How long a writer waits for `state/relay.lock` (WM-R42).
const LOCK_BUDGET: Duration = Duration::from_secs(60);
/// `--not-after`'s farthest day, from today (WM-R43).
const NOT_AFTER_MAX_DAYS: u64 = 731;
/// `--not-after`'s default, from today.
const NOT_AFTER_DEFAULT_DAYS: u64 = 365;
const DAY_S: u64 = 86_400;
/// The label of this Mac's own entry in the peers list (§RS.4.2).
pub(crate) const MAC_LABEL: &str = "mac";
/// A network wider than /16 needs `--wide`, and `relay status` warns of it (Q-R22).
pub(crate) const WIDE_BELOW: u8 = 16;
/// `--mine`'s `--hours` (§RS.4.2).
const MINE_HOURS_DEFAULT: u32 = 24;
const MINE_HOURS_MAX: u32 = 168;
/// The host that tells this Mac its address, and what `--mine` allows it (§RS.4.2).
const CHECKIP_HOST: &str = "checkip.amazonaws.com";
const CHECKIP_TIMEOUT: Duration = Duration::from_secs(10);
const CHECKIP_BODY_MAX: usize = 64;
/// `relay access --days`: how many days past today an entry's last day lies, by default and at most (R-150).
pub(crate) const ACCESS_DAYS_DEFAULT: u32 = 30;
const ACCESS_DAYS_MAX: u32 = 90;

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

/// [`gate`], then the refusal of `allow --tls-key` under a root or ambient marker (§RS.4.2, exit 9), both before any
/// unseal or AWS call: only the deployer takes the relay CA's key out of its seal.
fn tls_key_gate(args: &[String]) -> Result<()> {
    gate("allow", args)?;
    if !tls_refused(identity::declared().as_ref()) {
        return Ok(());
    }
    let given = as_given("allow", args);
    Err(CliError::Policy(format!("relay allow: --tls-key unseals the relay CA's key, which only the deployer uses: run ai-env as deployer -- ai-env relay {given}")))
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

/// What an `allow-ip` did to the peers list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerEdit {
    Added,
    /// The label's entry changed; its old network when the network itself moved.
    Replaced { old: Option<String> },
    Unchanged,
}

impl PeerEdit {
    fn word(&self) -> &'static str {
        match self {
            PeerEdit::Added => "added",
            PeerEdit::Replaced { .. } => "replaced",
            PeerEdit::Unchanged => "unchanged",
        }
    }
}

/// `a.b.c.d/n`.
fn network_text((addr, prefix): (Ipv4Addr, u8)) -> String {
    format!("{addr}/{prefix}")
}

/// `<CIDR>` (§RS.4.2): `a.b.c.d` (read as `/32`) or `a.b.c.d/n` by R-86's grammar, which `render_peers` alone holds:
/// the network it would write.
pub(crate) fn network_of(given: &str) -> Option<(Ipv4Addr, u8)> {
    let cidr = if given.contains('/') { given.to_string() } else { format!("{given}/32") };
    let probe = PeerEntry { cidr, label: MAC_LABEL.to_string(), not_after: "2000-01-01T00:00:00Z".to_string() };
    policy::render_peers(std::slice::from_ref(&probe)).ok()?;
    Some(probe.network())
}

/// `entry` in the peers list (§RS.4.2): a network another label holds is refused (`Err` that label: one network, one
/// label); the label's entry is replaced, or the entry added; the same network and time again changes nothing.
pub(crate) fn upsert_peer(list: &mut Vec<PeerEntry>, entry: PeerEntry) -> std::result::Result<PeerEdit, String> {
    let network = entry.network();
    if let Some(other) = list.iter().find(|p| p.network() == network && p.label != entry.label) {
        return Err(other.label.clone());
    }
    match list.iter_mut().find(|p| p.label == entry.label) {
        Some(p) if p.network() == network && p.not_after == entry.not_after => Ok(PeerEdit::Unchanged),
        Some(p) => {
            let old = (p.network() != network).then(|| network_text(p.network()));
            *p = entry;
            Ok(PeerEdit::Replaced { old })
        }
        None => {
            list.push(entry);
            Ok(PeerEdit::Added)
        }
    }
}

/// Which entry a `revoke-ip` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerNamed {
    Network((Ipv4Addr, u8)),
    Label(String),
}

/// The entry `named` out of the peers list: the entry, if there was one.
pub(crate) fn remove_peer(list: &mut Vec<PeerEntry>, named: &PeerNamed) -> Option<PeerEntry> {
    let at = list.iter().position(|p| match named {
        PeerNamed::Network(network) => p.network() == *network,
        PeerNamed::Label(label) => p.label == *label,
    })?;
    Some(list.remove(at))
}

/// What an edit did to one chat's entry of the access list (R-150): the audit's `outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessEdit {
    /// The grant joined the chat's entry, or an entry was made.
    Added,
    /// The chat held the grant, and its entry's end moved later.
    Extended,
    /// The chat held the grant until that end or later.
    Unchanged,
    Removed,
    /// The chat did not hold the grant.
    Absent,
}

impl AccessEdit {
    fn word(self) -> &'static str {
        match self {
            AccessEdit::Added => "added",
            AccessEdit::Extended => "extended",
            AccessEdit::Unchanged => "unchanged",
            AccessEdit::Removed => "removed",
            AccessEdit::Absent => "absent",
        }
    }
}

/// The entries lapsed at `now` out of `list`: how many there were (R-150). What the reader holds in force is `now <=
/// not_after`, so an entry whose last second is `now` stays.
pub(crate) fn prune_access(list: &mut Vec<AccessEntry>, now: u64) -> usize {
    let before = list.len();
    list.retain(|a| now <= a.not_after_unix());
    before - list.len()
}

/// The last valid day of an approval of `days` at `now`, `YYYY-MM-DD`, UTC (R-150).
pub(crate) fn access_day(now: u64, days: u32) -> String {
    rfc3339_utc(now - now % DAY_S + u64::from(days) * DAY_S)[..10].to_string()
}

/// `grant` in `chat`'s entry until `not_after`, or later if the entry ends later (R-150); an entry made when it has none.
/// An entry has one end, so this also moves the end of what it holds already: [`cmd_access`] and the confirm page say so.
pub(crate) fn allow_access(list: &mut Vec<AccessEntry>, chat: &str, grant: &str, not_after: &str) -> AccessEdit {
    let Some(entry) = list.iter_mut().find(|a| a.chat == chat) else {
        list.push(AccessEntry { chat: chat.to_string(), grants: vec![grant.to_string()], not_after: not_after.to_string() });
        return AccessEdit::Added;
    };
    let later = policy::unix_of(not_after).is_ok_and(|t| t > entry.not_after_unix());
    if later {
        entry.not_after = not_after.to_string();
    }
    if entry.grants.iter().any(|g| g == grant) {
        return if later { AccessEdit::Extended } else { AccessEdit::Unchanged };
    }
    entry.grants.push(grant.to_string());
    entry.grants.sort();
    AccessEdit::Added
}

/// `grant` out of `chat`'s entry; an entry left empty is removed (R-150).
pub(crate) fn remove_access(list: &mut Vec<AccessEntry>, chat: &str, grant: &str) -> AccessEdit {
    let Some(at) = list.iter().position(|a| a.chat == chat && a.grants.iter().any(|g| g == grant)) else {
        return AccessEdit::Absent;
    };
    list[at].grants.retain(|g| g != grant);
    if list[at].grants.is_empty() {
        list.remove(at);
    }
    AccessEdit::Removed
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

/// `allow`'s arguments, as clap parsed them.
pub struct AllowArgs<'a> {
    pub id: &'a str,
    pub key: &'a str,
    pub sources: &'a [String],
    pub token_signer: bool,
    pub not_after: Option<&'a str>,
    pub tls_key: Option<&'a str>,
    pub grants: &'a [String],
}

impl AllowArgs<'_> {
    /// As given (for the gate's refusals).
    fn given(&self) -> Vec<String> {
        let mut args = vec![self.id.to_string(), "--key".into(), self.key.to_string()];
        if self.token_signer {
            args.push("--token-signer".into());
        } else {
            args.extend(["--sources".to_string(), self.sources.join(",")]);
        }
        if let Some(day) = self.not_after {
            args.extend(["--not-after".to_string(), day.to_string()]);
        }
        if let Some(point) = self.tls_key {
            args.extend(["--tls-key".to_string(), point.to_string()]);
        }
        if !self.grants.is_empty() {
            args.extend(["--grants".to_string(), self.grants.join(",")]);
        }
        args
    }
}

/// What an `allow` of a worker did about its client certificate (§RS.4.2).
enum WorkerCert {
    /// `--tls-key`: the new certificate's DER, and the fingerprint of the one it replaced.
    Issued { der: Vec<u8>, old: Option<String> },
    /// None asked for: the entry's stays, the first 16 of its `tls_fp`; `outrun` when this run moves the entry's end
    /// later, which a certificate does not follow (only its fingerprint is on the list, so no row can show it).
    Kept { fp: String, outrun: bool },
    /// None asked for, and the entry has none.
    None,
}

/// The first 16 of a `tls_fp`: the form every row and line shows (LD-R44).
pub(crate) fn fp16(tls_fp: &str) -> &str {
    tls_fp.get(..16).unwrap_or(tls_fp)
}

/// One `note: …` line on stderr (never a panic on a closed pipe): stdout keeps the lines the contract gives it.
fn side_note(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "note: {line}");
}

/// `ai-env relay allow <id> --key <text> (--sources <globs> [--tls-key <p256:…>] | --token-signer [--grants <globs>])
/// [--not-after <YYYY-MM-DD>]` (WM-R43, §RS.4.2): the arguments checked first (exit 2), then the gate (exit 9), then
/// the lists; `--tls-key`'s one Touch ID comes after the read and WM-R43's checks and before the write.
pub fn cmd_allow(store: &Keystore, args: &AllowArgs<'_>) -> Result<()> {
    let AllowArgs { id, key, sources, token_signer, not_after, tls_key, grants } = *args;
    let usage = |why: String| CliError::Usage(format!("relay allow: {why}"));
    if !valid_id(id) {
        return Err(usage(format!("{id:?} is not an id ({})", ai_env_worker::ai_env_source::names::NAME_RULE)));
    }
    let public = PublicKey::parse_text(key).map_err(|_| usage("--key is not a public key's text, ed25519:<base64 of 32 bytes> (52 characters), as keygen prints it".into()))?;
    if token_signer && !sources.is_empty() {
        return Err(usage("--sources and --token-signer: a token signer registers no source".into()));
    }
    if token_signer && tls_key.is_some() {
        return Err(usage("--tls-key and --token-signer: a token signer has no client certificate".into()));
    }
    if !token_signer && !grants.is_empty() {
        return Err(usage("--grants without --token-signer: a worker mints no token".into()));
    }
    let point = tls_key
        .map(|text| ClientPoint::parse_text(text).map_err(|_| usage("--tls-key is not a P-256 public point's text, p256:<base64 of 65 bytes> (93 characters), as tls-keygen prints it".into())))
        .transpose()?;
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
    let grant_set = normalized(grants);
    if grant_set.len() > SIGNER_GRANTS_MAX {
        return Err(usage(format!("--grants names {} glob(s): 1 to {SIGNER_GRANTS_MAX}", grant_set.len())));
    }
    if let Some(bad) = grant_set.iter().find(|g| !valid_glob(g)) {
        return Err(usage(format!("--grants {bad:?} is not a glob (1 to 64 of [a-z0-9._-*], starting with [a-z0-9*], at most 4 *)")));
    }
    let day = not_after_day(not_after, unix_now()).map_err(usage)?;
    let until = policy::not_after_of_day(&day).map_err(|e| usage(format!("--not-after {day}: {e}")))?;
    if point.is_some() {
        tls_key_gate(&args.given())?;
    } else {
        gate("allow", &args.given())?;
    }
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
        let one_id = |other: String| CliError::Policy(format!("relay allow: the key fp {fp} is already allowed as {other}: one key, one id"));
        let (outcome, value, count, cert, signer_grants) = match kind {
            Kind::Worker => {
                let mut list = policy::parse_workers(&mine.value).map_err(|e| unparsed("allow", mine.name, &e))?;
                let old = list.iter().find(|w| w.worker_id == id);
                let old_end = old.map(WorkerEntry::not_after_unix);
                let held = old.and_then(|w| w.tls_fp.clone());
                let mut entry = WorkerEntry { worker_id: id.to_string(), alg: "ed25519".into(), public_key: public.b64(), sources: globs.clone(), not_after: until.clone(), tls_fp: held.clone() };
                let cert = match &point {
                    Some(point) => {
                        // WM-R43's checks and the limits on the entry as it will be, so a refusal costs no Touch ID.
                        let mut trial = list.clone();
                        upsert(&mut trial, WorkerEntry { tls_fp: Some("0".repeat(64)), ..entry.clone() }).map_err(one_id)?;
                        rendered("allow", mine.name, &trial, policy::render_workers)?;
                        let not_after_unix = policy::unix_of(&until).map_err(|e| usage(format!("--not-after {day}: {e}")))?;
                        let der = super::tls::client_certificate(store, &ctx.paths, id, point, not_after_unix)?;
                        entry.tls_fp = Some(certs::tls_fp(&der));
                        WorkerCert::Issued { der, old: held.map(|t| fp16(&t).to_string()) }
                    }
                    None => held.map_or(WorkerCert::None, |t| WorkerCert::Kept { fp: fp16(&t).to_string(), outrun: old_end.is_some_and(|end| entry.not_after_unix() > end) }),
                };
                let outcome = upsert(&mut list, entry).map_err(one_id)?;
                (outcome, rendered("allow", mine.name, &list, policy::render_workers)?, list.len(), cert, None)
            }
            Kind::TokenSigner => {
                let mut list = policy::parse_signers(&mine.value).map_err(|e| unparsed("allow", mine.name, &e))?;
                // `--grants` is the whole set; without it the entry keeps its own (a key rotation).
                let set = if grant_set.is_empty() { list.iter().find(|s| s.signer_id == id).and_then(|s| s.grants.clone()) } else { Some(grant_set.clone()) };
                let entry = SignerEntry { signer_id: id.to_string(), alg: "ed25519".into(), public_key: public.b64(), not_after: until.clone(), grants: set.clone() };
                let outcome = upsert(&mut list, entry).map_err(one_id)?;
                (outcome, rendered("allow", mine.name, &list, policy::render_signers)?, list.len(), WorkerCert::None, set)
            }
        };
        let scope = match kind {
            Kind::Worker => format!(" for sources {}", globs.join(",")),
            Kind::TokenSigner => signer_grants.as_ref().map_or_else(|| " for every grant".to_string(), |set| format!(" for grants {}", set.join(","))),
        };
        // `(key fp <fp>)`, or with the certificate: issued, or kept.
        let shown = match &cert {
            WorkerCert::Issued { der, .. } => format!("key fp {fp}, cert fp {}", certs::fingerprint(der)),
            WorkerCert::Kept { fp: cert_fp, .. } => format!("key fp {fp}, cert fp {cert_fp} kept"),
            WorkerCert::None => format!("key fp {fp}"),
        };
        // On stderr: stdout keeps WM-R43's lines.
        let cert_note = || match &cert {
            WorkerCert::None if kind == Kind::Worker => side_note(&format!("worker {id} has no client certificate: a relay that requires one refuses it (ai-env relay allow {id} … --tls-key p256:…, after tls-keygen on the worker)")),
            WorkerCert::Kept { outrun: true, .. } => side_note(&format!("worker {id}: this moves the entry's end to {day}, not its client certificate's, which keeps the end it was issued with (ai-env relay allow {id} … --tls-key p256:… issues a new one)")),
            _ => {}
        };
        let mut pairs = vec![("kind", kind.word().to_string()), ("id", id.to_string()), ("fp", fp.clone()), ("outcome", outcome.word().to_string())];
        if kind == Kind::Worker {
            pairs.push(("sources", globs.len().to_string()));
        }
        pairs.push(("not_after", day.clone()));
        if let WorkerCert::Issued { der, .. } = &cert {
            pairs.push(("tls_fp", certs::fingerprint(der)));
        }
        if let Some(set) = &signer_grants {
            pairs.push(("grants", set.len().to_string()));
        }
        if outcome == Allowed::Unchanged {
            say(&format!("{} {id} ({shown}) is already allowed{scope} until {day} ({} v{}); nothing written", kind.noun(), mine.name, mine.version));
            pairs.push(("version", mine.version.to_string()));
            audit(&ctx.paths, RELAY_ALLOW, &pairs);
            cert_note();
            return Ok(());
        }
        // A put that lost a race landed all the same, so the list may name a certificate nobody got.
        let version = write(&ctx, &op, "allow", mine, &value).map_err(|e| if matches!(cert, WorkerCert::Issued { .. }) { CliError::Aws(format!("{e}; the certificate it issued was not printed: run the command again")) } else { e })?;
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
        let line = format!("allowed {} {id} ({shown}){scope} until {day} ({} v{version}, {count} {}(s)){replaced}; {applies}", kind.noun(), mine.name, kind.noun());
        let any_source = kind == Kind::Worker && globs.iter().any(|g| g == "*");
        if let WorkerCert::Issued { der, old } = &cert {
            // stdout is exactly the certificate (public): every line goes to stderr.
            let new = certs::fingerprint(der);
            note(&old.as_ref().map_or_else(|| line.clone(), |old| format!("{line}; replaced its client certificate fp {old} by fp {new}")));
            note("the certificate on stdout goes to the worker's relay_client_cert file (0640, the worker's group)");
            if any_source {
                note("this worker may register any source name");
            }
            // LD-R61: a tunnel already passed its proof, so a new `tls_fp` closes nothing; a new key does, by itself (R-18).
            if old.is_some() && !matches!(outcome, Allowed::Replaced { old_key: Some(_) }) {
                side_note(&format!("worker {id}: a live tunnel stays up on the old certificate until it next connects (LD-R61): if its keys may be stolen, rotate --key too, or revoke"));
            }
            // The only copy, its serial random, and the list already names it. Never `?`: `From<io::Error>` makes a
            // closed pipe exit 0.
            let mut out = std::io::stdout().lock();
            if let Err(e) = out.write_all(certs::pem("CERTIFICATE", der).as_bytes()).and_then(|()| out.flush()) {
                return Err(CliError::Msg(format!("relay allow: the certificate could not be written to stdout ({e}); {} v{version} already names it: run the command again", mine.name)));
            }
        } else {
            say(&line);
            if any_source {
                say("this worker may register any source name");
            }
            cert_note();
            if !grant_set.is_empty() {
                side_note("a relay before part H refuses this list whole and every token then fails (RO-6): ai-env relay status's relay row must end client certificates required first");
            }
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

// ---- the peers list -----------------------------------------------------------------------------

/// `allow-ip`'s arguments, as clap parsed them.
pub struct AllowIpArgs<'a> {
    pub cidr: Option<&'a str>,
    pub label: Option<&'a str>,
    pub not_after: Option<&'a str>,
    pub wide: bool,
    pub mine: bool,
    pub hours: Option<u32>,
}

impl AllowIpArgs<'_> {
    /// As given (for the gate's refusal).
    fn given(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.extend(self.cidr.map(str::to_string));
        if let Some(label) = self.label {
            args.extend(["--label".to_string(), label.to_string()]);
        }
        if let Some(day) = self.not_after {
            args.extend(["--not-after".to_string(), day.to_string()]);
        }
        if self.wide {
            args.push("--wide".to_string());
        }
        if self.mine {
            args.push("--mine".to_string());
        }
        if let Some(hours) = self.hours {
            args.extend(["--hours".to_string(), hours.to_string()]);
        }
        args
    }
}

/// What `allow-ip` writes, its arguments checked (§RS.4.2).
enum PeerWanted {
    /// `--mine`: the label `mac`, the address asked for after the gate.
    Mine { hours: u32 },
    /// A network, as given, and its label until the end of a day.
    Network { given: String, network: (Ipv4Addr, u8), label: String, until: String },
}

/// One IPv4 address and an optional newline, at most 64 bytes (§RS.4.2).
pub(crate) fn checkip_address(body: &[u8]) -> Option<Ipv4Addr> {
    if body.len() > CHECKIP_BODY_MAX {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    text.strip_suffix('\n').unwrap_or(text).parse().ok()
}

/// An error and its causes on one line: reqwest's own text says only that a request failed.
fn with_causes(e: &(dyn std::error::Error + 'static)) -> String {
    let mut text = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        text.push_str(": ");
        text.push_str(&c.to_string());
        cause = c.source();
    }
    text
}

/// The client and the URL of a loopback checkip, in plain http (`AI_ENV_BRIDGE_LAB_CHECKIP`, debug builds).
#[cfg(debug_assertions)]
fn lab_checkip(addr: std::net::SocketAddr) -> std::result::Result<(reqwest::Client, String), String> {
    note(&format!("LAB KNOB ACTIVE ({}): {CHECKIP_HOST} is {addr} (debug build)", crate::bridge::lab::VM_KNOBS[11]));
    let client = crate::bridge::tls::lab_http_client(addr, CHECKIP_HOST).map_err(|e| e.to_string())?;
    Ok((client, format!("http://{CHECKIP_HOST}:{}/", addr.port())))
}

/// Release builds never read the knob, so nothing asks for this.
#[cfg(not(debug_assertions))]
fn lab_checkip(_addr: std::net::SocketAddr) -> std::result::Result<(reqwest::Client, String), String> {
    Err("no lab knob in a release build".to_string())
}

/// `GET` `url`: the body of a 2xx answer, or `None` for another status or a body over 64 bytes.
async fn checkip_body(client: &reqwest::Client, url: &str) -> std::result::Result<Option<Vec<u8>>, reqwest::Error> {
    let mut answer = client.get(url).send().await?;
    if !answer.status().is_success() {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = answer.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > CHECKIP_BODY_MAX {
            return Ok(None);
        }
    }
    Ok(Some(body))
}

/// This Mac's address as `https://checkip.amazonaws.com/` answers it (§RS.4.2), through the one TLS client (its trust
/// store holds the Amazon roots), within 10 s; anything but one IPv4 address is exit 1.
fn checkip() -> Result<Ipv4Addr> {
    let unreached = |e: String| CliError::Msg(format!("relay allow-ip --mine: {CHECKIP_HOST} could not be reached ({e})"));
    let (client, url) = match crate::bridge::lab::vm_knobs().checkip_addr().map_err(CliError::Msg)? {
        Some(addr) => lab_checkip(addr).map_err(unreached)?,
        None => (crate::bridge::tls::reqwest_client().map_err(|e| unreached(with_causes(&e)))?, format!("https://{CHECKIP_HOST}/")),
    };
    let rt = runtime()?;
    let answered = rt.block_on(async { tokio::time::timeout(CHECKIP_TIMEOUT, checkip_body(&client, &url)).await });
    // A stalled name lookup stays on the blocking pool: dropping the runtime would wait for it, past the 10 s.
    rt.shutdown_background();
    let body = match answered {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => return Err(unreached(with_causes(&e))),
        Err(_) => return Err(unreached(format!("no answer within {} s", CHECKIP_TIMEOUT.as_secs()))),
    };
    body.as_deref().and_then(checkip_address).ok_or_else(|| CliError::Msg(format!("relay allow-ip --mine: {CHECKIP_HOST} answered no IPv4 address")))
}

/// `ai-env relay allow-ip <CIDR> --label <id> [--not-after <YYYY-MM-DD>] [--wide]`, `ai-env relay allow-ip --mine
/// [--hours <N>]` (§RS.4.2): the arguments (exit 2), the gate (exit 9), the context, the address, the operator, then
/// WM-R42's read-modify-write of `/ai-env/relay/peers`, one audit row (never the address) and the lines.
pub fn cmd_allow_ip(args: &AllowIpArgs<'_>) -> Result<()> {
    let usage = |why: String| CliError::Usage(format!("relay allow-ip: {why}"));
    let wanted = if args.mine {
        let hours = args.hours.unwrap_or(MINE_HOURS_DEFAULT);
        if !(1..=MINE_HOURS_MAX).contains(&hours) {
            return Err(usage(format!("--hours {hours}: 1 to {MINE_HOURS_MAX}")));
        }
        PeerWanted::Mine { hours }
    } else {
        let (Some(given), Some(label)) = (args.cidr, args.label) else {
            return Err(usage("a network and --label, or --mine".to_string()));
        };
        let network = network_of(given).ok_or_else(|| usage(format!("{given} is not an IPv4 address or network (a.b.c.d or a.b.c.d/n, n 0 to 32)")))?;
        if network.1 < WIDE_BELOW && !args.wide {
            return Err(usage(format!("{} is wider than /16, which admits much of the internet: pass --wide if that is meant", network_text(network))));
        }
        if !valid_id(label) {
            return Err(usage(format!("--label {label:?} is not an id ({})", ai_env_worker::ai_env_source::names::NAME_RULE)));
        }
        // A label goes into the audit rows, which never hold an address (§RS.4.3).
        if network_of(label).is_some() {
            return Err(usage(format!("--label {label:?} reads as an address: a label says what the network is, and the audit never holds an address")));
        }
        let day = not_after_day(args.not_after, unix_now()).map_err(usage)?;
        let until = policy::not_after_of_day(&day).map_err(|e| usage(format!("--not-after {day}: {e}")))?;
        PeerWanted::Network { given: given.to_string(), network, label: label.to_string(), until }
    };
    gate("allow-ip", &args.given())?;
    let ctx = RelayCtx::load()?;
    // `(<given> is written as <network>)`, when host bits were set; this Mac's address, under --mine.
    let mut written_as = None;
    let mut address = None;
    let entry = match wanted {
        PeerWanted::Mine { hours } => {
            let ip = checkip()?;
            address = Some(ip);
            PeerEntry { cidr: network_text((ip, 32)), label: MAC_LABEL.to_string(), not_after: rfc3339_utc(unix_now() + u64::from(hours) * 3600) }
        }
        PeerWanted::Network { given, network, label, until } => {
            if given.split('/').next() != Some(network.0.to_string().as_str()) {
                written_as = Some(format!("({given} is written as {})", network_text(network)));
            }
            PeerEntry { cidr: network_text(network), label, not_after: until }
        }
    };
    let op = ctx.operator("relay allow-ip")?;
    let network = network_text(entry.network());
    let prefix = entry.network().1;
    let (label, until) = (entry.label.clone(), entry.not_after.clone());
    locked(&ctx, || {
        let held = read("allow-ip", &[PEERS])?.remove(0);
        let mut list = policy::parse_peers(&held.value).map_err(|e| unparsed("allow-ip", held.name, &e))?;
        let edit = upsert_peer(&mut list, entry).map_err(|other| CliError::Policy(format!("relay allow-ip: {network} is already allowed as {other}: one network, one label (ai-env relay revoke-ip --label {other} first)")))?;
        let address_line = || {
            if let Some(ip) = address {
                say(&format!("this Mac's address is {ip} ({CHECKIP_HOST})"));
            }
        };
        let mut pairs = vec![("label", label.clone()), ("prefix", prefix.to_string()), ("outcome", edit.word().to_string()), ("not_after", until.clone())];
        if address.is_some() {
            pairs.push(("mine", "yes".to_string()));
        }
        if edit == PeerEdit::Unchanged {
            pairs.push(("version", held.version.to_string()));
            audit(&ctx.paths, RELAY_ALLOW_IP, &pairs);
            address_line();
            if let Some(written_as) = &written_as {
                say(written_as);
            }
            say(&format!("peer {label} {network} is already allowed until {until} ({} v{}); nothing written", held.name, held.version));
            return Ok(());
        }
        let value = rendered("allow-ip", held.name, &list, policy::render_peers)?;
        let version = write(&ctx, &op, "allow-ip", &held, &value)?;
        pairs.push(("version", version.to_string()));
        audit(&ctx.paths, RELAY_ALLOW_IP, &pairs);
        address_line();
        let moved = match &edit {
            PeerEdit::Replaced { old: Some(old) } => format!("; replaced {old}"),
            _ => String::new(),
        };
        let noted = written_as.as_ref().map_or_else(String::new, |n| format!(" {n}"));
        say(&format!("allowed peer {label} {network} until {until} ({} v{version}, {} peer(s)); the relay applies it within 60 s{noted}{moved}", held.name, list.len()));
        Ok(())
    })
}

/// A note for each entry of `list` in force now that still admits all of `network` (`given`, as the line names it): a
/// `/32` may sit inside another label's `/24` (LD-R40), and whoever cuts an address off must hear it still passes.
fn note_admitted(list: &[PeerEntry], network: (Ipv4Addr, u8), given: &str) {
    let now = unix_now();
    for p in list.iter().filter(|p| p.network().1 <= network.1 && p.contains(network.0) && now <= p.not_after_unix()) {
        side_note(&format!("{given} stays admitted by peer {} {}", p.label, network_text(p.network())));
    }
}

/// `ai-env relay revoke-ip <CIDR>`, `ai-env relay revoke-ip --label <id>` (§RS.4.2): the entry removed; one not listed
/// (a missing list too) writes nothing and exits 0.
pub fn cmd_revoke_ip(cidr: Option<&str>, label: Option<&str>) -> Result<()> {
    let usage = |why: String| CliError::Usage(format!("relay revoke-ip: {why}"));
    let (named, given, args) = match (cidr, label) {
        (Some(given), None) => {
            let network = network_of(given).ok_or_else(|| usage(format!("{given} is not an IPv4 address or network (a.b.c.d or a.b.c.d/n, n 0 to 32)")))?;
            (PeerNamed::Network(network), given, vec![given.to_string()])
        }
        (None, Some(given)) => {
            if !valid_id(given) {
                return Err(usage(format!("--label {given:?} is not an id ({})", ai_env_worker::ai_env_source::names::NAME_RULE)));
            }
            (PeerNamed::Label(given.to_string()), given, vec!["--label".to_string(), given.to_string()])
        }
        _ => return Err(usage("a network or --label, exactly one".to_string())),
    };
    gate("revoke-ip", &args)?;
    let ctx = RelayCtx::load()?;
    let op = ctx.operator("relay revoke-ip")?;
    locked(&ctx, || {
        let held = read("revoke-ip", &[PEERS])?.remove(0);
        let mut list = policy::parse_peers(&held.value).map_err(|e| unparsed("revoke-ip", held.name, &e))?;
        let Some(removed) = remove_peer(&mut list, &named) else {
            say(&format!("{given} is not listed in {}; nothing written", held.name));
            audit(&ctx.paths, RELAY_REVOKE_IP, &[("outcome", "absent".to_string())]);
            if let PeerNamed::Network(network) = named {
                note_admitted(&list, network, given);
            }
            return Ok(());
        };
        let value = rendered("revoke-ip", held.name, &list, policy::render_peers)?;
        let version = write(&ctx, &op, "revoke-ip", &held, &value)?;
        let (network, prefix) = (network_text(removed.network()), removed.network().1);
        let mut pairs = vec![("outcome", "revoked".to_string())];
        // `allow-ip` writes no such label, but a list corrected by hand may hold one: the audit never holds an address.
        if network_of(&removed.label).is_none() {
            pairs.push(("label", removed.label.clone()));
        }
        pairs.extend([("prefix", prefix.to_string()), ("not_after", removed.not_after.clone()), ("version", version.to_string())]);
        audit(&ctx.paths, RELAY_REVOKE_IP, &pairs);
        say(&format!("revoked peer {} {network} ({} v{version}): the relay closes its tunnels within 60 s", removed.label, held.name));
        note_admitted(&list, removed.network(), if matches!(named, PeerNamed::Network(_)) { given } else { &network });
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

// ---- the access list ----------------------------------------------------------------------------

/// `relay access`'s arguments, as clap parsed them.
pub struct AccessArgs<'a> {
    pub session: Option<&'a str>,
    pub allow: Option<&'a str>,
    pub remove: Option<&'a str>,
    pub days: Option<u32>,
    pub list: bool,
    pub json: bool,
    pub from_panel: bool,
}

/// `state/relay-access.json` (R-152): the access list as a command last read it, for the panel alone to show.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccessCache {
    /// The parameter's version (0: absent).
    pub version: u64,
    /// When it was read, RFC 3339 UTC.
    pub at: String,
    pub entries: Vec<AccessEntry>,
}

/// The cache, as `list` at `version` was read just now (0600): a failure is a warning, since it is for display only and
/// the relay remains the gate.
pub(crate) fn write_access_cache(paths: &Paths, version: u64, list: &[AccessEntry]) {
    let cache = AccessCache { version, at: rfc3339_utc(unix_now()), entries: list.to_vec() };
    let target = paths.relay_access_cache();
    let written = serde_json::to_vec_pretty(&cache).map_err(|e| e.to_string()).and_then(|text| {
        let dir = super::cli::state_dir(paths);
        ensure_private_dir(&dir).map_err(|e| format!("cannot prepare {}: {e}", dir.display()))?;
        crate::bridge::infra::write_atomic_mode(&target, &text, 0o600).map_err(|e| e.to_string())
    });
    if let Err(e) = written {
        note(&format!("warning: {} not written: {e}", target.display()));
    }
}

/// The cache, if a command wrote one this build can read.
#[must_use]
pub fn read_access_cache(paths: &Paths) -> Option<AccessCache> {
    serde_json::from_slice(&std::fs::read(paths.relay_access_cache()).ok()?).ok()
}

/// A run that may have changed the list and cannot say (R-152): its write reported failure (its answer lost at the timeout,
/// another writer's version in it) or the panel killed its child, whose `aws` runs on. `pairs` is the audit row, its `outcome`
/// `unknown`; the cache goes, so the panel says `not read yet` until a command reads the list again.
pub(crate) fn access_outcome_unknown(paths: &Paths, pairs: &[(&str, String)]) {
    audit(paths, RELAY_ACCESS, pairs);
    let target = paths.relay_access_cache();
    if let Err(e) = std::fs::remove_file(&target) {
        if e.kind() != std::io::ErrorKind::NotFound {
            note(&format!("warning: {} not removed: {e}", target.display()));
        }
    }
}

/// The access id of session `sid`'s row (R-150): no row is exit 1, a chat on this Mac with nothing to take back or asked for
/// more exit 9, a row with no id (its last start came before this build) exit 1. A row now on this Mac that holds an id can
/// still `--remove`: a later remote `--resume` takes that id. Its `relay` word too.
fn access_target(paths: &Paths, sid: &str, allowing: bool) -> Result<(String, Option<String>)> {
    let Some(row) = registry::read(paths, sid)? else {
        return Err(CliError::Msg(format!("no session {sid}")));
    };
    let id = row.access().map(str::to_string);
    if row.mode != "remote" && (allowing || id.is_none()) {
        return Err(CliError::Policy(format!("relay access: session {sid} runs on this Mac: only a chat on a VM holds a relay session")));
    }
    match id {
        Some(id) => Ok((id, row.relay)),
        None => Err(CliError::Msg(format!("relay access: session {sid} has no access id: it last ran before this ai-env, so reopen the chat first"))),
    }
}

/// `ai-env relay access <SESSION> (--allow G [--days N] | --remove G)`, `ai-env relay access --list [--json]` (R-150). No
/// gate: IAM decides. In this order: the arguments (exit 2); `G` in `[relay].offer`, for `--allow` only (exit 9); the
/// row; the context and the operator, then the lock; one read of `access` and `grants`, with `token-signers` for `--allow`,
/// `G` in `grants` for `--allow` (exit 9); the lapsed entries pruned; the edit, `render_access`, the write with its version
/// check; audit; cache. An edit that changes nothing writes nothing; a write that fails is [`access_outcome_unknown`]. An
/// allow whose grant this Mac's token signer leaves out says so (R-135, R-145): the relay gives the chat nothing through it.
pub fn cmd_access(args: &AccessArgs<'_>) -> Result<()> {
    if args.from_panel {
        crate::bridge::audit::set_actor(crate::bridge::audit::Actor::Panel);
    }
    if args.list {
        return access_list(args.json);
    }
    let usage = |why: String| CliError::Usage(format!("relay access: {why}"));
    let Some(sid) = args.session else {
        return Err(usage("a session and --allow or --remove, or --list".to_string()));
    };
    if !registry::is_uuid(sid) {
        return Err(usage(format!("not a session id: {sid}")));
    }
    let (allowing, grant) = match (args.allow, args.remove) {
        (Some(grant), None) => (true, grant),
        (None, Some(grant)) => (false, grant),
        _ => return Err(usage("--allow or --remove, exactly one".to_string())),
    };
    if !valid_id(grant) {
        return Err(usage(format!("{grant:?} is not an id ({})", ai_env_worker::ai_env_source::names::NAME_RULE)));
    }
    let days = args.days.unwrap_or(ACCESS_DAYS_DEFAULT);
    if !(1..=ACCESS_DAYS_MAX).contains(&days) {
        return Err(usage(format!("--days {days}: 1 to {ACCESS_DAYS_MAX}")));
    }
    let paths = Paths::resolve()?;
    // This Mac's token signer, for an allow: its id.
    let mut signer_id = String::new();
    if allowing {
        let relay = BridgeConfig::load(&paths)?.unwrap_or_default().relay;
        relay.validate()?;
        if !relay.offer.iter().any(|g| g == grant) {
            return Err(CliError::Policy(format!("relay access: grant {grant} is not in [relay].offer of {}: the chats' approvals name only what it offers", paths.config.display())));
        }
        signer_id = relay.worker_id;
    }
    let (access, relay_word) = access_target(&paths, sid, allowing)?;
    let ctx = RelayCtx::load()?;
    let op = ctx.operator("relay access")?;
    locked(&ctx, || {
        let mut lists = read("access", if allowing { &[ACCESS, GRANTS, TOKEN_SIGNERS] } else { &[ACCESS, GRANTS] })?;
        let left_out = allowing && signer_leaves_out(&lists[2].value, &signer_id, grant);
        let left_out_note = || {
            if left_out {
                side_note(&format!("token signer {signer_id}'s grants leave out {grant}: this chat reaches nothing through it"));
            }
        };
        let grants = lists.remove(1);
        let held = lists.remove(0);
        let mut list = policy::parse_access(&held.value).map_err(|e| unparsed("access", held.name, &e))?;
        if allowing {
            let known = policy::parse_grants(&grants.value).map_err(|e| unparsed("access", grants.name, &e))?;
            if !known.iter().any(|g| g.grant_id == grant) {
                return Err(CliError::Policy(format!("relay access: grant {grant} is not in {} v{}, so this chat would reach nothing through it: ai-env as deployer -- ai-env relay grant {grant} '<source-glob>/<op-glob>'", grants.name, grants.version)));
            }
        }
        let now = unix_now();
        let pruned = prune_access(&mut list, now);
        let edit = if allowing {
            let until = policy::not_after_of_day(&access_day(now, days)).map_err(|e| usage(format!("--days {days}: {e}")))?;
            allow_access(&mut list, &access, grant, &until)
        } else {
            remove_access(&mut list, &access, grant)
        };
        let chat = format!("chat {access} (session {sid})");
        let op_word = if allowing { "allow" } else { "remove" };
        let mut pairs = vec![("op", op_word.to_string()), ("outcome", edit.word().to_string()), ("grant", grant.to_string()), ("access", access.clone())];
        let until = list.iter().find(|a| a.chat == access).map(|a| a.not_after.clone());
        if let Some(until) = until.as_ref().filter(|_| allowing) {
            pairs.push(("not_after", until.clone()));
        }
        if matches!(edit, AccessEdit::Unchanged | AccessEdit::Absent) {
            pairs.push(("version", held.version.to_string()));
            audit(&ctx.paths, RELAY_ACCESS, &pairs);
            write_access_cache(&ctx.paths, held.version, &list);
            match until.filter(|_| edit == AccessEdit::Unchanged) {
                Some(until) => say(&format!("{chat} holds grant {grant} until {until} ({} v{}); nothing written", held.name, held.version)),
                None => say(&format!("{chat} does not hold grant {grant} ({} v{}); nothing written", held.name, held.version)),
            }
            left_out_note();
            return Ok(());
        }
        let value = rendered("access", held.name, &list, policy::render_access)?;
        let version = match write(&ctx, &op, "access", &held, &value) {
            Ok(version) => version,
            Err(e) => {
                pairs[1].1 = "unknown".to_string();
                access_outcome_unknown(&ctx.paths, &pairs);
                return Err(e);
            }
        };
        pairs.extend([("version", version.to_string()), ("pruned", pruned.to_string())]);
        audit(&ctx.paths, RELAY_ACCESS, &pairs);
        write_access_cache(&ctx.paths, version, &list);
        let swept = if pruned == 0 { String::new() } else { format!("; {pruned} lapsed chat(s) pruned") };
        match until.filter(|_| allowing) {
            Some(until) => {
                say(&format!("allowed {chat} grant {grant} until {until} ({} v{version}, {} chat(s)){swept}; the relay applies it within about 70 s, with no restart", held.name, list.len()));
                left_out_note();
                let others: Vec<&str> = list.iter().find(|a| a.chat == access).map_or_else(Vec::new, |a| a.grants.iter().map(String::as_str).filter(|g| *g != grant).collect());
                if !others.is_empty() {
                    side_note(&format!("chat {access}'s entry holds {} too: one end, {until}, covers them all", others.join(",")));
                }
                match relay_word.as_deref() {
                    None | Some("minted") => {}
                    Some("off") => side_note(&format!("session {sid}'s latest spawn holds no session token (relay=off): [relay].grant or its workspace's relay_grant names none, so the chat reaches this grant from the first spawn after one does")),
                    Some(word) => side_note(&format!("session {sid}'s latest spawn holds no session token (relay={word}): the chat reaches this grant from its next spawn (ai-env session migrate {sid})")),
                }
            }
            None => say(&format!("removed grant {grant} from {chat} ({} v{version}, {} chat(s)){swept}; the relay refuses it within about 70 s, and calls in flight finish", held.name, list.len())),
        }
        Ok(())
    })
}

/// Whether `signer_id`'s entry in the token signers' `value` holds `grants` none of which matches `grant`: the relay's
/// filter then takes that grant from every chat this Mac's tokens name (R-135, R-145). A list that does not parse or an
/// entry with no `grants` says nothing: this only explains, and the relay remains the gate.
fn signer_leaves_out(value: &str, signer_id: &str, grant: &str) -> bool {
    let entries = policy::parse_signers(value).unwrap_or_default();
    let globs = entries.iter().find(|s| s.signer_id == signer_id).and_then(|s| s.grants.as_ref());
    globs.is_some_and(|globs| !globs.iter().any(|glob| glob_match(glob, grant)))
}

/// `relay access --list [--json]`: the list as one read finds it, each chat with the sessions on this Mac whose row
/// holds it (a `/clear`'s rows share an id); the cache written.
fn access_list(json: bool) -> Result<()> {
    let ctx = RelayCtx::load()?;
    ctx.operator("relay access")?;
    let held = read("access", &[ACCESS])?.remove(0);
    let list = policy::parse_access(&held.value).map_err(|e| unparsed("access", held.name, &e))?;
    write_access_cache(&ctx.paths, held.version, &list);
    let rows = registry::list(&ctx.paths).unwrap_or_default();
    let sessions = |chat: &str| -> Vec<String> { rows.iter().filter(|r| r.access_id.as_deref() == Some(chat)).map(|r| r.session_id.clone()).collect() };
    let now = unix_now();
    if json {
        let entries: Vec<Value> = list.iter().map(|a| serde_json::json!({"chat": a.chat, "grants": a.grants, "not_after": a.not_after, "expired": now > a.not_after_unix(), "sessions": sessions(&a.chat)})).collect();
        let doc = serde_json::json!({"version": held.version, "entries": entries});
        say(&serde_json::to_string_pretty(&doc).unwrap_or_default());
        return Ok(());
    }
    if !held.exists {
        say(&format!("{ACCESS}: absent: no chat has more than its token's grant"));
        return Ok(());
    }
    let in_force = list.iter().filter(|a| now <= a.not_after_unix()).count();
    say(&format!("{ACCESS} v{}: {} chat(s), {in_force} in force", held.version, list.len()));
    for a in &list {
        let lapsed = if now > a.not_after_unix() { " EXPIRED" } else { "" };
        let shown = sessions(&a.chat);
        let on = if shown.is_empty() { "no session on this Mac".to_string() } else { format!("session {}", shown.join(",")) };
        say(&format!("  chat {} grants {} until {}{lapsed}: {on}", a.chat, a.grants.join(","), a.not_after));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::identity::{declared_operator, Marker};

    fn key(seed: u8) -> PublicKey {
        ai_env_worker::keys::SigningKey::from_seed(&[seed; 32]).unwrap().public_key()
    }

    fn worker(id: &str, seed: u8, sources: &[&str]) -> WorkerEntry {
        WorkerEntry { worker_id: id.into(), alg: "ed25519".into(), public_key: key(seed).b64(), sources: sources.iter().map(|s| (*s).to_string()).collect(), not_after: "2027-10-29T23:59:59Z".into(), tls_fp: None }
    }

    fn signer(id: &str, seed: u8) -> SignerEntry {
        SignerEntry { signer_id: id.into(), alg: "ed25519".into(), public_key: key(seed).b64(), not_after: "2027-10-29T23:59:59Z".into(), grants: None }
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
        // R-134: a signer's grants are part of its entry: another set, the same key, is a replacement.
        let bound = SignerEntry { grants: Some(s(&["g-a"])), ..signer("mac", 7) };
        assert_eq!(upsert(&mut signers, bound.clone()), Ok(Allowed::Replaced { old_key: None }));
        assert_eq!(upsert(&mut signers, bound), Ok(Allowed::Unchanged));
        assert_eq!(upsert(&mut signers, signer("mac", 7)), Ok(Allowed::Replaced { old_key: None }));
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

    fn peer(cidr: &str, label: &str, not_after: &str) -> PeerEntry {
        PeerEntry { cidr: cidr.into(), label: label.into(), not_after: not_after.into() }
    }

    /// §RS.4.2's pure edits of the peers list. `<CIDR>`: an address reads as `/32`, host bits are cleared, and R-86's
    /// refusals hold (WM-T51's grammar, through `render_peers`). An upsert is by label: added, replaced (naming the old
    /// network when it moved), unchanged for the same network and time; a network another label holds is refused,
    /// host bits or not, and a `/32` inside another label's `/24` is a new network (LD-R40). A removal by network or by
    /// label returns the entry; one not listed returns none.
    #[test]
    fn peer_edits_upsert_by_label_and_remove_by_network_or_label() {
        const T1: &str = "2027-10-29T23:59:59Z";
        const T2: &str = "2027-10-30T23:59:59Z";
        let net = |a: &str, n: u8| (a.parse::<Ipv4Addr>().unwrap(), n);
        assert_eq!(network_of("198.51.100.7"), Some(net("198.51.100.7", 32)));
        assert_eq!(network_of("198.51.100.7/24"), Some(net("198.51.100.0", 24)));
        assert_eq!(network_of("0.0.0.0/0"), Some(net("0.0.0.0", 0)));
        assert_eq!(network_of("203.0.113.9/0"), Some(net("0.0.0.0", 0)));
        for bad in ["", "/", "198.51.100.0/33", "198.51.100.0/", "198.51.100/24", "198.051.100.0/24", "198.51.100.0/08", "198.51.100.0/-1", "2001:db8::/32", "2001:db8::1", "example.invalid", "198.51.100.0/24/8", " 198.51.100.0/24"] {
            assert_eq!(network_of(bad), None, "{bad:?}");
        }
        let mut list = Vec::new();
        assert_eq!(upsert_peer(&mut list, peer("198.51.100.0/24", "office", T1)), Ok(PeerEdit::Added));
        assert_eq!(upsert_peer(&mut list, peer("198.51.100.0/24", "office", T1)), Ok(PeerEdit::Unchanged));
        assert_eq!(upsert_peer(&mut list, peer("198.51.100.0/24", "office", T2)), Ok(PeerEdit::Replaced { old: None }), "a new time, the same network");
        assert_eq!(upsert_peer(&mut list, peer("203.0.113.0/24", "office", T2)), Ok(PeerEdit::Replaced { old: Some("198.51.100.0/24".to_string()) }), "it moved");
        assert_eq!(list, [peer("203.0.113.0/24", "office", T2)]);
        assert_eq!(upsert_peer(&mut list, peer("203.0.113.0/24", "lab", T1)), Err("office".to_string()), "one network, one label");
        assert_eq!(upsert_peer(&mut list, peer("203.0.113.9/24", "lab", T1)), Err("office".to_string()), "the network, not its text");
        assert_eq!(list.len(), 1, "nothing changed by the refusal");
        assert_eq!(upsert_peer(&mut list, peer("203.0.113.9/32", "lab", T1)), Ok(PeerEdit::Added), "a /32 inside another label's /24 is its own network (LD-R40)");
        assert_eq!(policy::render_peers(&list).map(|t| policy::parse_peers(&t).map(|p| p.len())), Ok(Ok(2)), "and the list renders");
        assert_eq!(remove_peer(&mut list, &PeerNamed::Network(net("198.51.100.0", 24))), None);
        assert_eq!(remove_peer(&mut list, &PeerNamed::Label("nobody".to_string())), None);
        assert_eq!(remove_peer(&mut list, &PeerNamed::Network(net("203.0.113.9", 32))), Some(peer("203.0.113.9/32", "lab", T1)));
        assert_eq!(remove_peer(&mut list, &PeerNamed::Label("office".to_string())), Some(peer("203.0.113.0/24", "office", T2)));
        assert!(list.is_empty());
    }

    /// R-150's pure edits of the access list. An allow makes an entry, or joins one, its grants sorted, and its end is the
    /// later of the old and the new; the same grant to the same end changes nothing. A removal takes one grant, and an entry
    /// left empty goes. A prune takes what lapsed before `now` and leaves an entry whose last second it is.
    #[test]
    fn access_edits_allow_remove_and_prune() {
        const CHAT: &str = "0199a1b2-0000-7000-8000-0000000012a1";
        const OTHER: &str = "0199a1b2-0000-7000-8000-0000000012a2";
        const T1: &str = "2027-10-29T23:59:59Z";
        const T2: &str = "2027-11-29T23:59:59Z";
        let entry = |chat: &str, grants: &[&str], not_after: &str| AccessEntry { chat: chat.into(), grants: s(grants), not_after: not_after.into() };
        let mut list = Vec::new();
        assert_eq!(allow_access(&mut list, CHAT, "g-b", T1), AccessEdit::Added);
        assert_eq!(list, [entry(CHAT, &["g-b"], T1)]);
        assert_eq!(allow_access(&mut list, CHAT, "g-b", T1), AccessEdit::Unchanged);
        assert_eq!(allow_access(&mut list, CHAT, "g-b", T2), AccessEdit::Extended);
        assert_eq!(list, [entry(CHAT, &["g-b"], T2)], "the later end");
        assert_eq!(allow_access(&mut list, CHAT, "g-b", T1), AccessEdit::Unchanged, "never earlier");
        assert_eq!(allow_access(&mut list, CHAT, "g-a", T1), AccessEdit::Added);
        assert_eq!(list, [entry(CHAT, &["g-a", "g-b"], T2)], "joined, sorted, and an entry's end stays the later");
        assert_eq!(allow_access(&mut list, OTHER, "g-a", T1), AccessEdit::Added);
        assert_eq!(remove_access(&mut list, OTHER, "g-b"), AccessEdit::Absent, "another chat's grant");
        assert_eq!(remove_access(&mut list, CHAT, "g-c"), AccessEdit::Absent);
        assert_eq!(remove_access(&mut list, CHAT, "g-b"), AccessEdit::Removed);
        assert_eq!(list, [entry(CHAT, &["g-a"], T2), entry(OTHER, &["g-a"], T1)]);
        assert_eq!(remove_access(&mut list, CHAT, "g-a"), AccessEdit::Removed);
        assert_eq!(list, [entry(OTHER, &["g-a"], T1)], "an entry left empty goes");
        let t1 = policy::unix_of(T1).unwrap();
        assert_eq!(prune_access(&mut list, t1), 0, "its last second");
        assert_eq!(prune_access(&mut list, t1 + 1), 1);
        assert!(list.is_empty());
    }

    /// §RS.4.2: checkip's body is one IPv4 address and an optional newline, at most 64 bytes.
    #[test]
    fn checkip_answers_one_ipv4_address() {
        let ip: Ipv4Addr = "203.0.113.7".parse().unwrap();
        assert_eq!(checkip_address(b"203.0.113.7"), Some(ip));
        assert_eq!(checkip_address(b"203.0.113.7\n"), Some(ip));
        for bad in [&b""[..], b"\n", b"203.0.113.7\n\n", b"203.0.113.7\r\n", b" 203.0.113.7", b"203.0.113.7 ", b"203.0.113.7\n198.51.100.1\n", b"2001:db8::1\n", b"203.0.113.07\n", b"<html></html>\n", b"\xff\xfe"] {
            assert_eq!(checkip_address(bad), None, "{bad:?}");
        }
        let mut long = b"203.0.113.7".to_vec();
        long.resize(65, b'\n');
        assert_eq!(checkip_address(&long), None, "over 64 bytes");
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
