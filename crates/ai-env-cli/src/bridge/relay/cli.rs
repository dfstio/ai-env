//! `ai-env relay …` (S13, plans/s13-contracts.md §WM-worker-mac.6): the dispatch, and what the AWS-facing
//! commands share. [`RelayCtx`] is `egress::cli::Ctx`'s twin (WM-R41): `bridge.toml` with the S5 keys valid and
//! `[aws].egress_connector_arn` set (the operator's account is the connector's), and `state/infra.toml` (the
//! relay's instance and addresses, written by `make infra-status WRITE=1`), never Pulumi. Every AWS call is the
//! aws CLI as the operator (`bridge::awscli`, region and endpoint pinned), never the runtime key.
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::awscli::require_operator_account;
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::identity::{self, labelled, Operator};
use crate::bridge::infra::{read_infra_state, InfraState};
use crate::cli::{RelayCmd, RelayTlsCmd};
use crate::errors::{CliError, Result};
use crate::store::Keystore;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

/// What a missing stack record names.
pub(crate) const HINT: &str = "make infra-status WRITE=1";

/// `ai-env relay …`.
pub fn main(store: &Keystore, cmd: RelayCmd) -> Result<()> {
    match cmd {
        RelayCmd::Keygen { force } => super::keys::cmd_keygen(store, force),
        RelayCmd::Pubkey { worker, session, verify } => super::keys::cmd_pubkey(store, worker, session, verify),
        RelayCmd::Allow { id, key, sources, token_signer, not_after } => super::params::cmd_allow(&id, &key, &sources, token_signer, not_after.as_deref()),
        RelayCmd::Revoke { id, token_signer } => super::params::cmd_revoke(&id, token_signer),
        RelayCmd::Grant { grant_id, rules, remove } => super::params::cmd_grant(&grant_id, &rules, remove),
        RelayCmd::Status { json, local } => super::ops::cmd_status(json, local),
        RelayCmd::Start => super::ops::cmd_start(),
        RelayCmd::Stop => super::ops::cmd_stop(),
        RelayCmd::Agent { hours } => super::agent::cmd_agent(store, hours),
        RelayCmd::Tls { cmd: RelayTlsCmd::Init { force } } => super::tls::cmd_tls_init(store, force),
        RelayCmd::Tls { cmd: RelayTlsCmd::Rotate } => super::tls::cmd_tls_rotate(store),
        RelayCmd::Ca { der } => super::tls::cmd_ca(der),
    }
}

/// What an operator command of the relay works from (WM-R41).
pub(crate) struct RelayCtx {
    pub(crate) paths: Paths,
    pub(crate) state: InfraState,
    /// `[aws].egress_connector_arn`: the operator's account is its account.
    connector: String,
    /// `AI_ENV_BRIDGE_LAB_BACKOFF_MS` (debug builds): polls in milliseconds.
    pub(crate) backoff_ms: Option<u64>,
}

impl RelayCtx {
    /// `bridge.toml` (must exist; the S5 keys valid; the connector set) and `state/infra.toml` (must exist):
    /// exit 1 naming [`HINT`] otherwise. No AWS call, no Touch ID.
    pub(crate) fn load() -> Result<RelayCtx> {
        let paths = Paths::resolve()?;
        let cfg = BridgeConfig::load(&paths)?.ok_or_else(|| CliError::Msg(format!("{} not found: {HINT} (it writes [aws])", paths.config.display())))?;
        cfg.aws.validate_egress()?;
        let connector = cfg.aws.egress_connector_arn.as_deref().map(str::trim).filter(|a| !a.is_empty()).map(str::to_string);
        let connector = connector.ok_or_else(|| CliError::Msg(format!("[aws].egress_connector_arn is not set in {}: {HINT} (the operator's account is the connector's)", paths.config.display())))?;
        let state = read_infra_state(&paths)?.ok_or_else(|| CliError::Msg(format!("{} not found: {HINT} (ai-env relay reads the relay's ids from it, never from Pulumi)", paths.infra_state().display())))?;
        let backoff_ms = crate::bridge::lab::vm_knobs().backoff_ms;
        if backoff_ms.is_some() {
            note("LAB KNOB ACTIVE (AI_ENV_BRIDGE_LAB_BACKOFF_MS): polls scaled to milliseconds (debug build)");
        }
        Ok(RelayCtx { paths, state, connector, backoff_ms })
    }

    /// The operator identity (the runner's key, else `credentials/ops.env` and its one Touch ID, else exit 5),
    /// then its account check before any other aws call: the identity's refusals keep their class, another
    /// account is exit 1; each labelled `what`.
    pub(crate) fn operator(&self, what: &str) -> Result<Arc<Operator>> {
        let op = identity::operator().map_err(|e| labelled(what, e))?;
        require_operator_account(&self.connector).map_err(|e| labelled(what, e))?;
        Ok(op)
    }

    /// `relay_instance_id` of `state/infra.toml`, an `i-…` id (WM-R49): exit 1 naming [`HINT`] otherwise.
    pub(crate) fn instance(&self) -> Result<String> {
        let id = self.state.relay_instance_id.as_deref().map(str::trim).filter(|v| !v.is_empty());
        let id = id.ok_or_else(|| CliError::Msg(format!("state/infra.toml has no relay_instance_id: run {HINT} after deploying the relay")))?;
        if !is_instance_id(id) {
            return Err(CliError::Msg(format!("state/infra.toml relay_instance_id = {id:?} is not an i-… id: run {HINT}")));
        }
        Ok(id.to_string())
    }

    /// The bridge's private `state/` directory (a put-parameter's 0600 temp file goes there).
    pub(crate) fn state_dir(&self) -> PathBuf {
        state_dir(&self.paths)
    }
}

/// `<root>/state`.
pub(crate) fn state_dir(paths: &Paths) -> PathBuf {
    paths.root.join("state")
}

/// `i-` and 8 or 17 lowercase hex digits (never anything the aws CLI could read as an option).
pub(crate) fn is_instance_id(s: &str) -> bool {
    s.strip_prefix("i-").is_some_and(|h| matches!(h.len(), 8 | 17) && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}

/// One `ai-env: …` line on stderr (never a panic on a closed pipe).
pub(crate) fn note(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "ai-env: {line}");
}

/// One line on stdout, best effort: a closed pipe never ends a command early, so what it writes and audits
/// after the line still happens and its exit code still says what happened.
pub(crate) fn say(line: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

/// One audit row (its actor `AuditRow::new`'s); a failure to write is a warning (what it records already
/// happened). Ids, words, numbers and fingerprints only (WM-R57).
pub(crate) fn audit(paths: &Paths, event: &str, pairs: &[(&str, String)]) {
    if let Err(e) = audit::append(&paths.audit(), &AuditRow::new(event, None, audit::detail(pairs))) {
        note(&format!("warning: audit row {event} not written: {e}"));
    }
}

/// A runtime for one command's async calls (the agent's socket, the lock's wait).
pub(crate) fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| CliError::Msg(format!("cannot start the async runtime: {e}")))
}

/// `arg` as a shell word: as it is when it is plain, else in single quotes (a glob's `*` included), so the
/// command a refusal names runs as written.
pub(crate) fn shell_word(arg: &str) -> String {
    if !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:/=,+@-".contains(&b)) {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_ids_and_shell_words() {
        assert!(is_instance_id("i-0123456789abcdef0") && is_instance_id("i-01234567"));
        for bad in ["", "i-", "i-0123456789ABCDEF0", "-i-0123", "i-012345678", "x-0123456789abcdef0"] {
            assert!(!is_instance_id(bad), "{bad:?}");
        }
        assert_eq!(shell_word("worker-a"), "worker-a");
        assert_eq!(shell_word("ed25519:abc+/="), "ed25519:abc+/=");
        assert_eq!(shell_word("example-*"), "'example-*'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word(""), "''");
    }
}
