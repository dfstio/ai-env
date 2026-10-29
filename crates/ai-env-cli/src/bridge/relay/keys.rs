//! This Mac's two relay keys (S13, WM-R36, WM-R37, LD-WM1): its worker key, which signs a worker's handshake
//! when a worker runs on this Mac, and its session key, which signs the VM session tokens; both Ed25519, in one
//! container, `credentials/relay-worker.env`, so one unseal (one Touch ID) serves `ai-env relay agent`.
//!
//! `ai-env relay keygen` makes them and seals them with no Touch ID (sealing is public-key only); the
//! container's notes (`container::meta`: unauthenticated, read without a Touch ID) record the worker id and both
//! public keys, which `ai-env relay pubkey` prints. [`unseal`] (`pubkey --verify`, the agent) opens the
//! container once and checks the keys against the notes. No private key reaches an argument list, the
//! environment, a log, an audit row or stdout (WM-R54): the plaintext lives in zeroizing memory, the keys in
//! aws-lc-rs.
use super::cli::{audit, note, runtime, say};
use crate::age_cmd::AgeTool;
use crate::bridge::audit::event::RELAY_KEYGEN;
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::creds::{aws_env_state, key_name, seal_file, AwsEnvState};
use crate::bridge::registry::read_regular_file;
use crate::bridge::unseal::UnsealJob;
use crate::bridge::voice;
use crate::errors::{CliError, Result};
use crate::store::{validate_key_name, Keystore};
use crate::wire::time::{parse_rfc3339_utc, rfc3339_utc, unix_now};
use ai_env_worker::keys::{PublicKey, SigningKey};
use base64::Engine as _;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The worker key's variable in the container's plaintext.
pub const WORKER_KEY_VAR: &str = "AI_ENV_RELAY_WORKER_KEY";
/// The session key's variable in the container's plaintext.
pub const SESSION_KEY_VAR: &str = "AI_ENV_RELAY_SESSION_KEY";
/// The notes' `kind`.
const KIND: &str = "relay-keys";
/// The container, as messages name it.
const FILE: &str = "credentials/relay-worker.env";
/// What re-seals a container that holds something else.
const RESEAL: &str = "re-seal it with ai-env relay keygen --force";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// This Mac's keys, unsealed ([`unseal`]): in aws-lc-rs only, never printed.
pub struct MacKeys {
    pub worker_id: String,
    pub worker: SigningKey,
    pub session: SigningKey,
}

impl std::fmt::Debug for MacKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MacKeys(worker {}, worker key fp {}, session key fp {})", self.worker_id, self.worker.public_key().fingerprint(), self.session.public_key().fingerprint())
    }
}

/// What the container's notes record, read with no Touch ID ([`read_notes`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacKeyNotes {
    pub worker_id: String,
    pub worker_key: PublicKey,
    pub session_key: PublicKey,
    /// Unix seconds.
    pub sealed_at: Option<u64>,
}

impl MacKeyNotes {
    /// `YYYY-MM-DD` of [`MacKeyNotes::sealed_at`], UTC.
    #[must_use]
    pub fn sealed_day(&self) -> Option<String> {
        self.sealed_at.map(|t| rfc3339_utc(t)[..10].to_string())
    }
}

/// `worker  <id>  ed25519:<b64>  fp <fp>` and `session <id>  …`: the two lines keygen and pubkey print.
fn key_lines(id: &str, worker: &PublicKey, session: &PublicKey) -> [String; 2] {
    [format!("worker  {id}  {}  fp {}", worker.text(), worker.fingerprint()), format!("session {id}  {}  fp {}", session.text(), session.fingerprint())]
}

/// `[relay]` of `bridge.toml` (its defaults without a file), validated (WM-R46).
pub(crate) fn relay_cfg(paths: &Paths) -> Result<crate::bridge::config::RelayCfg> {
    let cfg = BridgeConfig::load(paths)?.unwrap_or_default();
    cfg.relay.validate()?;
    Ok(cfg.relay)
}

/// `ai-env relay keygen [--force]` (WM-R36): no AWS call, no Touch ID. `--force` is also `creds::seal_file`'s, as
/// in every creds command: it accepts a `[creds].key` with no recovery recipient (plans/s13-contracts.md §Q.7).
pub fn cmd_keygen(store: &Keystore, force: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let relay = relay_cfg(&paths)?;
    let id = relay.worker_id;
    let target = paths.relay_worker_env();
    if !force && matches!(aws_env_state(&target), AwsEnvState::Sealed) {
        let held = match read_notes(&paths) {
            Ok(n) => format!(" (worker {}, worker key fp {}, session key fp {})", n.worker_id, n.worker_key.fingerprint(), n.session_key.fingerprint()),
            Err(_) => String::new(),
        };
        return Err(CliError::Msg(format!("{FILE} already holds this Mac's relay keys{held}: ai-env relay keygen --force replaces them; then allow the new keys and revoke the old")));
    }
    let fault = |e: ai_env_worker::keys::KeyError| CliError::Msg(format!("relay keygen: {e}"));
    let (worker, session) = (SigningKey::generate().map_err(fault)?, SigningKey::generate().map_err(fault)?);
    let worker_b64 = Zeroizing::new(B64.encode(worker.to_pkcs8_der().map_err(fault)?.as_slice()));
    let session_b64 = Zeroizing::new(B64.encode(session.to_pkcs8_der().map_err(fault)?.as_slice()));
    let plaintext = Zeroizing::new(format!("{WORKER_KEY_VAR}={}\n{SESSION_KEY_VAR}={}\n", worker_b64.as_str(), session_b64.as_str()));
    let (wk, sk) = (worker.public_key(), session.public_key());
    let (wk_text, sk_text, sealed) = (wk.text(), sk.text(), rfc3339_utc(unix_now()));
    let notes = [("kind", KIND), ("worker_id", id.as_str()), ("worker_key", wk_text.as_str()), ("session_key", sk_text.as_str()), ("sealed", sealed.as_str())];
    let key = key_name(&paths)?;
    let done = seal_file(store, &paths, &key, &target, plaintext.as_bytes(), &[worker_b64.as_bytes(), session_b64.as_bytes()], &notes, force)?;
    drop((plaintext, worker_b64, session_b64, worker, session));
    for line in key_lines(&id, &wk, &sk) {
        say(&line);
    }
    say("allow the session key as a token signer, so the relay takes this Mac's VM session tokens:");
    say(&format!("  ai-env as deployer -- ai-env relay allow {id} --token-signer --key {}", sk.text()));
    say("and, for a Mac that serves sources (a worker under ai-env relay agent), its worker key:");
    say(&format!("  ai-env as deployer -- ai-env relay allow {id} --key {} --sources '<glob>'", wk.text()));
    if let Some(bak) = &done.backup {
        note(&format!("the old container is kept as {}: revoke the old keys once the new ones are allowed", bak.display()));
    }
    if let Some(pid) = running_agent(&paths) {
        note(&format!("a running relay agent (pid {pid}) keeps the old keys until it restarts: stop it and run ai-env relay agent again"));
    }
    let mut pairs = vec![("worker_id", id.clone()), ("worker_fp", wk.fingerprint()), ("session_fp", sk.fingerprint())];
    if done.backup.is_some() {
        pairs.push(("replaced", "true".to_string()));
    }
    audit(&paths, RELAY_KEYGEN, &pairs);
    Ok(())
}

/// The pid of the agent answering `status` on this Mac's socket within a second, if one does.
fn running_agent(paths: &Paths) -> Option<u32> {
    let socket = paths.relay_agent_socket();
    if !socket.exists() {
        return None;
    }
    let rt = runtime().ok()?;
    match rt.block_on(ai_env_worker::agent::request(&socket, &ai_env_worker::agent::Request::Status, std::time::Duration::from_secs(1))) {
        Ok(ai_env_worker::agent::Response::Status(s)) => Some(s.pid),
        _ => None,
    }
}

/// `ai-env relay pubkey [--worker | --session] [--verify]` (WM-R37): the notes, with no Touch ID; with
/// `--verify`, one unseal that checks them against the sealed keys.
pub fn cmd_pubkey(store: &Keystore, worker: bool, session: bool, verify: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    relay_cfg(&paths)?;
    let notes = read_notes(&paths)?;
    if verify {
        let keys = unseal(store, &paths)?;
        drop(keys);
    }
    if worker {
        say(&notes.worker_key.text());
    } else if session {
        say(&notes.session_key.text());
    } else {
        for line in key_lines(&notes.worker_id, &notes.worker_key, &notes.session_key) {
            say(&line);
        }
    }
    if verify {
        note(&format!("{FILE}: the sealed keys match their notes (worker {})", notes.worker_id));
    }
    Ok(())
}

/// The notes of `credentials/relay-worker.env` (no Touch ID): absent is exit 5 naming `ai-env relay keygen`,
/// a file that is no container exit 5 with [`aws_env_state`]'s phrase, notes that are not a relay-keys
/// container's exit 5 naming the re-seal.
pub fn read_notes(paths: &Paths) -> Result<MacKeyNotes> {
    let path = paths.relay_worker_env();
    match aws_env_state(&path) {
        AwsEnvState::Sealed => {}
        AwsEnvState::Absent => return Err(CliError::AuthUnavailable(format!("{FILE} does not exist: make this Mac's relay keys with ai-env relay keygen"))),
        AwsEnvState::NotSealed(why) => return Err(CliError::AuthUnavailable(format!("{} {why}: move it away, then ai-env relay keygen", path.display()))),
    }
    let text = read_regular_file(&path)?.ok_or_else(|| CliError::AuthUnavailable(format!("{FILE} vanished while it was read: ai-env relay keygen")))?;
    let meta = crate::container::meta(&text);
    let bad = |what: &str| CliError::AuthUnavailable(format!("{FILE}'s notes lack {what}: {RESEAL}"));
    if meta.get("kind").map(String::as_str) != Some(KIND) {
        return Err(bad("kind=relay-keys"));
    }
    let worker_id = meta.get("worker_id").filter(|id| ai_env_worker::globs::valid_id(id)).cloned().ok_or_else(|| bad("a worker_id"))?;
    let key = |name: &str| meta.get(name).and_then(|t| PublicKey::parse_text(t).ok()).ok_or_else(|| bad(name));
    Ok(MacKeyNotes { worker_id, worker_key: key("worker_key")?, session_key: key("session_key")?, sealed_at: meta.get("sealed").and_then(|s| parse_rfc3339_utc(s)) })
}

/// The two keys of `plain`, exactly `AI_ENV_RELAY_WORKER_KEY=<b64>\nAI_ENV_RELAY_SESSION_KEY=<b64>\n` (each the
/// standard base64 of a PKCS#8 DER), else exit 5 naming the re-seal; never a value in the message.
fn parse_plaintext(plain: &[u8]) -> Result<(SigningKey, SigningKey)> {
    let other = || CliError::AuthUnavailable(format!("{FILE} holds something else: {RESEAL}"));
    let text = std::str::from_utf8(plain).map_err(|_| other())?;
    let body = text.strip_suffix('\n').ok_or_else(other)?;
    let (first, second) = body.split_once('\n').ok_or_else(other)?;
    let value = |line: &str, var: &str| -> Result<SigningKey> {
        let b64 = line.strip_prefix(var).and_then(|l| l.strip_prefix('=')).ok_or_else(other)?;
        let der = Zeroizing::new(B64.decode(b64).map_err(|_| other())?);
        SigningKey::from_pkcs8_der(&der).map_err(|_| other())
    };
    Ok((value(first, WORKER_KEY_VAR)?, value(second, SESSION_KEY_VAR)?))
}

/// One unseal of `credentials/relay-worker.env` (one Touch ID, `[creds].unseal_timeout_s`; a dismissed dialog
/// exit 3, the deadline exit 5): the plaintext must be exactly the two variables (else exit 5), and its keys
/// must be the ones the notes record (else exit 9: the container was tampered with or mixed up).
pub fn unseal(store: &Keystore, paths: &Paths) -> Result<MacKeys> {
    let notes = read_notes(paths)?;
    let path = paths.relay_worker_env();
    let cfg = BridgeConfig::load(paths)?.unwrap_or_default();
    validate_key_name(&cfg.creds.key).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    let text = read_regular_file(&path)?.ok_or_else(|| CliError::AuthUnavailable(format!("{FILE} vanished while it was read: ai-env relay keygen")))?;
    let cont = crate::container::read(&text)?;
    let name = crate::select::resolve_for_decrypt(store, Some(cfg.creds.key.as_str()), &cont)?;
    let age = Arc::new(AgeTool::probe()?);
    let plain = UnsealJob::start(age, store.identity_path(&name), cont.data, cfg.creds.unseal_budget(), format!("this Mac's relay keys ({FILE})"))
        .with_prefix(voice::prefix())
        .wait(crate::bridge::signals::say)?;
    let (worker, session) = parse_plaintext(&plain)?;
    drop(plain);
    if worker.public_key() != notes.worker_key || session.public_key() != notes.session_key {
        return Err(CliError::Policy(format!("the notes of {FILE} do not match its sealed keys: {RESEAL}")));
    }
    Ok(MacKeys { worker_id: notes.worker_id, worker, session })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_b64(seed: u8) -> String {
        B64.encode(SigningKey::from_seed(&[seed; 32]).unwrap().to_pkcs8_der().unwrap().as_slice())
    }

    /// The plaintext is exactly the two variables, in their order, each a PKCS#8 key; anything else is exit 5
    /// and its message holds no value.
    #[test]
    fn the_plaintext_is_exactly_the_two_keys() {
        let (w, s) = (der_b64(1), der_b64(7));
        let good = format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n");
        let (worker, session) = parse_plaintext(good.as_bytes()).unwrap();
        assert_eq!((worker.public_key(), session.public_key()), (SigningKey::from_seed(&[1; 32]).unwrap().public_key(), SigningKey::from_seed(&[7; 32]).unwrap().public_key()));
        for bad in [
            format!("{SESSION_KEY_VAR}={s}\n{WORKER_KEY_VAR}={w}\n"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\nEXTRA=1\n"),
            format!("{WORKER_KEY_VAR}={w}\n"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}=not-base64\n"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={}\n", B64.encode(b"not a key")),
            String::new(),
        ] {
            let e = parse_plaintext(bad.as_bytes()).err().unwrap_or_else(|| panic!("{bad:?} parsed"));
            assert_eq!(e.exit_code(), 5, "{bad:?}");
            assert!(e.to_string().contains("holds something else: re-seal it with ai-env relay keygen --force") && !e.to_string().contains(&w), "{e}");
        }
    }
}
