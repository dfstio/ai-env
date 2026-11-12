//! This Mac's relay keys (S13, WM-R36, WM-R37, LD-WM1; R-155): its worker key, which signs a worker's handshake
//! when a worker runs on this Mac, its session key, which signs the VM session tokens as `[relay].worker_id`, and,
//! once `ai-env relay keygen --sole` adds it, its sole key, which signs them as `<worker_id>-sole` for a chat on a VM
//! placed for it alone (the one token signer bound to `[relay].restricted`); all Ed25519, in one container,
//! `credentials/relay-worker.env`, so one unseal (one Touch ID) serves `ai-env relay agent`.
//!
//! `ai-env relay keygen` makes them and seals them with no Touch ID (sealing is public-key only); `--sole` adds the
//! third key to a container of two with one unseal. The container's notes (`container::meta`: unauthenticated, read
//! without a Touch ID) record the worker id and the public keys, which `ai-env relay pubkey` prints. [`unseal`]
//! (`pubkey --verify`, the agent) opens the container once and checks the keys against the notes. No private key
//! reaches an argument list, the environment, a log, an audit row or stdout (WM-R54): the plaintext lives in
//! zeroizing memory, the keys in aws-lc-rs.
use super::cli::{audit, note, runtime, say};
use crate::age_cmd::AgeTool;
use crate::bridge::audit::event::RELAY_KEYGEN;
use crate::bridge::config::{BridgeConfig, Paths, RelayCfg};
use crate::bridge::creds::{aws_env_state, key_name, preflight_for, seal_file, AwsEnvState};
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
/// R-155: the sole key's variable, the plaintext's third line when it holds one.
pub const SOLE_KEY_VAR: &str = "AI_ENV_RELAY_SOLE_KEY";
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
    /// R-155: the sole signer's key, when the container holds one (`ai-env relay keygen --sole`).
    pub sole: Option<SigningKey>,
}

impl std::fmt::Debug for MacKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MacKeys(worker {}, worker key fp {}, session key fp {}", self.worker_id, self.worker.public_key().fingerprint(), self.session.public_key().fingerprint())?;
        if let Some(sole) = &self.sole {
            write!(f, ", sole key fp {}", sole.public_key().fingerprint())?;
        }
        f.write_str(")")
    }
}

/// What the container's notes record, read with no Touch ID ([`read_notes`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacKeyNotes {
    pub worker_id: String,
    pub worker_key: PublicKey,
    pub session_key: PublicKey,
    /// R-155: the sole key, when the container holds one.
    pub sole_key: Option<PublicKey>,
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

/// `worker  <id>  ed25519:<b64>  fp <fp>`, `session <id>  …` and, with a sole key, `sole    <id>-sole  …`: the lines
/// keygen and pubkey print.
fn key_lines(id: &str, worker: &PublicKey, session: &PublicKey, sole: Option<&PublicKey>) -> Vec<String> {
    let mut lines = vec![format!("worker  {id}  {}  fp {}", worker.text(), worker.fingerprint()), format!("session {id}  {}  fp {}", session.text(), session.fingerprint())];
    if let Some(key) = sole {
        lines.push(format!("sole    {}  {}  fp {}", RelayCfg::sole_id_of(id), key.text(), key.fingerprint()));
    }
    lines
}

/// `bridge.toml` (its defaults without a file), its `[relay]` validated with the workspaces' own grants (WM-R46, R-153).
fn checked_cfg(paths: &Paths) -> Result<BridgeConfig> {
    let cfg = BridgeConfig::load(paths)?.unwrap_or_default();
    cfg.validate_relay()?;
    Ok(cfg)
}

/// `[relay]` of `bridge.toml` (its defaults without a file), validated with the workspaces' own grants (WM-R46, R-153).
pub(crate) fn relay_cfg(paths: &Paths) -> Result<RelayCfg> {
    Ok(checked_cfg(paths)?.relay)
}

/// `ai-env relay keygen [--force] [--sole]` (WM-R36, R-155): no AWS call. `--force` is also `creds::seal_file`'s, as in
/// every creds command: it accepts a `[creds].key` with no recovery recipient (plans/s13-contracts.md §Q.7).
///
/// - With no container, or `--force`: fresh keys sealed with no Touch ID, three with `--sole` or when the container it
///   replaces holds a sole key (its notes say so: a rotation never drops the sole signer), else two.
/// - `--sole` on a container of two keys: refused before any Touch ID when its notes name another worker id (as the agent
///   refuses it) or `creds::seal_file` would refuse the seal; then one unseal (one Touch ID) that checks the two keys,
///   which are sealed again beside a fresh sole key. A container that holds a sole key already is exit 1 naming
///   `relay status` (its allow command) and `relay pubkey --sole`, and `--force`, which replaces all three.
pub fn cmd_keygen(store: &Keystore, force: bool, sole: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let cfg = checked_cfg(&paths)?;
    let id = cfg.relay.worker_id.clone();
    let target = paths.relay_worker_env();
    let key = key_name(&paths)?;
    let sealed = matches!(aws_env_state(&target), AwsEnvState::Sealed);
    let kept = match (sealed, force, sole) {
        (true, false, false) => {
            let held = match read_notes(&paths) {
                Ok(n) => format!(" (worker {}, worker key fp {}, session key fp {}{})", n.worker_id, n.worker_key.fingerprint(), n.session_key.fingerprint(), n.sole_key.as_ref().map_or_else(String::new, |k| format!(", sole key fp {}", k.fingerprint()))),
                Err(_) => String::new(),
            };
            return Err(CliError::Msg(format!("{FILE} already holds this Mac's relay keys{held}: ai-env relay keygen --force replaces them; then allow the new keys and revoke the old")));
        }
        (true, false, true) => Some(unseal_to_add(store, &paths, &key, &id)?),
        _ => None,
    };
    let sole = sole || (sealed && force && read_notes(&paths).is_ok_and(|n| n.sole_key.is_some()));
    let fault = |e: ai_env_worker::keys::KeyError| CliError::Msg(format!("relay keygen: {e}"));
    let adding = kept.is_some();
    let (worker, session) = match kept {
        Some(keys) => (keys.worker, keys.session),
        None => (SigningKey::generate().map_err(fault)?, SigningKey::generate().map_err(fault)?),
    };
    let sole_key = if sole { Some(SigningKey::generate().map_err(fault)?) } else { None };
    let worker_b64 = Zeroizing::new(B64.encode(worker.to_pkcs8_der().map_err(fault)?.as_slice()));
    let session_b64 = Zeroizing::new(B64.encode(session.to_pkcs8_der().map_err(fault)?.as_slice()));
    let sole_b64 = match &sole_key {
        Some(k) => Some(Zeroizing::new(B64.encode(k.to_pkcs8_der().map_err(fault)?.as_slice()))),
        None => None,
    };
    let plaintext = Zeroizing::new(match &sole_b64 {
        Some(third) => format!("{WORKER_KEY_VAR}={}\n{SESSION_KEY_VAR}={}\n{SOLE_KEY_VAR}={}\n", worker_b64.as_str(), session_b64.as_str(), third.as_str()),
        None => format!("{WORKER_KEY_VAR}={}\n{SESSION_KEY_VAR}={}\n", worker_b64.as_str(), session_b64.as_str()),
    });
    let (wk, sk, ok) = (worker.public_key(), session.public_key(), sole_key.as_ref().map(SigningKey::public_key));
    let (wk_text, sk_text, ok_text, sealed_at) = (wk.text(), sk.text(), ok.as_ref().map(PublicKey::text), rfc3339_utc(unix_now()));
    let mut notes = vec![("kind", KIND), ("worker_id", id.as_str()), ("worker_key", wk_text.as_str()), ("session_key", sk_text.as_str())];
    if let Some(text) = &ok_text {
        notes.push(("sole_key", text.as_str()));
    }
    notes.push(("sealed", sealed_at.as_str()));
    let mut secrets: Vec<&[u8]> = vec![worker_b64.as_bytes(), session_b64.as_bytes()];
    if let Some(third) = &sole_b64 {
        secrets.push(third.as_bytes());
    }
    let done = seal_file(store, &paths, &key, &target, plaintext.as_bytes(), &secrets, &notes, force)?;
    drop(secrets);
    drop((plaintext, worker_b64, session_b64, sole_b64, worker, session, sole_key));
    for line in key_lines(&id, &wk, &sk, ok.as_ref()) {
        say(&line);
    }
    if !adding {
        say("allow the session key as a token signer, so the relay takes this Mac's VM session tokens:");
        say(&format!("  ai-env as deployer -- ai-env relay allow {id} --token-signer --key {}", sk.text()));
    }
    if let Some(k) = &ok {
        let sole_id = RelayCfg::sole_id_of(&id);
        let grants = cfg.sole_signer_grants();
        let grants = if grants.is_empty() { "'<grant globs>'".to_string() } else { grants.join(",") };
        say(&format!("allow the sole key as the token signer {sole_id}, the only one bound to [relay].restricted (the relay agent signs with it only for a chat on a VM of its own):"));
        say(&format!("  ai-env as deployer -- ai-env relay allow {sole_id} --token-signer --key {} --grants {grants}", k.text()));
    }
    if !adding {
        say("and, for a Mac that serves sources (a worker under ai-env relay agent), its worker key:");
        say(&format!("  ai-env as deployer -- ai-env relay allow {id} --key {} --sources '<glob>'", wk.text()));
    }
    match (&done.backup, adding) {
        (Some(bak), false) => note(&format!("the old container is kept as {}: revoke the old keys once the new ones are allowed", bak.display())),
        (Some(bak), true) => note(&format!("the old container is kept as {}: it holds the same worker and session keys", bak.display())),
        (None, _) => {}
    }
    if ok.is_some() && cfg.relay.restricted.is_empty() {
        note("[relay].restricted names no grant: the relay agent signs with the sole key once it names one");
    }
    if let Some(pid) = running_agent(&paths) {
        let what = if adding { "signs without the sole key" } else { "keeps the old keys" };
        note(&format!("a running relay agent (pid {pid}) {what} until it restarts: stop it and run ai-env relay agent again"));
    }
    let mut pairs = vec![("worker_id", id.clone()), ("worker_fp", wk.fingerprint()), ("session_fp", sk.fingerprint())];
    if let Some(k) = &ok {
        pairs.push(("sole_fp", k.fingerprint()));
    }
    if done.backup.is_some() && !adding {
        pairs.push(("replaced", "true".to_string()));
    }
    audit(&paths, RELAY_KEYGEN, &pairs);
    Ok(())
}

/// `keygen --sole`'s checks on a sealed container, in order, then its one unseal: the notes (no Touch ID) hold no sole
/// key (else exit 1 naming `--force`) and name `[relay].worker_id` (else exit 1, as the agent refuses them); the seal
/// would pass `creds::seal_file`'s checks (its first refusal); then [`unseal`] checks the two keys against the notes.
fn unseal_to_add(store: &Keystore, paths: &Paths, key: &str, id: &str) -> Result<MacKeys> {
    let notes = read_notes(paths)?;
    if let Some(sole) = &notes.sole_key {
        return Err(CliError::Msg(format!(
            "{FILE} already holds this Mac's sole key (worker {}, sole key fp {}): ai-env relay status names the command that allows it while it is not allowed, and ai-env relay pubkey --sole prints it; ai-env relay keygen --force replaces all three keys; then allow the new keys and revoke the old",
            notes.worker_id,
            sole.fingerprint()
        )));
    }
    if notes.worker_id != id {
        return Err(CliError::Msg(format!("{FILE} was sealed for worker {}, but [relay].worker_id is {id}: ai-env relay keygen --force --sole makes all three keys for {id}", notes.worker_id)));
    }
    let (rows, _) = preflight_for(store, paths, key, &paths.relay_worker_env(), false);
    if let Some(e) = rows.into_iter().find_map(std::result::Result::err) {
        return Err(e);
    }
    unseal(store, paths)
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

/// `ai-env relay pubkey [--worker | --session | --sole] [--verify]` (WM-R37, R-155): the notes, with no Touch ID; with
/// `--verify`, one unseal that checks them against the sealed keys. `--sole` of a container that holds no sole key is
/// exit 5 naming `keygen --sole`, before any Touch ID.
pub fn cmd_pubkey(store: &Keystore, worker: bool, session: bool, sole: bool, verify: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    relay_cfg(&paths)?;
    let notes = read_notes(&paths)?;
    if sole && notes.sole_key.is_none() {
        return Err(CliError::AuthUnavailable(format!("{FILE} holds no sole key: ai-env relay keygen --sole adds it")));
    }
    if verify {
        let keys = unseal(store, &paths)?;
        drop(keys);
    }
    if worker {
        say(&notes.worker_key.text());
    } else if session {
        say(&notes.session_key.text());
    } else if let Some(key) = notes.sole_key.as_ref().filter(|_| sole) {
        say(&key.text());
    } else {
        for line in key_lines(&notes.worker_id, &notes.worker_key, &notes.session_key, notes.sole_key.as_ref()) {
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
/// container's (a `sole_key` that is no key among them) exit 5 naming the re-seal.
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
    let sole_key = if meta.contains_key("sole_key") { Some(key("sole_key")?) } else { None };
    Ok(MacKeyNotes { worker_id, worker_key: key("worker_key")?, session_key: key("session_key")?, sole_key, sealed_at: meta.get("sealed").and_then(|s| parse_rfc3339_utc(s)) })
}

/// The keys of `plain`, exactly `AI_ENV_RELAY_WORKER_KEY=<b64>\nAI_ENV_RELAY_SESSION_KEY=<b64>\n`, or those two lines
/// and `AI_ENV_RELAY_SOLE_KEY=<b64>\n` after them (R-155), each the standard base64 of a PKCS#8 DER: the worker key, the
/// session key and the sole key if any. Anything else is exit 5 naming the re-seal; never a value in the message.
fn parse_plaintext(plain: &[u8]) -> Result<(SigningKey, SigningKey, Option<SigningKey>)> {
    let other = || CliError::AuthUnavailable(format!("{FILE} holds something else: {RESEAL}"));
    let text = std::str::from_utf8(plain).map_err(|_| other())?;
    let body = text.strip_suffix('\n').ok_or_else(other)?;
    let value = |line: &str, var: &str| -> Result<SigningKey> {
        let b64 = line.strip_prefix(var).and_then(|l| l.strip_prefix('=')).ok_or_else(other)?;
        let der = Zeroizing::new(B64.decode(b64).map_err(|_| other())?);
        SigningKey::from_pkcs8_der(&der).map_err(|_| other())
    };
    let lines: Vec<&str> = body.split('\n').collect();
    match lines.as_slice() {
        [first, second] => Ok((value(first, WORKER_KEY_VAR)?, value(second, SESSION_KEY_VAR)?, None)),
        [first, second, third] => Ok((value(first, WORKER_KEY_VAR)?, value(second, SESSION_KEY_VAR)?, Some(value(third, SOLE_KEY_VAR)?))),
        _ => Err(other()),
    }
}

/// One unseal of `credentials/relay-worker.env` (one Touch ID, `[creds].unseal_timeout_s`; a dismissed dialog
/// exit 3, the deadline exit 5): the plaintext must be exactly the two variables, or the three (else exit 5), and its
/// keys must be the ones the notes record, a sole key exactly when they record one (else exit 9: the container was
/// tampered with or mixed up).
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
    let (worker, session, sole) = parse_plaintext(&plain)?;
    drop(plain);
    if !matches_notes(&notes, &worker, &session, sole.as_ref()) {
        return Err(CliError::Policy(format!("the notes of {FILE} do not match its sealed keys: {RESEAL}")));
    }
    Ok(MacKeys { worker_id: notes.worker_id, worker, session, sole })
}

/// Whether the unsealed keys are the ones `notes` record: the worker and session keys, and a sole key exactly when the
/// notes record one, that one.
fn matches_notes(notes: &MacKeyNotes, worker: &SigningKey, session: &SigningKey, sole: Option<&SigningKey>) -> bool {
    worker.public_key() == notes.worker_key && session.public_key() == notes.session_key && sole.map(SigningKey::public_key) == notes.sole_key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_b64(seed: u8) -> String {
        B64.encode(SigningKey::from_seed(&[seed; 32]).unwrap().to_pkcs8_der().unwrap().as_slice())
    }

    fn public(seed: u8) -> PublicKey {
        SigningKey::from_seed(&[seed; 32]).unwrap().public_key()
    }

    /// The plaintext is exactly the two variables, in their order, each a PKCS#8 key; anything else is exit 5
    /// and its message holds no value.
    #[test]
    fn the_plaintext_is_exactly_the_two_keys() {
        let (w, s) = (der_b64(1), der_b64(7));
        let good = format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n");
        let (worker, session, sole) = parse_plaintext(good.as_bytes()).unwrap();
        assert_eq!((worker.public_key(), session.public_key()), (SigningKey::from_seed(&[1; 32]).unwrap().public_key(), SigningKey::from_seed(&[7; 32]).unwrap().public_key()));
        assert!(sole.is_none(), "two lines: no sole key");
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

    /// R-155: a third line is the sole key, only after the two and only under its own variable; a fourth line, the sole
    /// key first or second, an empty third line, a sole key that is no key, or the session key's variable twice is exit 5,
    /// its message holding no value.
    #[test]
    fn a_third_line_is_the_sole_key_after_the_two() {
        let (w, s, o) = (der_b64(1), der_b64(7), der_b64(8));
        let good = format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n{SOLE_KEY_VAR}={o}\n");
        let (worker, session, sole) = parse_plaintext(good.as_bytes()).unwrap();
        assert_eq!((worker.public_key(), session.public_key(), sole.map(|k| k.public_key())), (public(1), public(7), Some(public(8))));
        for bad in [
            format!("{SOLE_KEY_VAR}={o}\n{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n"),
            format!("{WORKER_KEY_VAR}={w}\n{SOLE_KEY_VAR}={o}\n{SESSION_KEY_VAR}={s}\n"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n{SESSION_KEY_VAR}={o}\n"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n{SOLE_KEY_VAR}={o}\n{SOLE_KEY_VAR}={o}\n"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n{SOLE_KEY_VAR}={o}"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n\n"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n{SOLE_KEY_VAR}=\n"),
            format!("{WORKER_KEY_VAR}={w}\n{SESSION_KEY_VAR}={s}\n{SOLE_KEY_VAR}={}\n", B64.encode(b"not a key")),
        ] {
            let e = parse_plaintext(bad.as_bytes()).err().unwrap_or_else(|| panic!("{bad:?} parsed"));
            assert_eq!(e.exit_code(), 5, "{bad:?}");
            assert!(e.to_string().contains("holds something else: re-seal it with ai-env relay keygen --force") && !e.to_string().contains(&o) && !e.to_string().contains(&w), "{e}");
        }
    }

    /// R-155: the unsealed keys match the notes only when each key is the one recorded, and a sole key is held exactly
    /// when the notes record one: a sole key the notes do not name, none where they name one, or another one, is no
    /// match (`unseal`'s exit 9).
    #[test]
    fn the_sole_key_must_be_the_one_the_notes_record() {
        let key = |seed: u8| SigningKey::from_seed(&[seed; 32]).unwrap();
        let notes = |sole: Option<u8>| MacKeyNotes { worker_id: "mac".into(), worker_key: public(1), session_key: public(7), sole_key: sole.map(public), sealed_at: None };
        let (worker, session, sole, other) = (key(1), key(7), key(8), key(9));
        assert!(matches_notes(&notes(None), &worker, &session, None));
        assert!(matches_notes(&notes(Some(8)), &worker, &session, Some(&sole)));
        assert!(!matches_notes(&notes(None), &worker, &session, Some(&sole)), "a sole key the notes do not name");
        assert!(!matches_notes(&notes(Some(8)), &worker, &session, None), "no sole key where the notes name one");
        assert!(!matches_notes(&notes(Some(8)), &worker, &session, Some(&other)), "another sole key");
        assert!(!matches_notes(&notes(Some(8)), &worker, &sole, Some(&session)), "the session and sole keys swapped");
        assert!(!matches_notes(&notes(None), &other, &session, None) && !matches_notes(&notes(None), &worker, &other, None), "as before for the two");
        let debug = format!("{:?}", MacKeys { worker_id: "mac".into(), worker, session, sole: Some(sole) });
        assert_eq!(debug, format!("MacKeys(worker mac, worker key fp {}, session key fp {}, sole key fp {})", public(1).fingerprint(), public(7).fingerprint(), public(8).fingerprint()));
    }

    /// R-155: the key lines name the sole signer `<worker_id>-sole` on a third line when a sole key is held, else the two
    /// lines as before.
    #[test]
    fn the_key_lines_name_the_sole_signer() {
        let two = key_lines("mac", &public(1), &public(7), None);
        assert_eq!(two, [format!("worker  mac  {}  fp {}", public(1).text(), public(1).fingerprint()), format!("session mac  {}  fp {}", public(7).text(), public(7).fingerprint())]);
        let three = key_lines("mac", &public(1), &public(7), Some(&public(8)));
        assert_eq!(three[..2], two[..]);
        assert_eq!(three.get(2), Some(&format!("sole    mac-sole  {}  fp {}", public(8).text(), public(8).fingerprint())));
    }
}
