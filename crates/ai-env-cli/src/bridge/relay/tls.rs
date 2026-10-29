//! The relay's TLS (S13, WM-R59 to WM-R62, LD-WM17): an ECDSA P-256 relay CA whose key is sealed on this Mac
//! (`credentials/relay-ca.env`), and the relay's ECDSA P-256 leaf, whose chain and key are the one SecureString
//! `/ai-env/relay/tls`. The certificates come from `ai_env_worker::certs` (a small DER writer signing with
//! aws-lc-rs): no OpenSSL runs at use time and no crate is added.
//!
//! - `ai-env relay tls init [--force]` (as ai-env-deployer: no marker, an ops, a root and an ambient marker are
//!   refused, exit 9, `params::tls_gate`): a new CA, its key sealed with no Touch ID (sealing is public-key only),
//!   its certificate (public) written to `state/relay-ca.pem` and `state/relay-ca.der`, then a leaf for both names
//!   a client verifies: DNS `ai-env-relay` (workers) and IP `10.42.0.20` (VMs). An existing CA is replaced only
//!   with `--force`: a new CA strands every worker's pinned `relay_ca` file.
//! - `ai-env relay tls rotate` (as ai-env-deployer): one unseal of the CA key (one Touch ID), the CA rebuilt from
//!   it and `state/relay-ca.der` (a mismatch is exit 9), a new leaf.
//! - `ai-env relay ca [--der]`: the CA's certificate, for a worker's `relay_ca` file; no AWS call, no Touch ID.
//! - [`ca_der_b64`]: what a spawn's relay session pins (WM-R62).
//!
//! The `tls` value is the leaf PEM, the CA PEM, then the PKCS#8 key PEM (I-R31), at most 4096 bytes; it reaches
//! SSM on the aws child's stdin (`--value file:///dev/stdin`, plans/s13-contracts.md §Q.8 F5), never a file or an
//! argument list, always as a SecureString under `alias/aws/ssm` (`params::put_secure`), and stdout names the two
//! fingerprints and the version, never a key (WM-R54).
use super::cli::{say, RelayCtx};
use super::params::{create_parameter, put_secure, tls_gate, ParamType};
use crate::age_cmd::AgeTool;
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::creds::{aws_env_state, key_name, seal_file, AwsEnvState};
use crate::bridge::egress::{ops, relay_param_name, RELAY_IP};
use crate::bridge::infra::write_atomic_mode;
use crate::bridge::registry::{ensure_private_dir, read_regular_file};
use crate::bridge::unseal::UnsealJob;
use crate::bridge::voice;
use crate::errors::{CliError, Result};
use crate::store::{validate_key_name, Keystore};
use crate::wire::time::{rfc3339_utc, unix_now};
use ai_env_worker::certs::{self, Issued, CA_DAYS};
use base64::Engine as _;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The CA key's variable in its container's plaintext.
pub const CA_KEY_VAR: &str = "AI_ENV_RELAY_CA_KEY";
/// The notes' `kind`.
const KIND: &str = "relay-ca";
/// SSM's Standard limit, which the chain and key must fit (I-R31).
const TLS_MAX: usize = 4096;
/// The container, as messages name it.
const CA_FILE: &str = "credentials/relay-ca.env";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The SecureString the relay's reload unit fetches: I's `relay_param_name("tls")` (`/ai-env/relay/tls`).
fn tls_param() -> String {
    relay_param_name("tls")
}

/// `credentials/relay-ca.env`: the CA key, sealed.
fn ca_env(paths: &Paths) -> PathBuf {
    paths.credentials().join("relay-ca.env")
}

/// `state/relay-ca.pem`: the CA's certificate (public, 0644).
fn ca_pem_path(paths: &Paths) -> PathBuf {
    paths.root.join("state").join("relay-ca.pem")
}

/// `state/relay-ca.der`: the same certificate, DER (public, 0644): what a spawn's relay session pins.
fn ca_der_path(paths: &Paths) -> PathBuf {
    paths.root.join("state").join("relay-ca.der")
}

/// `state/relay-ca.der` in standard base64, for a spawn's `RelaySpawn` (WM-R62); `None` when it is absent, not a
/// regular file, or not a DER certificate of at most `wire::relay::CA_DER_MAX` bytes.
#[must_use]
pub fn ca_der_b64(paths: &Paths) -> Option<String> {
    let der = read_der(&ca_der_path(paths)).ok().flatten()?;
    (!der.is_empty() && der.len() <= crate::wire::relay::CA_DER_MAX && der[0] == 0x30).then(|| B64.encode(&der))
}

/// The bytes of a regular file (never through a symlink), `None` when it is missing.
fn read_der(path: &std::path::Path) -> std::result::Result<Option<Vec<u8>>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let opened = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path);
    let file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot open {}: {e}", path.display())),
    };
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let mut out = Vec::new();
    file.take(64 * 1024).read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(Some(out))
}

/// The leaf for the relay under `ca`, as the `tls` value: the leaf PEM, the CA PEM, the key PEM (I-R31), at most
/// 4096 bytes. Returns the value and the leaf's fingerprint.
fn tls_value(ca: &Issued, now: u64) -> Result<(Zeroizing<String>, String)> {
    let ip = RELAY_IP.parse().map_err(|_| CliError::Msg(format!("relay tls: {RELAY_IP} is not an IPv4 address")))?;
    let leaf = certs::relay_leaf(ca, ip, now).map_err(|e| CliError::Msg(format!("relay tls: the relay's certificate: {e}")))?;
    let key = Zeroizing::new(certs::pem("PRIVATE KEY", &leaf.key_pkcs8));
    let value = Zeroizing::new(format!("{}{}{}", certs::pem("CERTIFICATE", &leaf.cert_der), certs::pem("CERTIFICATE", &ca.cert_der), key.as_str()));
    if value.len() > TLS_MAX {
        return Err(CliError::Msg(format!("relay tls: {} would be {} bytes, over SSM's {TLS_MAX}; nothing was written", tls_param(), value.len())));
    }
    Ok((value, certs::fingerprint(&leaf.cert_der)))
}

/// Write the `tls` value as `op` (WM-R60): created as a SecureString under `alias/aws/ssm` when absent (no
/// `--overwrite`), else overwritten with the same `--type SecureString --key-id alias/aws/ssm` (a `tls` of another
/// type is refused by SSM, exit 7, never given the key); either way on the aws child's stdin, never through a
/// file (§Q.8 F5: I's `egress::ops::put_parameter`, which writes a temp file, is not used here). The new version.
fn write_tls(op: &crate::bridge::identity::Operator, what: &str, value: &str) -> Result<u64> {
    let name = tls_param();
    let (held, _) = ops::get_parameters(std::slice::from_ref(&name)).map_err(|e| CliError::Aws(format!("relay {what}: {e}")))?;
    if held.contains_key(&name) {
        put_secure(op, &name, value, true).map_err(|e| CliError::Aws(format!("relay {what}: {e}")))
    } else {
        create_parameter(op, &name, value, ParamType::SecureString).map_err(|e| CliError::Aws(format!("relay {what}: {e}")))
    }
}

/// `ai-env relay tls init [--force]` (WM-R59, WM-R60). `--force` is also `creds::seal_file`'s, as in every creds
/// command: it accepts a `[creds].key` with no recovery recipient (plans/s13-contracts.md §Q.7).
pub fn cmd_tls_init(store: &Keystore, force: bool) -> Result<()> {
    tls_gate("tls init", &if force { vec!["--force".to_string()] } else { Vec::new() })?;
    let paths = Paths::resolve()?;
    let existing: Vec<String> = [(ca_env(&paths), CA_FILE), (ca_pem_path(&paths), "state/relay-ca.pem"), (ca_der_path(&paths), "state/relay-ca.der")]
        .into_iter()
        .filter(|(p, _)| std::fs::symlink_metadata(p).is_ok())
        .map(|(_, name)| name.to_string())
        .collect();
    if !existing.is_empty() && !force {
        return Err(CliError::Msg(format!(
            "relay tls init: a relay CA exists ({}): ai-env relay tls init --force makes a new one, and every worker's relay_ca file must then be replaced (ai-env relay tls rotate issues a new certificate under this one)",
            existing.join(", ")
        )));
    }
    let ctx = RelayCtx::load()?;
    let op = ctx.operator("relay tls init")?;
    let now = unix_now();
    let ca = certs::relay_ca(now).map_err(|e| CliError::Msg(format!("relay tls init: the relay CA: {e}")))?;
    let ca_fp = certs::fingerprint(&ca.cert_der);
    // The leaf and the value first, in memory: a refusal there (over SSM's 4096 bytes) leaves nothing written.
    let (value, leaf_fp) = tls_value(&ca, now)?;
    let key_b64 = Zeroizing::new(B64.encode(ca.key_pkcs8.as_slice()));
    let plaintext = Zeroizing::new(format!("{CA_KEY_VAR}={}\n", key_b64.as_str()));
    let not_after = rfc3339_utc(now + u64::from(CA_DAYS) * 86_400)[..10].to_string();
    let notes = [("kind", KIND), ("ca_fp", ca_fp.as_str()), ("not_after", not_after.as_str())];
    let sealed = seal_file(store, &paths, &key_name(&paths)?, &ca_env(&paths), plaintext.as_bytes(), &[key_b64.as_bytes()], &notes, force)?;
    drop((plaintext, key_b64));
    ensure_private_dir(&paths.root.join("state"))?;
    write_atomic_mode(&ca_pem_path(&paths), certs::pem("CERTIFICATE", &ca.cert_der).as_bytes(), 0o644)?;
    write_atomic_mode(&ca_der_path(&paths), &ca.cert_der, 0o644)?;
    // The CA stands from here on: a failed write of the value is recovered under it, with no new CA.
    let tls = tls_param();
    let version = write_tls(&op, "tls init", &value).map_err(|e| CliError::Aws(format!("{e}; the relay CA fp {ca_fp} is made and sealed: ai-env relay tls rotate writes {tls} under it")))?;
    drop(value);
    say(&format!("relay CA fp {ca_fp} until {not_after}: its key sealed in {CA_FILE}, its certificate in state/relay-ca.pem and state/relay-ca.der"));
    say(&format!("relay certificate fp {leaf_fp} (ai-env-relay, {RELAY_IP}) in {tls} v{version}: the relay serves it within a minute"));
    if sealed.backup.is_some() {
        say("a new CA: every worker's relay_ca file must be replaced (ai-env relay ca prints it)");
    }
    Ok(())
}

/// `ai-env relay tls rotate` (WM-R60).
pub fn cmd_tls_rotate(store: &Keystore) -> Result<()> {
    tls_gate("tls rotate", &[])?;
    let paths = Paths::resolve()?;
    let cert = read_der(&ca_der_path(&paths)).map_err(|e| CliError::Msg(format!("relay tls rotate: {e}")))?;
    let cert = cert.ok_or_else(|| CliError::AuthUnavailable("relay tls rotate: state/relay-ca.der does not exist: make the relay CA with ai-env relay tls init".into()))?;
    let ctx = RelayCtx::load()?;
    let op = ctx.operator("relay tls rotate")?;
    let key = unseal_ca(store, &paths)?;
    let ca = certs::ca_from_parts(&cert, &key).map_err(|e| match e {
        certs::CertError::Mismatch => CliError::Policy(format!("relay tls rotate: {CA_FILE} does not hold the key of state/relay-ca.der: make a new CA with ai-env relay tls init --force")),
        other => CliError::Msg(format!("relay tls rotate: the relay CA: {other}")),
    })?;
    drop(key);
    let (value, leaf_fp) = tls_value(&ca, unix_now())?;
    let version = write_tls(&op, "tls rotate", &value)?;
    drop(value);
    say(&format!("relay certificate fp {leaf_fp} (ai-env-relay, {RELAY_IP}) under the relay CA fp {} in {} v{version}: the relay serves it to new connections within a minute", certs::fingerprint(&ca.cert_der), tls_param()));
    Ok(())
}

/// One unseal of `credentials/relay-ca.env` (one Touch ID): the PKCS#8 DER of the CA key, from a plaintext that
/// is exactly `AI_ENV_RELAY_CA_KEY=<b64>\n` (else exit 5).
fn unseal_ca(store: &Keystore, paths: &Paths) -> Result<Zeroizing<Vec<u8>>> {
    let path = ca_env(paths);
    match aws_env_state(&path) {
        AwsEnvState::Sealed => {}
        AwsEnvState::Absent => return Err(CliError::AuthUnavailable(format!("{CA_FILE} does not exist: make the relay CA with ai-env relay tls init"))),
        AwsEnvState::NotSealed(why) => return Err(CliError::AuthUnavailable(format!("{} {why}: move it away, then ai-env relay tls init --force", path.display()))),
    }
    let cfg = BridgeConfig::load(paths)?.unwrap_or_default();
    validate_key_name(&cfg.creds.key).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    let text = read_regular_file(&path)?.ok_or_else(|| CliError::AuthUnavailable(format!("{CA_FILE} vanished while it was read")))?;
    let cont = crate::container::read(&text)?;
    let name = crate::select::resolve_for_decrypt(store, Some(cfg.creds.key.as_str()), &cont)?;
    let age = Arc::new(AgeTool::probe()?);
    let plain = UnsealJob::start(age, store.identity_path(&name), cont.data, cfg.creds.unseal_budget(), format!("the relay CA's key ({CA_FILE})"))
        .with_prefix(voice::prefix())
        .wait(crate::bridge::signals::say)?;
    let other = || CliError::AuthUnavailable(format!("{CA_FILE} holds something else: make a new CA with ai-env relay tls init --force"));
    let text = std::str::from_utf8(&plain).map_err(|_| other())?;
    let b64 = text.strip_suffix('\n').and_then(|t| t.strip_prefix(CA_KEY_VAR)).and_then(|t| t.strip_prefix('=')).ok_or_else(other)?;
    let der = Zeroizing::new(B64.decode(b64).map_err(|_| other())?);
    drop(plain);
    Ok(der)
}

/// `ai-env relay ca [--der]` (WM-R61): `state/relay-ca.pem`, or the standard base64 of `state/relay-ca.der`;
/// absent is exit 5 naming `ai-env relay tls init`.
pub fn cmd_ca(der: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let absent = || CliError::AuthUnavailable("the relay CA's certificate is not on this Mac: make it with ai-env relay tls init (as ai-env-deployer)".into());
    if der {
        let bytes = read_der(&ca_der_path(&paths)).map_err(CliError::Msg)?.ok_or_else(absent)?;
        say(&B64.encode(&bytes));
    } else {
        let pem = read_regular_file(&ca_pem_path(&paths))?.ok_or_else(absent)?;
        let _ = std::io::Write::write_all(&mut std::io::stdout().lock(), pem.as_bytes());
    }
    Ok(())
}
