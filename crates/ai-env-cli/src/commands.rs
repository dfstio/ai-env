//! Subcommand implementations.
use crate::age_cmd::AgeTool;
use crate::bail;
use crate::container;
use crate::errors::{CliError, Result};
use crate::git;
use crate::select;
use crate::store::{check_clobber, write_atomic, Keystore};
use ai_env_age::{parse, StanzaKind};
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// `println!` panics on a closed pipe (`ai-env doctor | head`); this routes
/// status output through the same error path as data output, so a broken pipe
/// becomes the documented exit 0. (Carried verbatim from menv v1.)
pub fn outln(args: std::fmt::Arguments<'_>) -> Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_fmt(args)?;
    out.write_all(b"\n")?;
    Ok(())
}

macro_rules! outln {
    () => { $crate::commands::outln(format_args!(""))? };
    ($($arg:tt)*) => { $crate::commands::outln(format_args!($($arg)*))? };
}

// ---- encrypt ----------------------------------------------------------------

pub struct EncryptOpts {
    pub file: PathBuf,
    pub key: Option<String>,
    pub stdout: bool,
    pub force: bool,
}

pub fn encrypt(store: &Keystore, age: &AgeTool, opts: &EncryptOpts) -> Result<()> {
    let text = read_file_string(&opts.file)?;
    if container::has_marker(&text) {
        // The marker alone is not enough to claim success: a file that SAYS
        // it is encrypted but has a broken/missing payload must not be
        // reported as "already encrypted" (the user might then delete their
        // plaintext), and must not be re-encrypted over (its non-container
        // lines might be the only surviving content).
        return match container::read(&text) {
            Ok(_) => {
                outln!(
                    "{} is already encrypted (ai-env container) — nothing to do",
                    opts.file.display()
                );
                Ok(())
            }
            Err(e) => Err(CliError::Corrupt(format!(
                "{} carries the AI_ENV=1 marker but is NOT a valid container ({e}) — \
                 refusing to touch it; inspect it manually",
                opts.file.display()
            ))),
        };
    }
    // Warn (not refuse) when the plaintext will not survive `ai-env run`'s
    // strict dotenv parser — better to hear it now than after encrypting.
    if let Err(e) = crate::dotenv::parse(&text) {
        eprintln!(
            "warning: {} does not parse as a dotenv file ({e}) — `ai-env run` will not \
             be able to inject these variables (show/decrypt are unaffected)",
            opts.file.display()
        );
    }
    let plaintext = Zeroizing::new(text.into_bytes());
    if plaintext.len() > container::MAX_PLAINTEXT {
        bail!(
            "{} is {} bytes; the container format caps plaintext at {} KiB (docker's \
             64 KiB env-file line limit) — split the file",
            opts.file.display(),
            plaintext.len(),
            container::MAX_PLAINTEXT / 1024
        );
    }
    if plaintext.len() > container::WARN_PLAINTEXT {
        eprintln!(
            "warning: {} is {} KiB — approaching the {} KiB container cap",
            opts.file.display(),
            plaintext.len() / 1024,
            container::MAX_PLAINTEXT / 1024
        );
    }

    let key = select::resolve_for_encrypt(store, opts.key.as_deref(), &opts.file, None)?;

    // Fail closed on unrecoverable keys: in-place encryption is about to
    // REPLACE the only plaintext copy.
    if store.recovery_recipient_of(&key)?.is_none() && !opts.force {
        return Err(CliError::Msg(format!(
            "key {key:?} has no recovery identity — if this Mac's enclave dies, the file \
             is gone forever. Use a key created with a recovery identity, or pass --force \
             to accept that risk"
        )));
    }

    let ciphertext = age.encrypt(&store.recipients_path(&key), &plaintext)?;
    let out_text = container::write(&ciphertext);

    if opts.stdout {
        write_stdout(out_text.as_bytes())?;
        return Ok(());
    }
    write_atomic(&opts.file, out_text.as_bytes())?;
    eprintln!("encrypted {} in place with key {key:?}", opts.file.display());
    git::post_encrypt_advice(&opts.file)?;
    Ok(())
}

// ---- show / decrypt / run ---------------------------------------------------

pub struct DecryptOpts {
    pub file: PathBuf,
    pub output: Option<PathBuf>,
    pub key: Option<String>,
    pub identity: Option<PathBuf>,
    pub force: bool,
}

fn load_container(file: &Path) -> Result<container::Container> {
    let text = read_file_string(file)?;
    if !container::has_marker(&text) {
        return Err(CliError::Corrupt(format!(
            "{} is not an ai-env encrypted file (no AI_ENV=1 marker) — is it still plaintext?",
            file.display()
        )));
    }
    container::read(&text)
}

/// The single decrypt pipeline: container pre-flight (exit 6), tag-based key
/// resolution (exit 4) — both BEFORE age is spawned — then exactly one `-i`.
fn decrypt_ciphertext(
    store: &Keystore,
    age: &AgeTool,
    opts: &DecryptOpts,
    to_stdout: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let cont = load_container(&opts.file)?;
    let identity_path = match &opts.identity {
        Some(path) => path.clone(), // recovery escape hatch: user-provided identity file
        None => {
            let key = select::resolve_for_decrypt(store, opts.key.as_deref(), &cont)?;
            store.identity_path(&key)
        }
    };
    if to_stdout {
        age.decrypt_to_stdout(&identity_path, &cont.data)?;
        Ok(None)
    } else {
        Ok(Some(age.decrypt_to_bytes(&identity_path, &cont.data)?))
    }
}

pub fn show(store: &Keystore, age: &AgeTool, opts: &DecryptOpts) -> Result<()> {
    decrypt_ciphertext(store, age, opts, true)?;
    Ok(())
}

pub fn decrypt(store: &Keystore, age: &AgeTool, opts: &DecryptOpts) -> Result<()> {
    let plaintext = decrypt_ciphertext(store, age, opts, false)?.expect("bytes mode");
    match &opts.output {
        Some(path) if path != Path::new("-") => {
            check_clobber(path, opts.force)?;
            write_private_file(path, &plaintext)?;
            eprintln!("wrote {}", path.display());
        }
        Some(_) => write_stdout(&plaintext)?,
        None => {
            // In-place restore to plaintext.
            if !opts.force {
                bail!(
                    "decrypt restores {} to PLAINTEXT in place — pass --force to confirm \
                     (or use -o FILE, or `ai-env show` to just print it)",
                    opts.file.display()
                );
            }
            write_atomic(&opts.file, &plaintext)?;
            eprintln!(
                "restored {} to plaintext — re-encrypt with `ai-env encrypt` when done",
                opts.file.display()
            );
        }
    }
    Ok(())
}

pub struct RunOpts {
    pub file: PathBuf,
    pub key: Option<String>,
    pub identity: Option<PathBuf>,
    pub command: Vec<String>,
}

/// The centerpiece: run CMD with the decrypted variables injected. Secrets
/// travel only in the child's envp — never argv, never a file.
pub fn run(store: &Keystore, age: &AgeTool, opts: &RunOpts) -> Result<()> {
    if opts.command.is_empty() {
        bail!("nothing to run — usage: ai-env run [-f FILE] -- CMD [ARGS...]");
    }
    let dopts = DecryptOpts {
        file: opts.file.clone(),
        output: None,
        key: opts.key.clone(),
        identity: opts.identity.clone(),
        force: false,
    };
    let plaintext = decrypt_ciphertext(store, age, &dopts, false)?.expect("bytes mode");
    let text = std::str::from_utf8(&plaintext)
        .map_err(|_| CliError::Msg("decrypted content is not UTF-8".into()))?;
    let vars = crate::dotenv::parse(text)?;

    let mut cmd = std::process::Command::new(&opts.command[0]);
    cmd.args(&opts.command[1..]);
    for name in container::CONTAINER_VARS {
        cmd.env_remove(name);
    }
    for (k, v) in &vars {
        cmd.env(k, v);
    }
    drop(plaintext);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec(); // only returns on failure
        Err(CliError::Msg(format!("cannot exec {:?}: {err}", opts.command[0])))
    }
    #[cfg(not(unix))]
    {
        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

// ---- which / info -----------------------------------------------------------

pub fn which(store: &Keystore, file: &Path) -> Result<()> {
    let cont = load_container(file)?;
    let key = select::resolve_for_decrypt(store, None, &cont)?;
    outln!("{key}");
    Ok(())
}

pub fn info(store: &Keystore, file: &Path, json: bool) -> Result<()> {
    let cont = load_container(file)?;
    let header = parse(&cont.data)?;
    let resolved = select::resolve_for_decrypt(store, None, &cont).ok();
    let meta = resolved.as_deref().and_then(|k| store.load_meta(k));

    // The resolved key's public point, to label ONLY the stanza that actually
    // matches it (a file can carry stanzas for several different SE keys).
    let resolved_point =
        resolved.as_deref().and_then(|k| store.tag_point_of(k).ok().flatten());
    let stanza_is_resolved = |s: &ai_env_age::Stanza| -> bool {
        let (Some(point), Some(tag)) = (&resolved_point, s.tag4()) else { return false };
        match s.kind {
            StanzaKind::P256Tag => {
                s.enc65().is_some_and(|enc| ai_env_age::p256tag_tag(&enc, point) == tag)
            }
            StanzaKind::PivP256 => ai_env_age::piv_p256_tag(point) == tag,
            _ => false,
        }
    };

    if json {
        let stanzas: Vec<String> = header
            .stanzas
            .iter()
            .map(|s| {
                format!(
                    "{{\"type\":{},\"tag\":{},\"matches_key\":{}}}",
                    json_string(&s.type_name),
                    s.tag4().map_or("null".into(), |t| json_string(&hex::encode(t))),
                    stanza_is_resolved(s)
                )
            })
            .collect();
        outln!(
            "{{\"file\":{},\"version\":{},\"ciphertext_bytes\":{},\"stanzas\":[{}],\"key\":{}}}",
            json_string(&file.display().to_string()),
            cont.version,
            cont.data.len(),
            stanzas.join(","),
            resolved.as_deref().map_or("null".into(), json_string)
        );
        return Ok(());
    }

    outln!("{}", file.display());
    outln!("  format    : ai-env v{} (age container, {} bytes ciphertext)", cont.version, cont.data.len());
    outln!("  recipients: {}", header.stanzas.len());
    for (i, s) in header.stanzas.iter().enumerate() {
        let annotation = match s.kind {
            StanzaKind::P256Tag | StanzaKind::PivP256 => match (&resolved, stanza_is_resolved(s)) {
                (Some(k), true) => format!("  <- your key {k:?} (Secure Enclave, Touch ID)"),
                _ => "  (Secure Enclave — no matching key in this keystore)".into(),
            },
            StanzaKind::X25519 => match &meta {
                Some(m) if m.recovery_recipient.is_some() => format!(
                    "  <- presumed recovery key (Strongbox: {})",
                    m.strongbox_entry.as_deref().unwrap_or("?")
                ),
                _ => "  (X25519 — unlabeled by design)".into(),
            },
            StanzaKind::Scrypt => "  (passphrase)".into(),
            StanzaKind::Other => String::new(),
        };
        outln!("    [{i}] {:<10}{annotation}", s.type_name);
    }
    Ok(())
}

// ---- keys -------------------------------------------------------------------

pub fn keys_list(store: &Keystore) -> Result<()> {
    let keys = store.keys();
    if keys.is_empty() {
        outln!("no keys — create one with: ai-env keygen NAME");
        return Ok(());
    }
    let default = store.default_key();
    for (name, meta) in keys {
        let mark = if default.as_deref() == Some(&name) { "*" } else { " " };
        let recovery = match (&meta.recovery_recipient, &meta.recovery_verified) {
            (None, _) => "NO RECOVERY".to_string(),
            (Some(_), Some(date)) => {
                let stale = days_since(date).map(|d| d > 90).unwrap_or(false);
                if stale {
                    format!("recovery verified {date} (STALE — run: ai-env verify-recovery {name})")
                } else {
                    format!("recovery verified {date}")
                }
            }
            (Some(_), None) => "recovery never verified".to_string(),
        };
        outln!("{mark} {name:<24} {:<28} {recovery}", meta.access_control);
    }
    Ok(())
}

pub fn keys_show(store: &Keystore, name: &str) -> Result<()> {
    let meta = store
        .load_meta(name)
        .ok_or_else(|| CliError::NoKey(format!("key {name:?} does not exist")))?;
    outln!("key      : {name}");
    outln!("created  : {}", meta.created);
    outln!("policy   : {}", meta.access_control);
    for line in store.recipients_of(name)? {
        outln!("recipient: {line}");
    }
    match meta.strongbox_entry {
        Some(entry) => outln!("strongbox: {entry}"),
        None => outln!("strongbox: (no recovery identity!)"),
    }
    outln!("verified : {}", meta.recovery_verified.as_deref().unwrap_or("never"));
    Ok(())
}

pub fn keys_default(store: &Keystore, name: &str) -> Result<()> {
    if !store.key_exists(name) {
        return Err(CliError::NoKey(format!("key {name:?} does not exist")));
    }
    store.set_default(name)?;
    outln!("default key is now {name:?}");
    Ok(())
}

pub fn keys_forget(store: &Keystore, name: &str, yes: bool) -> Result<()> {
    if !store.key_exists(name) {
        return Err(CliError::NoKey(format!("key {name:?} does not exist")));
    }
    if !yes {
        bail!(
            "`keys forget` deletes the local handle for {name:?}. The enclave key itself \
             cannot be deleted (CryptoKit SE keys are unenumerable) — it is orphaned \
             forever, and files encrypted to it become openable ONLY via their recovery \
             identity. Re-run with --yes to confirm"
        );
    }
    fs::remove_dir_all(store.key_dir(name))?;
    if store.default_key().as_deref() == Some(name) {
        let _ = fs::remove_file(store.root().join("default"));
    }
    outln!("forgot key {name:?} (recovery identity in Strongbox still opens its files)");
    Ok(())
}

// ---- rekey ------------------------------------------------------------------

pub fn rekey(store: &Keystore, age: &AgeTool, dir: &Path, dry_run: bool, yes: bool) -> Result<()> {
    let mut targets: Vec<PathBuf> = Vec::new();
    discover_containers(dir, 0, &mut targets)?;
    if targets.is_empty() {
        outln!("no ai-env containers found under {}", dir.display());
        return Ok(());
    }
    for t in &targets {
        outln!("{}", t.display());
    }
    if dry_run {
        outln!("(dry run: {} file(s) would be re-encrypted)", targets.len());
        return Ok(());
    }
    if targets.len() > 10 && !yes {
        bail!(
            "{} files — that is {} Touch ID prompts (the enclave never caches biometry). \
             Re-run with --yes to proceed",
            targets.len(),
            targets.len()
        );
    }
    let mut skipped = 0usize;
    for path in &targets {
        let cont = load_container(path)?;
        // A container none of our keys can open (someone else's file, or a
        // forgotten key) is skipped with a warning — not a reason to abort
        // the rest of the sweep.
        let key = match select::resolve_for_decrypt(store, None, &cont) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("skipping {} — {e}", path.display());
                skipped += 1;
                continue;
            }
        };
        let plaintext = age.decrypt_to_bytes(&store.identity_path(&key), &cont.data)?;
        let ciphertext = age.encrypt(&store.recipients_path(&key), &plaintext)?;
        write_atomic(path, container::write(&ciphertext).as_bytes())?;
        eprintln!("re-encrypted {} with key {key:?}", path.display());
    }
    if skipped > 0 {
        eprintln!("({skipped} file(s) skipped — no key in this keystore opens them)");
    }
    Ok(())
}

fn discover_containers(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<()> {
    if depth > 8 {
        return Ok(());
    }
    let Ok(entries) = fs::read_dir(dir) else { return Ok(()) };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !matches!(name.as_str(), ".git" | "target" | "node_modules" | ".svelte-kit") {
                discover_containers(&path, depth + 1, out)?;
            }
        } else if path.is_file() && entry.metadata().map(|m| m.len() < 256 * 1024).unwrap_or(false)
        {
            if let Ok(text) = fs::read_to_string(&path) {
                if container::detect(&text) {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

// ---- verify-recovery --------------------------------------------------------

pub fn verify_recovery(store: &Keystore, age: &AgeTool, name: &str) -> Result<()> {
    let mut meta = store
        .load_meta(name)
        .ok_or_else(|| CliError::NoKey(format!("key {name:?} does not exist")))?;
    let expected = meta.recovery_recipient.clone().ok_or_else(|| {
        CliError::Msg(format!("key {name:?} was created with --no-recovery — nothing to verify"))
    })?;

    let pasted = crate::ceremony::read_secret_from_tty(&format!(
        "Paste the recovery identity for {name:?} from Strongbox (or the paper sheet): "
    ))?;
    let pasted = Zeroizing::new(pasted.trim().to_string());
    let derived = age.identity_to_recipient(&pasted)?;
    if derived != expected {
        bail!(
            "that identity derives recipient {derived}, but key {name:?} expects {expected} \
             — WRONG RECOVERY KEY. Fix your Strongbox entry NOW, while the enclave still works"
        );
    }
    // Full round trip: encrypt a probe to the key's recipients, decrypt with
    // the pasted identity only (no enclave involved — this is the drill).
    let probe = b"ai-env recovery drill";
    let ct = age.encrypt(&store.recipients_path(name), probe)?;
    let pt = age.decrypt_with_identity_string(&pasted, &ct)?;
    if &**pt != probe {
        bail!("round-trip failed — recovery identity did not decrypt the probe");
    }
    meta.recovery_verified = Some(crate::ceremony::today_string());
    store.save_meta(name, &meta)?;
    outln!("recovery identity for {name:?} VERIFIED — next drill due in ~90 days");
    Ok(())
}

// ---- doctor -----------------------------------------------------------------

pub fn doctor(store: &Keystore, file: &Path) -> Result<()> {
    outln!("ai-env doctor");
    match AgeTool::probe() {
        Ok(age) => {
            let (a, b, c) = age.version;
            let hint = if (a, b, c) < (1, 3, 2) { "  (1.3.2+ recommended)" } else { "" };
            outln!("  [ok ] age v{a}.{b}.{c}{hint}");
            outln!(
                "  [{}] age-plugin-se{}",
                if age.plugin_se_available() { "ok " } else { "NO " },
                if age.plugin_se_available() { "" } else { "  <- brew install age-plugin-se (needed for keygen/decrypt)" }
            );
        }
        Err(e) => outln!("  [NO ] age: {e}"),
    }
    let gui = Path::new("/dev/tty").exists()
        && std::process::Command::new("launchctl")
            .arg("managername")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "Aqua")
            .unwrap_or(false);
    outln!(
        "  [{}] GUI session (Touch ID prompts need one){}",
        if gui { "ok " } else { "NO " },
        if gui { "" } else { "  <- decryption will fail over SSH" }
    );
    outln!("  keystore: {}", store.root().display());
    let keys = store.keys();
    if keys.is_empty() {
        outln!("  [NO ] no keys — run: ai-env keygen NAME");
    }
    for (name, meta) in &keys {
        let recovery = if meta.recovery_recipient.is_none() {
            "NO RECOVERY"
        } else if meta
            .recovery_verified
            .as_deref()
            .and_then(days_since)
            .map(|d| d > 90)
            .unwrap_or(true)
        {
            "recovery verification STALE (>90d)"
        } else {
            "ok"
        };
        outln!("  [ok ] key {name:<20} {recovery}");
    }

    // File-level checks.
    if file.exists() {
        let text = read_file_string(file)?;
        if container::has_marker(&text) {
            outln!("  [ok ] {} is encrypted", file.display());
            if text.contains('\r') {
                outln!("  [NO ] {} contains CR characters — a CRLF checkout will corrupt the base64", file.display());
            }
        } else {
            outln!("  [NO ] {} is PLAINTEXT — run: ai-env encrypt", file.display());
        }
        if let Some(ctx) = git::inspect(file) {
            if ctx.file_ignored {
                outln!(
                    "  [-  ] {} is gitignored — the encrypted file is safe to commit and \
                     committing it is its backup",
                    file.display()
                );
            }
            outln!(
                "  [{}] pre-commit guard against plaintext .env commits",
                if ctx.hook_installed { "ok " } else { "-  " }
            );
            // Plaintext siblings.
            if let Some(parent) = file.parent() {
                if let Ok(entries) = fs::read_dir(if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                }) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        let looks_env = name.starts_with(".env") || name.ends_with(".env");
                        let backupish = name.ends_with(".backup")
                            || name.ends_with(".bak")
                            || name.ends_with(".old")
                            || name.ends_with(".orig");
                        if looks_env || (backupish && name.contains("env")) {
                            if let Ok(t) = fs::read_to_string(entry.path()) {
                                if !container::has_marker(&t) && entry.path() != *file {
                                    outln!(
                                        "  [!! ] plaintext env-like sibling: {name}  <- rotate \
                                         or encrypt it"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        outln!("  [-  ] {} does not exist in this directory", file.display());
    }
    Ok(())
}

// ---- shared helpers ---------------------------------------------------------

/// Minimal JSON string encoder (escapes quotes, backslashes, control chars).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn days_since(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    // days-from-civil (Howard Hinnant), mirrored in ceremony::today.
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = y_adj.div_euclid(400);
    let yoe = y_adj - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64
        / 86_400;
    Some(now - days)
}

fn read_file_string(path: &Path) -> Result<String> {
    if path == Path::new("-") {
        let mut stdin = std::io::stdin();
        if stdin.is_terminal() {
            bail!("stdin is a terminal — pass a FILE, or pipe data in");
        }
        let mut buf = String::new();
        stdin.read_to_string(&mut buf)?;
        return Ok(buf);
    }
    fs::read_to_string(path).map_err(|e| {
        CliError::Msg(format!("cannot read {}: {e}", path.display()))
    })
}

fn write_stdout(data: &[u8]) -> Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(data)?;
    out.flush()?;
    Ok(())
}

/// Write a decrypted plaintext file, enforcing 0600 and refusing to follow a
/// symlink at the target path. (Carried verbatim from menv v1, including its
/// review fixes: chmod on pre-existing files + O_NOFOLLOW.)
fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        opts.custom_flags(0x0100); // O_NOFOLLOW
        #[cfg(target_os = "linux")]
        opts.custom_flags(0x2_0000); // O_NOFOLLOW
    }
    let mut file = opts.open(path).map_err(|e| {
        if e.raw_os_error() == Some(62) || e.raw_os_error() == Some(40) {
            CliError::Msg(format!("refusing to write {} — it is a symlink", path.display()))
        } else {
            CliError::Msg(format!("cannot write {}: {e}", path.display()))
        }
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data)?;
    file.flush()?;
    Ok(())
}
