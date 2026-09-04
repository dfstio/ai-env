//! The keygen ceremony — the one moment that decides whether recovery works.
//!
//! 1. create the key dir 0700 FIRST (age-plugin-se keygen into a missing dir
//!    prints "Public key: …", exits 0, and writes NOTHING — the SE key would
//!    be permanently unrecoverable);
//! 2. run `age-plugin-se keygen`, then POST-VERIFY the identity file;
//! 3. generate the recovery identity with `age-keygen` into a Zeroizing
//!    buffer — never written to disk, displayed once;
//! 4. paste-back via /dev/tty (echo off, 3 attempts) proves it was saved;
//! 5. self-test USES THE PASTED STRING (via `age-keygen -y` and a probe
//!    decrypt through a FIFO) — proving the saved bytes actually decrypt;
//! 6. atomically commit identity.txt / recipients.txt / meta.toml.
use crate::age_cmd::{effective_path, AgeTool};
use crate::bail;
use crate::errors::{CliError, Result};
use crate::store::{validate_identity_file, validate_key_name, write_atomic, KeyMeta, Keystore};
use std::fs;
use std::io::{BufRead, BufReader, Write};

use std::process::Command;
use zeroize::Zeroizing;

pub const ACCESS_CONTROLS: [&str; 7] = [
    "none",
    "passcode",
    "any-biometry",
    "any-biometry-and-passcode",
    "any-biometry-or-passcode",
    "current-biometry",
    "current-biometry-and-passcode",
];

pub struct KeygenOpts {
    pub name: String,
    pub access_control: String,
    pub strongbox_entry: Option<String>,
    pub no_recovery: bool,
}

/// Shared preflight for keygen and restore: name/policy validation,
/// existing-key refusal, plugin discovery.
fn preflight_new_key(store: &Keystore, name: &str, access_control: &str) -> Result<std::path::PathBuf> {
    validate_key_name(name)?;
    if !ACCESS_CONTROLS.contains(&access_control) {
        bail!(
            "unknown --access-control {:?} (one of: {})",
            access_control,
            ACCESS_CONTROLS.join(", ")
        );
    }
    if store.key_exists(name) {
        bail!(
            "key {name:?} already exists — keys are never replaced in place; pick a new name \
             (or `ai-env keys forget {name}` first, which orphans the old enclave key forever)"
        );
    }
    find_plugin().ok_or_else(|| {
        CliError::AuthUnavailable(
            "age-plugin-se is not installed — run: brew install age-plugin-se".into(),
        )
    })
}

/// Create the key dir (0700, FIRST — the plugin writes nothing yet exits 0
/// into a missing dir) and the SE identity, with full post-verification.
/// Returns the SE public recipient. Removes the dir on failure.
fn create_se_identity(
    store: &Keystore,
    plugin: &std::path::Path,
    name: &str,
    access_control: &str,
) -> Result<String> {
    store.ensure_dirs()?;
    let key_dir = store.key_dir(name);
    fs::create_dir_all(&key_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700))?;
    }

    let result = (|| -> Result<String> {
        let identity_path = store.identity_path(name);
        let out = Command::new(plugin)
            .env("PATH", effective_path())
            .arg("keygen")
            .arg(format!("--access-control={access_control}"))
            .arg("--recipient-type=tag")
            .arg("-o")
            .arg(&identity_path)
            .output()
            .map_err(|e| CliError::Msg(format!("cannot run age-plugin-se: {e}")))?;
        if !out.status.success() {
            bail!(
                "age-plugin-se keygen failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let plugin_stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let plugin_stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let printed_pub = plugin_stdout
            .lines()
            .chain(plugin_stderr.lines())
            .find_map(|l| l.split("ublic key:").nth(1).map(str::trim).map(str::to_owned))
            .filter(|s| s.starts_with("age1tag1"));

        // Post-verify: file exists, exactly one SE identity, zero software
        // keys, and the file's comment matches what the plugin printed.
        validate_identity_file(&identity_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))?;
        }
        let identity_text = fs::read_to_string(&identity_path)?;
        let file_pub = identity_text
            .lines()
            .find_map(|l| l.split("ublic key:").nth(1).map(str::trim).map(str::to_owned))
            .filter(|s| s.starts_with("age1tag1"))
            .ok_or_else(|| {
                CliError::Msg("identity file has no `# public key: age1tag1…` comment".into())
            })?;
        if let Some(printed) = &printed_pub {
            if printed != &file_pub {
                bail!(
                    "plugin printed public key {printed} but the file says {file_pub} — aborting"
                );
            }
        }
        ai_env_age::decode_recipient(&file_pub)
            .map_err(|e| CliError::Msg(format!("plugin produced an undecodable recipient: {e}")))?;
        Ok(file_pub)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&key_dir);
    }
    result
}

pub fn keygen(store: &Keystore, age: &AgeTool, opts: &KeygenOpts) -> Result<()> {
    let plugin = preflight_new_key(store, &opts.name, &opts.access_control)?;
    let key_dir = store.key_dir(&opts.name);
    let file_pub = create_se_identity(store, &plugin, &opts.name, &opts.access_control)?;

    let mut recipients = format!(
        "# ai-env key {name}  (created {date})\n# Secure Enclave (daily, Touch ID):\n{file_pub}\n",
        name = opts.name,
        date = today_string(),
    );
    let mut meta = KeyMeta {
        created: today_string(),
        access_control: opts.access_control.clone(),
        recovery_recipient: None,
        strongbox_entry: None,
        recovery_verified: None,
    };

    // 3–5. Recovery identity ceremony. Any failure from here on must remove
    // the half-created key dir — otherwise an identity.txt without
    // recipients/meta lingers, referencing an orphaned enclave key.
    let ceremony_result =
        run_recovery_ceremony(store, age, opts, &file_pub, &mut recipients, &mut meta);
    if let Err(e) = ceremony_result {
        let _ = fs::remove_dir_all(&key_dir);
        return Err(e);
    }

    // 6. Atomic commit.
    write_atomic(&store.recipients_path(&opts.name), recipients.as_bytes())?;
    store.save_meta(&opts.name, &meta)?;
    if store.default_key().is_none() {
        store.set_default(&opts.name)?;
    }

    outprint(&format!(
        "created key {:?} (access control: {})\n  keystore : {}\n  recipient: {}\n",
        opts.name,
        opts.access_control,
        store.key_dir(&opts.name).display(),
        file_pub,
    ))?;
    if opts.access_control == "current-biometry"
        || opts.access_control == "current-biometry-and-passcode"
    {
        outprint(
            "  NOTE: current-biometry keys stop working if you add or remove a fingerprint\n",
        )?;
    }
    Ok(())
}

pub struct RestoreOpts {
    pub name: String,
    pub access_control: String,
    pub strongbox_entry: Option<String>,
    pub rekey: Option<std::path::PathBuf>,
    pub new_recovery: bool,
}

/// Recreate a usable named key from the Strongbox recovery identity: one
/// paste -> a NEW Secure Enclave key -> (optionally) existing files
/// re-encrypted to it. The old SE key is unrecoverable by design (CryptoKit
/// SE keys cannot be enumerated); this restores the WORKFLOW, not that key.
pub fn restore(store: &Keystore, age: &AgeTool, opts: &RestoreOpts) -> Result<()> {
    let plugin = preflight_new_key(store, &opts.name, &opts.access_control)?;

    // Obtain + verify the recovery identity BEFORE creating anything — a bad
    // paste must leave the keystore untouched. The paste proves possession,
    // which is exactly what the keygen ceremony's paste-back verifies.
    let mut pasted = Zeroizing::new(String::new());
    let mut recovery_recipient = String::new();
    if !opts.new_recovery {
        let mut verified = false;
        for attempt in 1..=3 {
            let line = Zeroizing::new(
                read_secret_from_tty(&format!(
                    "Paste the recovery identity for {:?} from Strongbox (attempt {attempt}/3): ",
                    opts.name
                ))?
                .trim()
                .to_string(),
            );
            if line.is_empty() {
                continue;
            }
            match age.identity_to_recipient(&line) {
                Ok(recipient) => {
                    recovery_recipient = recipient;
                    *pasted = line.to_string();
                    verified = true;
                    break;
                }
                Err(_) => outprint("that is not a valid AGE-SECRET-KEY line\n")?,
            }
        }
        if !verified {
            bail!("no valid recovery identity provided — nothing was created");
        }
    }

    // New SE key (the paste is settled; from here failures clean up).
    let key_dir = store.key_dir(&opts.name);
    let file_pub = create_se_identity(store, &plugin, &opts.name, &opts.access_control)?;

    let commit_result = (|| -> Result<()> {
        let mut recipients = format!(
            "# ai-env key {name}  (restored {date})\n# Secure Enclave (daily, Touch ID):\n{file_pub}\n",
            name = opts.name,
            date = today_string(),
        );
        let mut meta = KeyMeta {
            created: today_string(),
            access_control: opts.access_control.clone(),
            recovery_recipient: None,
            strongbox_entry: None,
            recovery_verified: None,
        };

        if opts.new_recovery {
            // Full fresh ceremony (compromise-suspected restores).
            let kopts = KeygenOpts {
                name: opts.name.clone(),
                access_control: opts.access_control.clone(),
                strongbox_entry: opts.strongbox_entry.clone(),
                no_recovery: false,
            };
            run_recovery_ceremony(store, age, &kopts, &file_pub, &mut recipients, &mut meta)?;
        } else {
            let entry_name = opts
                .strongbox_entry
                .clone()
                .unwrap_or_else(|| format!("ai-env: {} recovery", opts.name));
            recipients
                .push_str(&format!("# recovery (Strongbox: {entry_name}):\n{recovery_recipient}\n"));
            meta.recovery_recipient = Some(recovery_recipient.clone());
            meta.strongbox_entry = Some(entry_name);
            meta.recovery_verified = Some(today_string());
        }

        write_atomic(&store.recipients_path(&opts.name), recipients.as_bytes())?;
        store.save_meta(&opts.name, &meta)?;
        if store.default_key().is_none() {
            store.set_default(&opts.name)?;
        }

        // Self-test: a probe encrypted to the NEW recipients must open with
        // the pasted identity (skipped for --new-recovery: its own ceremony
        // already self-tested the fresh identity).
        if !opts.new_recovery {
            let probe = b"ai-env restore self-test";
            let ct = age.encrypt(&store.recipients_path(&opts.name), probe)?;
            let pt = age.decrypt_with_identity_string(&pasted, &ct)?;
            if &**pt != probe {
                bail!("self-test failed: the pasted identity does not decrypt the probe");
            }
        }
        Ok(())
    })();
    if let Err(e) = commit_result {
        let _ = fs::remove_dir_all(&key_dir);
        return Err(e);
    }

    outprint(&format!(
        "restored key {:?} with a NEW Secure Enclave key (access control: {})\n  \
         keystore : {}\n  recipient: {}\n  \
         NOTE: the previous enclave key is orphaned; files encrypted to it open via this\n  \
         key only after re-encryption.\n",
        opts.name,
        opts.access_control,
        store.key_dir(&opts.name).display(),
        file_pub,
    ))?;

    if let Some(dir) = &opts.rekey {
        if opts.new_recovery {
            outprint(
                "note: --rekey with --new-recovery uses the OLD pasted identity — not \
                 available in this mode; run the sweep manually with the old identity\n",
            )?;
        } else {
            let (done, skipped) =
                crate::commands::restore_rekey_sweep(store, age, dir, &pasted, &opts.name)?;
            outprint(&format!(
                "re-encrypted {done} file(s) to the new key ({skipped} skipped — not \
                 addressed to this recovery identity)\n"
            ))?;
        }
    } else {
        outprint(
            "run with --rekey DIR (or re-run: ai-env keys restore … --rekey .) to re-encrypt \
             existing files so Touch ID opens them again\n",
        )?;
    }
    Ok(())
}

fn run_recovery_ceremony(
    _store: &Keystore,
    age: &AgeTool,
    opts: &KeygenOpts,
    _file_pub: &str,
    recipients: &mut String,
    meta: &mut KeyMeta,
) -> Result<()> {
    if opts.no_recovery {
        outprint(&format!(
            "WARNING: key {:?} has NO recovery identity. If this Mac's Secure Enclave dies \
             (theft, logic-board repair, erase-and-install), every file encrypted to this key \
             is permanently unrecoverable. Encrypting with it requires --force.\n",
            opts.name
        ))?;
    } else {
        let (secret, recipient) = age.keygen_x25519()?;
        let entry_name = opts
            .strongbox_entry
            .clone()
            .unwrap_or_else(|| format!("ai-env: {} recovery", opts.name));

        outprint(&format!(
            "\n════════════════ RECOVERY IDENTITY for key {:?} ════════════════\n\
             \n\
                 {}\n\
             \n\
               1. Create a Strongbox entry named:  {}\n\
               2. Paste the AGE-SECRET-KEY line above into it and SAVE.\n\
               3. Optionally print it and store the sheet outside this room.\n\
             \n\
               ai-env does NOT store this key anywhere. This is the ONLY time it\n\
               is shown. Without it, this key's files die with this Mac.\n\
             ══════════════════════════════════════════════════════════════════\n\n",
            opts.name,
            &**secret,
            entry_name,
        ))?;

        // Paste-back: proves the secret survived the trip to Strongbox.
        let mut verified = false;
        for attempt in 1..=3 {
            let pasted = read_secret_from_tty(&format!(
                "Paste the recovery identity back to confirm you saved it (attempt {attempt}/3): "
            ))?;
            let pasted = Zeroizing::new(pasted.trim().to_string());
            if pasted.is_empty() {
                continue;
            }
            // Self-test with THE PASTED STRING: derive its recipient and
            // round-trip a probe through age — never touching disk.
            match age.identity_to_recipient(&pasted) {
                Ok(derived) if derived == recipient => {
                    let probe = b"ai-env recovery self-test";
                    let tmp_rec = tempfile::NamedTempFile::new()
                        .map_err(|e| CliError::Msg(format!("tempfile: {e}")))?;
                    fs::write(tmp_rec.path(), format!("{recipient}\n"))?;
                    let ct = age.encrypt(tmp_rec.path(), probe)?;
                    let pt = age.decrypt_with_identity_string(&pasted, &ct)?;
                    if &**pt == probe {
                        verified = true;
                        break;
                    }
                    outprint("self-test decrypt failed — paste the exact AGE-SECRET-KEY line\n")?;
                }
                Ok(_) => outprint("that identity does not match the one shown above\n")?,
                Err(_) => outprint("that is not a valid AGE-SECRET-KEY line\n")?,
            }
        }
        if !verified {
            bail!("recovery identity was not verified — key NOT created (nothing to lose yet)");
        }

        recipients.push_str(&format!("# recovery (Strongbox: {entry_name}):\n{recipient}\n"));
        meta.recovery_recipient = Some(recipient);
        meta.strongbox_entry = Some(entry_name);
        meta.recovery_verified = Some(today_string());
    }
    Ok(())
}

fn find_plugin() -> Option<std::path::PathBuf> {
    std::env::split_paths(&effective_path())
        .map(|d| d.join("age-plugin-se"))
        .find(|p| p.is_file())
}

pub fn today_string() -> String {
    // Date-only, from the C library (no chrono dependency).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = now / 86_400;
    // Civil-from-days (Howard Hinnant's algorithm), date only.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn outprint(s: &str) -> Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(s.as_bytes())?;
    out.flush()?;
    Ok(())
}

/// Read a line from /dev/tty with echo disabled (the pasted secret must not
/// land in the terminal scrollback a second time).
pub fn read_secret_from_tty(prompt: &str) -> Result<String> {
    // Automation/tests: force the piped-stdin path (never used interactively).
    if std::env::var("AI_ENV_PASTE_STDIN").as_deref() == Ok("1") {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            eprint!("{prompt}");
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            return Ok(line);
        }
    }
    let tty = fs::OpenOptions::new().read(true).write(true).open("/dev/tty");
    let mut tty = match tty {
        Ok(t) => t,
        Err(_) => {
            // No controlling terminal. If stdin is piped (scripts, tests),
            // read the secret from it — it still never touches argv or disk.
            use std::io::IsTerminal;
            if !std::io::stdin().is_terminal() {
                eprint!("{prompt}");
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                return Ok(line);
            }
            return Err(CliError::Msg(
                "no terminal available for the paste step — run interactively \
                 (or use --no-recovery for a throwaway key)"
                    .into(),
            ));
        }
    };
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;

    use std::os::fd::AsRawFd;
    let fd = tty.as_raw_fd();

    /// RAII echo restore: runs on normal return AND on unwind, so a panic
    /// mid-read does not leave the user's terminal with echo disabled.
    /// (A default-action SIGINT still bypasses this — shells reset echo on
    /// the next prompt in practice.)
    struct EchoGuard {
        fd: i32,
        saved: libc::termios,
        active: bool,
    }
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            if self.active {
                // SAFETY: restoring termios state we captured on a valid fd.
                unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
            }
        }
    }

    // SAFETY: plain termios calls on a valid fd we own.
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let have_termios = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let guard = EchoGuard { fd, saved: term, active: have_termios };
    if have_termios {
        term.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let mut line = String::new();
    let read_result = BufReader::new(&tty).read_line(&mut line);
    drop(guard); // restore echo before writing the newline
    let _ = tty.write_all(b"\n");
    read_result?;
    Ok(line)
}
