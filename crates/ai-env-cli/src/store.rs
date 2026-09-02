//! Keystore: N named keys under `$AI_ENV_DIR` (default `~/.config/ai-env`).
//!
//! ```text
//! ~/.config/ai-env/                 (0700)
//! ├── default                       # name of the default key
//! └── keys/<name>/                  (0700)
//!     ├── identity.txt              (0600)  AGE-PLUGIN-SE-1…  (device-bound)
//!     ├── recipients.txt            (0644)  age1tag1… + recovery age1… (public)
//!     └── meta.toml
//! ```
//!
//! There is deliberately NO code path that serialises a recovery PRIVATE key:
//! recovery identities exist only in Strongbox and on paper.
//! `write_atomic` and `check_clobber` are carried verbatim from menv v1.
use crate::bail;
use crate::errors::{CliError, Result};
use ai_env_age::{decode_recipient, Recipient};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMeta {
    pub created: String,
    pub access_control: String,
    #[serde(default)]
    pub recovery_recipient: Option<String>,
    #[serde(default)]
    pub strongbox_entry: Option<String>,
    #[serde(default)]
    pub recovery_verified: Option<String>,
}

pub struct Keystore {
    root: PathBuf,
}

impl Keystore {
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self> {
        let root = match explicit {
            Some(d) => d,
            None => {
                let home = std::env::var_os("HOME")
                    .ok_or_else(|| CliError::Msg("HOME is not set".into()))?;
                PathBuf::from(home).join(".config").join("ai-env")
            }
        };
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn key_dir(&self, name: &str) -> PathBuf {
        self.root.join("keys").join(name)
    }
    pub fn identity_path(&self, name: &str) -> PathBuf {
        self.key_dir(name).join("identity.txt")
    }
    pub fn recipients_path(&self, name: &str) -> PathBuf {
        self.key_dir(name).join("recipients.txt")
    }
    pub fn meta_path(&self, name: &str) -> PathBuf {
        self.key_dir(name).join("meta.toml")
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [self.root.clone(), self.root.join("keys")] {
            fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
    }

    pub fn key_exists(&self, name: &str) -> bool {
        self.identity_path(name).is_file()
    }

    /// All keys that have an identity file, sorted by name. A missing or
    /// unparsable meta.toml does NOT hide the key (that would make files look
    /// unopenable); it degrades to placeholder metadata that `doctor` flags.
    /// No prompts, no subprocesses — safe for `keys list`, `which`, `doctor`.
    pub fn keys(&self) -> Vec<(String, KeyMeta)> {
        let mut out: Vec<(String, KeyMeta)> = Vec::new();
        let Ok(entries) = fs::read_dir(self.root.join("keys")) else {
            return out;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !self.key_exists(&name) {
                continue;
            }
            let meta = self.load_meta(&name).unwrap_or_else(|| KeyMeta {
                created: "unknown".into(),
                access_control: "unknown (meta.toml missing or damaged)".into(),
                recovery_recipient: None,
                strongbox_entry: None,
                recovery_verified: None,
            });
            out.push((name, meta));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn load_meta(&self, name: &str) -> Option<KeyMeta> {
        let text = fs::read_to_string(self.meta_path(name)).ok()?;
        toml::from_str(&text).ok()
    }

    pub fn save_meta(&self, name: &str, meta: &KeyMeta) -> Result<()> {
        let text = toml::to_string_pretty(meta)
            .map_err(|e| CliError::Msg(format!("cannot serialize meta: {e}")))?;
        write_atomic(&self.meta_path(name), text.as_bytes())
    }

    /// Public recipient lines from recipients.txt (comments stripped).
    pub fn recipients_of(&self, name: &str) -> Result<Vec<String>> {
        let text = fs::read_to_string(self.recipients_path(name)).map_err(|_| {
            CliError::NoKey(format!(
                "key {name:?} has no recipients.txt — keystore is damaged"
            ))
        })?;
        Ok(text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect())
    }

    /// The key's tagged (SE) recipient as a compressed P-256 point — what the
    /// decrypt-side tag matcher works on.
    pub fn tag_point_of(&self, name: &str) -> Result<Option<[u8; 33]>> {
        for line in self.recipients_of(name)? {
            if let Ok(recipient) = decode_recipient(&line) {
                if let Some(point) = recipient.p256_point() {
                    return Ok(Some(*point));
                }
            }
        }
        Ok(None)
    }

    /// The key's recovery (X25519) recipient string, if any.
    pub fn recovery_recipient_of(&self, name: &str) -> Result<Option<String>> {
        for line in self.recipients_of(name)? {
            if matches!(decode_recipient(&line), Ok(Recipient::X25519(_))) {
                return Ok(Some(line));
            }
        }
        Ok(None)
    }

    pub fn default_key(&self) -> Option<String> {
        fs::read_to_string(self.root.join("default"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn set_default(&self, name: &str) -> Result<()> {
        write_atomic(&self.root.join("default"), name.as_bytes())
    }
}

/// Key names: lowercase alphanumerics and dashes, 1..=64 chars.
pub fn validate_key_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-');
    if !ok {
        bail!("invalid key name {name:?} (use lowercase letters, digits, dashes)");
    }
    Ok(())
}

/// The plugin identity file must contain exactly one SE identity and zero
/// software secrets (a software identity here would silently bypass Touch ID
/// — age sorts native identities first).
pub fn validate_identity_file(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path)
        .map_err(|e| CliError::Msg(format!("cannot read {}: {e}", path.display())))?;
    let se_lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("AGE-PLUGIN-SE-1"))
        .collect();
    if se_lines.len() != 1 {
        bail!(
            "{} must contain exactly one AGE-PLUGIN-SE identity (found {})",
            path.display(),
            se_lines.len()
        );
    }
    if text.lines().any(|l| l.trim().starts_with("AGE-SECRET-KEY-1")) {
        bail!(
            "{} contains a software AGE-SECRET-KEY — refusing: it would silently bypass \
             Touch ID (age tries native identities first)",
            path.display()
        );
    }
    Ok(se_lines[0].to_string())
}

/// Write a file atomically: exclusive temp file (0600 on unix) in the same
/// directory, fsync, rename over the target, fsync the directory.
/// (Carried verbatim from menv v1.)
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    // Refuse symlinked targets: rename() would replace the LINK, not the
    // target — for `encrypt .env` that silently leaves the plaintext intact
    // at wherever the link pointed while the link itself becomes ciphertext.
    if std::fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        bail!(
            "{} is a symlink — refusing to replace it (the real file it points to would \
             keep the old content); operate on the target directly",
            path.display()
        );
    }
    let dir = path.parent().ok_or_else(|| CliError::Msg("invalid path".into()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CliError::Msg("invalid file name".into()))?;
    let tmp = dir.join(format!(".{name}.tmp"));

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::Msg(format!(
                "{} exists — another ai-env process may be running (delete it if not)",
                tmp.display()
            ))
        } else {
            CliError::Msg(format!("cannot create {}: {e}", tmp.display()))
        }
    })?;
    let result = (|| -> Result<()> {
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Refuse to overwrite an existing file unless `force`.
/// (Carried verbatim from menv v1.)
pub fn check_clobber(path: &Path, force: bool) -> Result<()> {
    if !force && path.exists() {
        bail!("{} already exists (use --force to overwrite)", path.display());
    }
    Ok(())
}
