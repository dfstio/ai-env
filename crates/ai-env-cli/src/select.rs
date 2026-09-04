//! Key resolution.
//!
//! Decrypt side: parse the container's age header and TAG-MATCH against every
//! keystore key's public recipient — automatic, offline, prompt-free (the
//! whole point of `p256tag`). Encrypt side: explicit flag, then the existing
//! container's tag, then `.ai-env.toml`, then the keystore default.
use crate::config;
use crate::container::Container;
use crate::errors::{CliError, Result};
use crate::store::Keystore;
use ai_env_age::{match_recipients, parse, MatchResult};
use std::path::Path;

/// Which key opens this container? Exit 4 (`NoKey`) when none — decided here,
/// with no prompt and no age process.
pub fn resolve_for_decrypt(
    store: &Keystore,
    explicit: Option<&str>,
    container: &Container,
) -> Result<String> {
    if let Some(name) = explicit {
        if !store.key_exists(name) {
            return Err(CliError::NoKey(format!(
                "key {name:?} does not exist (ai-env keys list)"
            )));
        }
        return Ok(name.to_string());
    }
    let header = parse(&container.data)?;
    let keys = store.keys();
    let mut points: Vec<[u8; 33]> = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    for (name, _) in &keys {
        if let Some(point) = store.tag_point_of(name)? {
            points.push(point);
            names.push(name);
        }
    }
    match match_recipients(&header, &points) {
        MatchResult::One(i) => Ok(names[i].to_string()),
        MatchResult::None => Err(CliError::NoKey(
            "no key in your keystore can open this file — if you have the recovery \
             identity (Strongbox), run: ai-env keys restore NAME --rekey . (re-encrypts \
             the files to the key, creating it only if missing), or decrypt directly: \
             ai-env decrypt -i IDENTITY_FILE (or the stock recovery one-liner in the \
             file header)"
                .into(),
        )),
        MatchResult::Ambiguous(indices) => {
            let list: Vec<&str> = indices.iter().map(|&i| names[i]).collect();
            Err(CliError::Msg(format!(
                "multiple keys match this file ({}) — pass -k to choose",
                list.join(", ")
            )))
        }
    }
}

/// Which key should encrypt this (new or re-encrypted) file?
pub fn resolve_for_encrypt(
    store: &Keystore,
    explicit: Option<&str>,
    file: &Path,
    existing: Option<&Container>,
) -> Result<String> {
    if let Some(name) = explicit {
        if !store.key_exists(name) {
            return Err(CliError::NoKey(format!(
                "key {name:?} does not exist (ai-env keys list, or: ai-env keygen {name})"
            )));
        }
        return Ok(name.to_string());
    }
    if let Some(container) = existing {
        // Re-encrypt: keep the key the file is already addressed to.
        if let Ok(name) = resolve_for_decrypt(store, None, container) {
            return Ok(name);
        }
    }
    if let Some(name) = config::key_for_file(file)? {
        if !store.key_exists(&name) {
            return Err(CliError::NoKey(format!(
                ".ai-env.toml names key {name:?}, which does not exist (ai-env keygen {name})"
            )));
        }
        return Ok(name);
    }
    if let Some(name) = store.default_key() {
        if store.key_exists(&name) {
            return Ok(name);
        }
    }
    Err(CliError::NoKey(
        "no key selected — pass -k NAME, add a .ai-env.toml rule, or set a default \
         (ai-env keys default NAME). Create one with: ai-env keygen NAME"
            .into(),
    ))
}
