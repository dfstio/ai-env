//! `.ai-env.toml` — the encrypt-side key map. Discovered by walking up from
//! the target file's directory to `$HOME` (inclusive); first file found wins,
//! first matching rule inside it wins. Contains only key NAMES (no secrets);
//! gitignored by default, safe to commit for teams.
//!
//! ```toml
//! default_key = "silvana-devnet"
//!
//! [[rules]]
//! paths = ["*.mainnet.env", "deploy/prod/*"]
//! key   = "silvana-mainnet"
//! ```
use crate::errors::{CliError, Result};
use serde::Deserialize;
use std::path::Path;

pub const CONFIG_NAME: &str = ".ai-env.toml";

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub default_key: Option<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub paths: Vec<String>,
    pub key: String,
}

/// Minimal wildcard matcher: `*` matches within a path segment, `**` crosses
/// segments, `?` matches one character. Matched against BOTH the file's name
/// and its path relative to the config file's directory.
#[must_use]
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    fn inner(p: &[u8], t: &[u8]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        match p[0] {
            b'*' => {
                if p.get(1) == Some(&b'*') {
                    // `**`: match any run including '/'
                    (0..=t.len()).any(|i| inner(&p[2..], &t[i..]))
                } else {
                    // `*`: match any run excluding '/'
                    (0..=t.len())
                        .take_while(|&i| i == 0 || t[i - 1] != b'/')
                        .any(|i| inner(&p[1..], &t[i..]))
                }
            }
            b'?' => !t.is_empty() && t[0] != b'/' && inner(&p[1..], &t[1..]),
            c => !t.is_empty() && t[0] == c && inner(&p[1..], &t[1..]),
        }
    }
    inner(pattern.as_bytes(), text.as_bytes())
}

/// Find and parse the nearest `.ai-env.toml`; returns (config, its directory).
pub fn discover(start_dir: &Path) -> Result<Option<(Config, std::path::PathBuf)>> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let mut dir = Some(start_dir.to_path_buf());
    while let Some(d) = dir {
        let candidate = d.join(CONFIG_NAME);
        if candidate.is_file() {
            let text = std::fs::read_to_string(&candidate)
                .map_err(|e| CliError::Msg(format!("cannot read {}: {e}", candidate.display())))?;
            let config: Config = toml::from_str(&text)
                .map_err(|e| CliError::Msg(format!("{}: {e}", candidate.display())))?;
            return Ok(Some((config, d)));
        }
        if home.as_deref() == Some(&d) {
            break;
        }
        dir = d.parent().map(Path::to_path_buf);
    }
    Ok(None)
}

/// Resolve a key name for `file` from the nearest config, if any rule matches.
pub fn key_for_file(file: &Path) -> Result<Option<String>> {
    let abs = file
        .canonicalize()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().join(file));
    let start = abs.parent().unwrap_or(Path::new("."));
    let Some((config, config_dir)) = discover(start)? else {
        return Ok(None);
    };
    let rel = abs.strip_prefix(&config_dir).unwrap_or(&abs).to_string_lossy().into_owned();
    let base = abs.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    for rule in &config.rules {
        for pattern in &rule.paths {
            if wildcard_match(pattern, &rel) || wildcard_match(pattern, &base) {
                return Ok(Some(rule.key.clone()));
            }
        }
    }
    Ok(config.default_key)
}

#[cfg(test)]
mod tests {
    use super::wildcard_match;

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*.mainnet.env", "app.mainnet.env"));
        assert!(!wildcard_match("*.mainnet.env", "deploy/app.mainnet.env")); // * stops at /
        assert!(wildcard_match("**/*.mainnet.env", "deploy/app.mainnet.env"));
        assert!(wildcard_match("deploy/prod/*", "deploy/prod/x.env"));
        assert!(!wildcard_match("deploy/prod/*", "deploy/prod/sub/x.env"));
        assert!(wildcard_match("deploy/**", "deploy/prod/sub/x.env"));
        assert!(wildcard_match(".env", ".env"));
        assert!(wildcard_match("?.env", "a.env"));
        assert!(!wildcard_match("?.env", "/.env"));
    }
}
