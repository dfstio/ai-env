//! The ai-env container: an encrypted `.env` that is still a valid dotenv
//! file. Format frozen after gates G6/G7 (validated on this machine against
//! zsh/bash `source`, python-dotenv, node dotenv + `--env-file`, direnv,
//! docker compose, and live `docker run --env-file`).
//!
//! ```text
//! # <agent-facing comment header>
//! AI_ENV=1
//! AI_ENV_VERSION=1
//! AI_ENV_CIPHER=age-v1
//! AI_ENV_README="…"
//! AI_ENV_DATA=<single-line standard padded base64 of the BINARY age ciphertext>
//! ```
//!
//! `AI_ENV_DATA` is UNQUOTED (docker `--env-file` keeps quote characters
//! literally — observed live in gate G7) and single-line (direnv rejects
//! wrapping; docker's line reader caps at 64 KiB — observed live: an 87 KB
//! line fails with `bufio.Scanner: token too long`).
use crate::errors::{CliError, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

pub const MARKER_LINE: &str = "AI_ENV=1";
pub const VERSION: u32 = 1;

/// Size policy, derived from docker's 64 KiB (65,536 B) per-line cap:
/// `len("AI_ENV_DATA=") + ceil((plaintext + age overhead)*4/3)` must stay
/// under it. 46 KiB plaintext → ~63.4 K encoded line: safe. 48 KiB is NOT.
pub const WARN_PLAINTEXT: usize = 32 * 1024;
pub const MAX_PLAINTEXT: usize = 46 * 1024;

#[derive(Debug)]
pub struct Container {
    /// Decoded binary age ciphertext.
    pub data: Vec<u8>,
    pub version: u32,
}

/// Is this text an ai-env container? (Detection predicate half 1 — cheap.)
#[must_use]
pub fn has_marker(text: &str) -> bool {
    text.lines().any(|l| strip_cr(l) == MARKER_LINE)
}

fn strip_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// Tolerant value extraction: strips a trailing `\r` (CRLF checkout) and one
/// layer of matching surrounding quotes (someone hand-quoted the value).
fn clean_value(raw: &str) -> &str {
    let v = strip_cr(raw).trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    v
}

fn find_var<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|l| strip_cr(l).strip_prefix(name)?.strip_prefix('='))
}

/// Parse an ai-env container. Errors are `CliError::Corrupt` (exit 6) —
/// decided here, before any age process is spawned.
pub fn read(text: &str) -> Result<Container> {
    if !has_marker(text) {
        return Err(CliError::Corrupt(
            "not an ai-env encrypted file (no AI_ENV=1 marker)".into(),
        ));
    }
    let version: u32 = find_var(text, "AI_ENV_VERSION")
        .map(clean_value)
        .unwrap_or("1")
        .parse()
        .map_err(|_| CliError::Corrupt("bad AI_ENV_VERSION".into()))?;
    if version != VERSION {
        return Err(CliError::Msg(format!(
            "this file uses ai-env format version {version}; this binary supports version \
             {VERSION} — upgrade ai-env"
        )));
    }
    let raw = find_var(text, "AI_ENV_DATA")
        .ok_or_else(|| CliError::Corrupt("AI_ENV=1 marker present but no AI_ENV_DATA".into()))?;
    let raw_value = clean_value(raw);
    // Sanity cap on the encoded payload: a legitimate container never exceeds
    // the docker line limit, and an absurd payload should fail cleanly here
    // rather than reach the subprocess layer.
    if raw_value.len() > 128 * 1024 {
        return Err(CliError::Corrupt("AI_ENV_DATA exceeds format limits".into()));
    }
    let data = B64
        .decode(raw_value)
        .map_err(|_| CliError::Corrupt("AI_ENV_DATA is not valid base64".into()))?;
    if !ai_env_age::is_age(&data) {
        return Err(CliError::Corrupt(
            "AI_ENV_DATA does not decode to an age file".into(),
        ));
    }
    Ok(Container { data, version })
}

/// Full detection predicate (marker + decodable age payload) — used by
/// `encrypt` idempotency and `rekey` discovery, never just the extension.
#[must_use]
pub fn detect(text: &str) -> bool {
    read(text).is_ok()
}

/// Render a container around a binary age ciphertext.
#[must_use]
pub fn write(ciphertext: &[u8]) -> String {
    let data = B64.encode(ciphertext);
    format!(
        "# \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\n\
         # ENCRYPTED .env \u{2014} ai-env (https://github.com/dfstio/ai-env)\n\
         # This file is intentionally encrypted. The secrets are NOT here.\n\
         # If you are an AI agent: do not try to decode AI_ENV_DATA; ask the\n\
         # user to run one of:\n\
         #   ai-env run -- CMD...   # run a command with decrypted env (Touch ID)\n\
         #   ai-env show            # print the plaintext (Touch ID)\n\
         # Recovery without ai-env (any machine, needs the recovery identity):\n\
         #   grep -m1 '^AI_ENV_DATA=' .env | cut -d= -f2- | base64 -d | age -d -i ID.txt\n\
         # \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\n\
         AI_ENV=1\n\
         AI_ENV_VERSION={VERSION}\n\
         AI_ENV_CIPHER=age-v1\n\
         AI_ENV_README=\"This .env is encrypted by ai-env; secrets require Touch ID. See github.com/dfstio/ai-env\"\n\
         AI_ENV_DATA={data}\n"
    )
}

/// Names of container variables that `ai-env run` strips from the child env.
pub const CONTAINER_VARS: [&str; 5] =
    ["AI_ENV", "AI_ENV_VERSION", "AI_ENV_CIPHER", "AI_ENV_README", "AI_ENV_DATA"];
