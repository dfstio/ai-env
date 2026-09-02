//! Parser for the plaintext header of a **binary** age file.
//!
//! Grammar (age v1):
//! ```text
//! age-encryption.org/v1\n
//! -> TYPE [ARG...]\n                 (one or more stanzas)
//! <body: base64 lines wrapped at exactly 64 cols,
//!  terminated by a line shorter than 64 (possibly empty)>\n
//! --- MAC\n
//! <binary payload>
//! ```
//!
//! Hardened against untrusted input: hard caps on header size, stanza count,
//! and per-stanza args/body; canonical unpadded base64 required for stanza
//! bodies and binary-carrying args; never panics.
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;

pub const MAGIC_LINE: &str = "age-encryption.org/v1";

/// Hard caps (matching the spirit of age 1.3.2's own header limits).
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_STANZAS: usize = 64;
pub const MAX_ARGS_PER_STANZA: usize = 16;
pub const MAX_BODY_LINES: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("not an age file (bad intro line)")]
    NotAge,
    #[error("age file uses CRLF line endings (corrupted by a text-mode transfer?)")]
    CrLf,
    #[error("age header is truncated")]
    Truncated,
    #[error("age header exceeds limits ({0})")]
    TooLarge(&'static str),
    #[error("malformed age header: {0}")]
    Malformed(&'static str),
}

/// The recipient stanza types ai-env understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StanzaKind {
    /// `p256tag` — tagged P-256 (age-plugin-se `age1tag1…` recipients).
    /// args: `[tag(4B b64), enc(65B b64)]`.
    P256Tag,
    /// `piv-p256` — tagged P-256 (YubiKey PIV / age-plugin-se `age1se1…`).
    /// args: `[tag(4B b64), enc(33B b64)]`.
    PivP256,
    /// `X25519` — native age recipients; deliberately unlabeled.
    X25519,
    /// `scrypt` — passphrase recipient.
    Scrypt,
    /// Anything else (future or third-party plugin stanzas).
    Other,
}

#[derive(Debug, Clone)]
pub struct Stanza {
    pub kind: StanzaKind,
    /// The literal stanza type string (e.g. "p256tag").
    pub type_name: String,
    /// Raw argument strings, as they appear after the type.
    pub args: Vec<String>,
}

impl Stanza {
    /// For tagged stanzas: the decoded 4-byte recipient tag (arg 0).
    #[must_use]
    pub fn tag4(&self) -> Option<[u8; 4]> {
        let arg = self.args.first()?;
        let bytes = decode_b64_exact(arg, 4)?;
        let mut out = [0u8; 4];
        out.copy_from_slice(&bytes);
        Some(out)
    }

    /// For `p256tag`: the decoded 65-byte ephemeral share (arg 1).
    #[must_use]
    pub fn enc65(&self) -> Option<Vec<u8>> {
        decode_b64_exact(self.args.get(1)?, 65)
    }
}

#[derive(Debug)]
pub struct Header {
    pub stanzas: Vec<Stanza>,
}

/// Cheap age-file predicate (binary format).
#[must_use]
pub fn is_age(data: &[u8]) -> bool {
    data.starts_with(MAGIC_LINE.as_bytes())
        && data.get(MAGIC_LINE.len()) == Some(&b'\n')
}

/// Canonical unpadded base64 decode that must yield exactly `want` bytes.
fn decode_b64_exact(s: &str, want: usize) -> Option<Vec<u8>> {
    let bytes = STANDARD_NO_PAD.decode(s).ok()?;
    (bytes.len() == want).then_some(bytes)
}

fn classify(type_name: &str) -> StanzaKind {
    match type_name {
        "p256tag" => StanzaKind::P256Tag,
        "piv-p256" => StanzaKind::PivP256,
        "X25519" => StanzaKind::X25519,
        "scrypt" => StanzaKind::Scrypt,
        _ => StanzaKind::Other,
    }
}

/// Iterate `\n`-terminated lines without allocating; rejects `\r`.
struct Lines<'a> {
    rest: &'a [u8],
    consumed: usize,
}

impl<'a> Lines<'a> {
    fn next_line(&mut self) -> Result<Option<&'a str>, ParseError> {
        if self.consumed > MAX_HEADER_BYTES {
            return Err(ParseError::TooLarge("header bytes"));
        }
        if self.rest.is_empty() {
            return Ok(None);
        }
        let nl = match self.rest.iter().position(|&b| b == b'\n') {
            Some(i) => i,
            None => return Err(ParseError::Truncated),
        };
        let line = &self.rest[..nl];
        self.rest = &self.rest[nl + 1..];
        self.consumed += nl + 1;
        if line.ends_with(b"\r") || line.contains(&b'\r') {
            return Err(ParseError::CrLf);
        }
        std::str::from_utf8(line)
            .map(Some)
            .map_err(|_| ParseError::Malformed("non-UTF-8 header line"))
    }
}

/// Parse the header of a binary age file. The payload after the MAC line is
/// ignored (and may be absent — a bare header parses fine).
pub fn parse(data: &[u8]) -> Result<Header, ParseError> {
    // Distinguish "not age at all" from "age but CRLF-mangled".
    if !data.starts_with(MAGIC_LINE.as_bytes()) {
        if data.starts_with(b"age-encryption.org/") {
            return Err(ParseError::Malformed("unsupported age version"));
        }
        return Err(ParseError::NotAge);
    }
    let after_magic = &data[MAGIC_LINE.len()..];
    if after_magic.starts_with(b"\r\n") {
        return Err(ParseError::CrLf);
    }
    if !after_magic.starts_with(b"\n") {
        return Err(ParseError::NotAge);
    }

    let mut lines = Lines { rest: &data[MAGIC_LINE.len() + 1..], consumed: 0 };
    let mut stanzas: Vec<Stanza> = Vec::new();

    loop {
        let line = lines.next_line()?.ok_or(ParseError::Truncated)?;

        if let Some(mac) = line.strip_prefix("--- ") {
            if stanzas.is_empty() {
                return Err(ParseError::Malformed("no stanzas before MAC"));
            }
            if decode_b64_exact(mac, 32).is_none() {
                return Err(ParseError::Malformed("bad MAC encoding"));
            }
            return Ok(Header { stanzas });
        }

        let Some(stanza_line) = line.strip_prefix("-> ") else {
            return Err(ParseError::Malformed("expected stanza or MAC line"));
        };
        if stanzas.len() >= MAX_STANZAS {
            return Err(ParseError::TooLarge("stanza count"));
        }

        let mut parts = stanza_line.split(' ');
        let type_name = parts.next().unwrap_or_default();
        if type_name.is_empty()
            || !type_name.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(ParseError::Malformed("invalid stanza type"));
        }
        let args: Vec<String> = parts.map(str::to_owned).collect();
        if args.len() > MAX_ARGS_PER_STANZA {
            return Err(ParseError::TooLarge("stanza args"));
        }
        if args.iter().any(|a| {
            a.is_empty() || !a.bytes().all(|b| (0x21..=0x7e).contains(&b))
        }) {
            return Err(ParseError::Malformed("invalid stanza argument"));
        }

        // Body: 64-col base64 lines; a line shorter than 64 ends the body.
        let mut body_lines = 0usize;
        loop {
            let body = lines.next_line()?.ok_or(ParseError::Truncated)?;
            body_lines += 1;
            if body_lines > MAX_BODY_LINES {
                return Err(ParseError::TooLarge("stanza body"));
            }
            if body.len() > 64 {
                return Err(ParseError::Malformed("stanza body line over 64 columns"));
            }
            if STANDARD_NO_PAD.decode(body).is_err() {
                return Err(ParseError::Malformed("stanza body is not canonical base64"));
            }
            if body.len() < 64 {
                break;
            }
        }

        stanzas.push(Stanza { kind: classify(type_name), type_name: type_name.to_owned(), args });
    }
}
