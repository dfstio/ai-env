//! Read-only tooling over the [age v1 format](https://age-encryption.org/v1)
//! for `ai-env`: parse the plaintext header of a **binary** age file and
//! decide — offline, without any decryption and without ever touching the
//! Secure Enclave — which locally-known recipient a file is addressed to.
//!
//! This works because `age-plugin-se` emits *tagged* recipient stanzas
//! (`p256tag`, `piv-p256`) that carry a 4-byte tag computable from the
//! recipient's **public** key alone. Native `X25519` stanzas are deliberately
//! unlabeled and are reported as [`StanzaKind::Other`].
//!
//! This crate performs no cryptography beyond SHA-256 / HKDF-Extract and does
//! no I/O; input is always an untrusted in-memory byte slice.
#![forbid(unsafe_code)]

mod header;
mod recipient;
mod tag;

pub use header::{is_age, parse, Header, ParseError, Stanza, StanzaKind, MAGIC_LINE};
pub use recipient::{decode_recipient, Recipient};
pub use tag::{match_recipients, p256tag_tag, piv_p256_tag, MatchResult, P256TAG_SALT};
