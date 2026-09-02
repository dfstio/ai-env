//! The load-bearing 60 lines: recipient-tag derivations and the matcher.
//!
//! Derivations frozen by a known-answer test against a REAL age-produced file
//! (tests/vectors.rs) — do not touch without re-running it. The critical trap
//! this guards: Go's `hkdf.Extract(h, secret, salt)` argument order is the
//! REVERSE of RFC 5869 naming; the verified-correct mapping to Rust is
//! `Hkdf::<Sha256>::extract(Some(salt), ikm)`.
use crate::header::{Header, StanzaKind};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// HKDF-Extract salt for the `p256tag` derivation (C2SP age spec).
pub const P256TAG_SALT: &[u8] = b"age-encryption.org/p256tag";

/// `p256tag` stanza tag: per-file (bound to the ephemeral share `enc`), so
/// tags are unlinkable across files while computable by the key holder.
///
/// `tag = HKDF-Extract-SHA256(salt, enc(65B) ‖ SHA256(recip33)[..4])[..4]`
#[must_use]
pub fn p256tag_tag(enc65: &[u8], recip33: &[u8; 33]) -> [u8; 4] {
    let recip_hash = Sha256::digest(recip33);
    let mut ikm = Vec::with_capacity(enc65.len() + 4);
    ikm.extend_from_slice(enc65);
    ikm.extend_from_slice(&recip_hash[..4]);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(P256TAG_SALT), &ikm);
    let mut out = [0u8; 4];
    out.copy_from_slice(&prk[..4]);
    out
}

/// `piv-p256` stanza tag (legacy `age1se1…` recipients): static per recipient.
///
/// `tag = SHA256(recip33)[..4]`
#[must_use]
pub fn piv_p256_tag(recip33: &[u8; 33]) -> [u8; 4] {
    let digest = Sha256::digest(recip33);
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest[..4]);
    out
}

/// Which candidate recipient(s) a parsed header is addressed to.
#[derive(Debug, PartialEq, Eq)]
pub enum MatchResult {
    /// Exactly one candidate matched (index into the candidates slice).
    One(usize),
    /// No tagged stanza matched any candidate.
    None,
    /// More than one distinct candidate matched (indices).
    Ambiguous(Vec<usize>),
}

/// Match a header's tagged stanzas against candidate compressed P-256 points.
///
/// Pure computation over PUBLIC data: no decryption, no prompt, no enclave.
/// `X25519`/`scrypt`/unknown stanzas are ignored (they carry no tag).
#[must_use]
pub fn match_recipients(header: &Header, candidates: &[[u8; 33]]) -> MatchResult {
    let mut matched: Vec<usize> = Vec::new();
    // Distinct by RECIPIENT VALUE, not index: the same public key listed twice
    // in `candidates` is one recipient, not an ambiguity.
    let mut push = |i: usize, candidates: &[[u8; 33]]| {
        if !matched.iter().any(|&j| candidates[j] == candidates[i]) {
            matched.push(i);
        }
    };
    for stanza in &header.stanzas {
        let Some(tag) = stanza.tag4() else { continue };
        match stanza.kind {
            StanzaKind::P256Tag => {
                let Some(enc) = stanza.enc65() else { continue };
                for (i, cand) in candidates.iter().enumerate() {
                    if p256tag_tag(&enc, cand) == tag {
                        push(i, candidates);
                    }
                }
            }
            StanzaKind::PivP256 => {
                for (i, cand) in candidates.iter().enumerate() {
                    if piv_p256_tag(cand) == tag {
                        push(i, candidates);
                    }
                }
            }
            _ => {}
        }
    }
    match matched.len() {
        0 => MatchResult::None,
        1 => MatchResult::One(matched[0]),
        _ => MatchResult::Ambiguous(matched),
    }
}
