//! W/M's token (WM-R5, WM-R6), verified through ai-env-worker (R-51 to R-54). The relay holds no second token
//! parser (Q-R2): it adds the header and freshness steps around `session::verify`, and verifies on every request,
//! with no cache (R-53).

use crate::lists::Signers;

pub use ai_env_worker::session::{SessionClaims, SessionError, SESSION_AUD};

/// The metadata key of the session token: `x-ai-env-session` (ai-env-source's `wire`, review A-M13).
pub const SESSION_HEADER: &str = ai_env_source::wire::SESSION_HEADER;

/// Why a private-face request was refused: for the relay's own log (the caller sees UNAUTHENTICATED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFault {
    /// No header, or more than one value.
    Missing,
    /// The token signers are not loaded, or stale.
    NotLoaded,
    /// The token was refused.
    Token(SessionError),
}

impl SessionFault {
    /// The call line's detail word for the relay's own log (R-53).
    pub fn word(&self) -> &'static str {
        match self {
            SessionFault::Missing => "missing",
            SessionFault::NotLoaded => "not_loaded",
            SessionFault::Token(e) => match e {
                SessionError::Malformed(_) => "malformed",
                SessionError::UnknownSigner => "unknown_signer",
                SessionError::SignerExpired => "signer_expired",
                SessionError::BadSignature => "bad_signature",
                SessionError::NotYetValid => "not_yet_valid",
                SessionError::Expired => "expired",
                SessionError::TooLong => "too_long",
                SessionError::BadClaim(_) => "bad_claim",
            },
        }
    }
}

/// R-51 to R-53: exactly one header value, the token-signers loaded and fresh, then
/// `ai_env_worker::session::verify(token, now, &|kid| signers.key(kid))`.
pub fn verify_request(values: &[&str], signers: Option<&Signers>, now_unix: u64) -> Result<SessionClaims, SessionFault> {
    let [token] = values else {
        return Err(SessionFault::Missing);
    };
    let signers = signers.ok_or(SessionFault::NotLoaded)?;
    ai_env_worker::session::verify(token, now_unix, &|kid| signers.key(kid)).map(|v| v.claims).map_err(SessionFault::Token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_env_worker::keys::SigningKey;
    use ai_env_worker::policy::{self, SignerEntry};
    use ai_env_worker::session;

    const IAT: u64 = 1_800_000_000;

    /// WM-T6's claims.
    fn claims() -> SessionClaims {
        SessionClaims {
            kid: "mac".into(),
            aud: SESSION_AUD.into(),
            caller_id: "mac".into(),
            session_id: "0199a1b2-0000-7000-8000-000000000002".into(),
            chat_id: None,
            grant_id: "default".into(),
            vm_id: "microvm-0199a1b2-0000-7000-8000-000000000001".into(),
            iat: IAT,
            exp: IAT + 28_800,
        }
    }

    fn signer(id: &str, seed: u8, not_after: &str) -> SignerEntry {
        SignerEntry { signer_id: id.into(), alg: "ed25519".into(), public_key: SigningKey::from_seed(&[seed; 32]).unwrap().public_key().b64(), not_after: not_after.into() }
    }

    fn signers(entries: Vec<SignerEntry>) -> Signers {
        crate::lists::parse_signers(policy::render_signers(&entries).unwrap().as_bytes()).unwrap()
    }

    fn mint(seed: u8, c: &SessionClaims) -> String {
        session::mint(&SigningKey::from_seed(&[seed; 32]).unwrap(), c, c.iat).unwrap()
    }

    /// Unit 10.
    #[test]
    fn the_shared_token_verifies_through_the_relay() {
        let s = signers(vec![signer("mac", 7, "2027-12-31T23:59:59Z")]);
        let token = mint(7, &claims());
        let got = verify_request(&[&token], Some(&s), IAT + 10).expect("W/M's token verifies");
        assert_eq!(got, claims());
        let direct = session::verify(&token, IAT + 10, &|kid| s.key(kid)).unwrap();
        assert_eq!(direct.claims, got);
    }

    /// Unit 11.
    #[test]
    fn each_token_fault_is_one_fault() {
        let s = signers(vec![signer("mac", 7, "2027-12-31T23:59:59Z")]);
        let token = mint(7, &claims());
        let now = IAT + 10;
        assert_eq!(verify_request(&[], Some(&s), now), Err(SessionFault::Missing));
        assert_eq!(verify_request(&[&token, &token], Some(&s), now), Err(SessionFault::Missing), "never the first of two");
        assert_eq!(verify_request(&[&token], None, now), Err(SessionFault::NotLoaded));
        // Stale signers reach the verifier as None (`Watched::fresh`).
        let dir = tempfile::tempdir().unwrap();
        let watched: crate::files::Watched<Signers> = crate::files::Watched::new(dir.path().join(crate::lists::SIGNERS_FILE));
        std::fs::write(dir.path().join(crate::lists::SIGNERS_FILE), policy::render_signers(&s.entries).unwrap()).unwrap();
        let fetched = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now);
        watched.poll(Some(fetched), crate::lists::parse_signers);
        let stale = watched.fresh(fetched + std::time::Duration::from_secs(901), std::time::Duration::from_secs(900));
        assert_eq!(verify_request(&[&token], stale.as_deref(), now), Err(SessionFault::NotLoaded));

        assert_eq!(verify_request(&[&mint(4, &claims())], Some(&s), now), Err(SessionFault::Token(SessionError::BadSignature)));
        let other_kid = SessionClaims { kid: "mac-9".into(), ..claims() };
        assert_eq!(verify_request(&[&mint(7, &other_kid)], Some(&s), now), Err(SessionFault::Token(SessionError::UnknownSigner)));
        assert_eq!(verify_request(&[&token], Some(&s), IAT + 28_800), Err(SessionFault::Token(SessionError::Expired)));
        // `aud` changed after signing: the signature no longer covers the claims.
        let changed = {
            let claims_b64 = token.split('.').nth(1).unwrap();
            let json = String::from_utf8(b64url_decode(claims_b64)).unwrap().replace("ai-env-relay", "ai-env-other");
            token.replace(claims_b64, &b64url_encode(json.as_bytes()))
        };
        assert_eq!(verify_request(&[&changed], Some(&s), now), Err(SessionFault::Token(SessionError::BadSignature)));

        let words: Vec<&str> = [
            SessionFault::Missing,
            SessionFault::NotLoaded,
            SessionFault::Token(SessionError::Malformed("x")),
            SessionFault::Token(SessionError::UnknownSigner),
            SessionFault::Token(SessionError::SignerExpired),
            SessionFault::Token(SessionError::BadSignature),
            SessionFault::Token(SessionError::NotYetValid),
            SessionFault::Token(SessionError::Expired),
            SessionFault::Token(SessionError::TooLong),
            SessionFault::Token(SessionError::BadClaim("y")),
        ]
        .iter()
        .map(SessionFault::word)
        .collect();
        assert!(words.iter().all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')), "{words:?}");
        assert_eq!(words.iter().collect::<std::collections::BTreeSet<_>>().len(), words.len());
    }

    /// Unit 12.
    #[test]
    fn a_removed_or_lapsed_signer_refuses_its_tokens() {
        let token = mint(7, &claims());
        let without = signers(vec![signer("mac-2", 8, "2027-12-31T23:59:59Z")]);
        assert_eq!(verify_request(&[&token], Some(&without), IAT + 10), Err(SessionFault::Token(SessionError::UnknownSigner)));
        let lapsed = signers(vec![signer("mac", 7, "2027-01-15T07:00:00Z")]);
        assert!(policy::unix_of("2027-01-15T07:00:00Z").unwrap() < IAT + 10);
        assert_eq!(verify_request(&[&token], Some(&lapsed), IAT + 10), Err(SessionFault::Token(SessionError::SignerExpired)));
    }

    const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn b64url_encode(bytes: &[u8]) -> String {
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..=c.len() {
                out.push(B64URL[(n >> (18 - 6 * i)) as usize & 63] as char);
            }
        }
        out
    }

    fn b64url_decode(s: &str) -> Vec<u8> {
        let vals: Vec<u32> = s.bytes().map(|b| B64URL.iter().position(|x| *x == b).unwrap() as u32).collect();
        let mut out = Vec::new();
        for c in vals.chunks(4) {
            let n = c.iter().enumerate().fold(0u32, |acc, (i, v)| acc | (v << (18 - 6 * i)));
            for i in 0..c.len() - 1 {
                out.push((n >> (16 - 8 * i)) as u8);
            }
        }
        out
    }
}
