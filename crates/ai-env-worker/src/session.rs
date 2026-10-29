//! The VM session token (WM-R5, WM-R6): minted by the Mac's agent, verified by the relay.
//!
//! `token = "v1." ‖ b64url(claims) ‖ "." ‖ b64url(signature)`: the claims are the exact bytes
//! `serde_json::to_vec(&SessionClaims)` wrote, and the verifier parses the very bytes that were signed, so no
//! canonical JSON is needed.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::globs::{valid_id, valid_uuid, valid_vm_id};
use crate::keys::SIGNATURE_LEN;

/// The signing input's domain.
pub const SESSION_DOMAIN: &[u8] = b"ai-env/relay/session/v1";
/// Every token starts with it.
pub const TOKEN_PREFIX: &str = "v1.";
/// The `aud` claim.
pub const SESSION_AUD: &str = "ai-env-relay";
/// The longest session: 8 h.
pub const SESSION_MAX_S: u64 = 28_800;
/// The clock skew allowed on `iat`.
pub const SESSION_SKEW_S: u64 = 300;
/// The longest token.
pub const TOKEN_MAX: usize = 2048;
/// The longest claims JSON.
pub const CLAIMS_MAX: usize = 1024;

/// The token's claims, serialized in this field order (`chat_id` left out when `None`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionClaims {
    /// The token signer's id.
    pub kid: String,
    /// `SESSION_AUD`.
    pub aud: String,
    /// The caller's id.
    pub caller_id: String,
    /// The spawn's id (a uuid, LD-WM4).
    pub session_id: String,
    /// The Claude session id of a resumed or moved chat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<String>,
    /// The grant.
    pub grant_id: String,
    /// The VM's id.
    pub vm_id: String,
    /// Issued at, unix seconds.
    pub iat: u64,
    /// Expires at, unix seconds.
    pub exp: u64,
}

/// A token signer's key and its `not_after`, as `verify` looks it up.
pub struct SignerKey {
    /// The key.
    pub public_key: crate::keys::PublicKey,
    /// Unix seconds.
    pub not_after: u64,
}

/// A token that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSession {
    /// Its claims.
    pub claims: SessionClaims,
}

/// `lp(SESSION_DOMAIN) ‖ lp(claims)`.
pub fn signing_input(claims_json: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + SESSION_DOMAIN.len() + claims_json.len());
    for field in [SESSION_DOMAIN, claims_json] {
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// `v1.` ‖ b64url(claims) ‖ `.` ‖ b64url(signature); refuses what `verify` would (WM-R5).
pub fn mint(key: &crate::keys::SigningKey, claims: &SessionClaims, now: u64) -> Result<String, SessionError> {
    check_claims(claims, now)?;
    let json = serde_json::to_vec(claims).map_err(|_| SessionError::Malformed("claims"))?;
    if json.len() > CLAIMS_MAX {
        return Err(SessionError::Malformed("claims over 1024 bytes"));
    }
    let signature = key.sign(&signing_input(&json));
    let token = format!("{TOKEN_PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(&json), URL_SAFE_NO_PAD.encode(signature));
    if token.len() > TOKEN_MAX {
        return Err(SessionError::Malformed("token over 2048 bytes"));
    }
    Ok(token)
}

/// WM-R6's checks, in order.
pub fn verify(token: &str, now: u64, signer: &dyn Fn(&str) -> Option<SignerKey>) -> Result<VerifiedSession, SessionError> {
    let shape = parse(token)?;
    let key = signer(&shape.claims.kid).ok_or(SessionError::UnknownSigner)?;
    if now > key.not_after {
        return Err(SessionError::SignerExpired);
    }
    if !key.public_key.verify(&signing_input(&shape.json), &shape.signature) {
        return Err(SessionError::BadSignature);
    }
    check_claims(&shape.claims, now)?;
    Ok(VerifiedSession { claims: shape.claims })
}

/// The claims unverified: for display only.
pub fn peek(token: &str) -> Result<SessionClaims, SessionError> {
    parse(token).map(|shape| shape.claims)
}

/// A token's parts, its signature not checked yet.
struct Shape {
    json: Vec<u8>,
    claims: SessionClaims,
    signature: Vec<u8>,
}

/// WM-R6's shape steps: at most 2048 ASCII bytes, `v1.`, two `b64url` segments (no padding), claims of at
/// most 1024 bytes that parse (unknown fields refused), a 64-byte signature.
fn parse(token: &str) -> Result<Shape, SessionError> {
    if token.len() > TOKEN_MAX || !token.is_ascii() {
        return Err(SessionError::Malformed("not a token of at most 2048 ASCII bytes"));
    }
    let rest = token.strip_prefix(TOKEN_PREFIX).ok_or(SessionError::Malformed("not v1."))?;
    let (claims, signature) = rest.split_once('.').ok_or(SessionError::Malformed("not three segments"))?;
    if claims.is_empty() || signature.is_empty() || signature.contains('.') {
        return Err(SessionError::Malformed("not three segments"));
    }
    let json = URL_SAFE_NO_PAD.decode(claims).map_err(|_| SessionError::Malformed("claims not base64url"))?;
    if json.len() > CLAIMS_MAX {
        return Err(SessionError::Malformed("claims over 1024 bytes"));
    }
    let parsed: SessionClaims = serde_json::from_slice(&json).map_err(|_| SessionError::Malformed("claims"))?;
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| SessionError::Malformed("signature not base64url"))?;
    if signature.len() != SIGNATURE_LEN {
        return Err(SessionError::Malformed("signature not 64 bytes"));
    }
    Ok(Shape { json, claims: parsed, signature })
}

/// WM-R6's claim steps after the signature: `aud`, the ids, then the times.
fn check_claims(c: &SessionClaims, now: u64) -> Result<(), SessionError> {
    if c.aud != SESSION_AUD {
        return Err(SessionError::BadClaim("aud"));
    }
    for (name, value) in [("kid", &c.kid), ("caller_id", &c.caller_id), ("grant_id", &c.grant_id)] {
        if !valid_id(value) {
            return Err(SessionError::BadClaim(name));
        }
    }
    if !valid_uuid(&c.session_id) {
        return Err(SessionError::BadClaim("session_id"));
    }
    if c.chat_id.as_deref().is_some_and(|chat| !valid_uuid(chat)) {
        return Err(SessionError::BadClaim("chat_id"));
    }
    if !valid_vm_id(&c.vm_id) {
        return Err(SessionError::BadClaim("vm_id"));
    }
    if c.iat > now.saturating_add(SESSION_SKEW_S) {
        return Err(SessionError::NotYetValid);
    }
    if c.exp <= now {
        return Err(SessionError::Expired);
    }
    if c.iat >= c.exp || c.exp - c.iat > SESSION_MAX_S {
        return Err(SessionError::TooLong);
    }
    Ok(())
}

/// Why a token was refused: for the relay's log (the caller sees a generic `UNAUTHENTICATED`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// Not a token's shape.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// `kid` names no token signer.
    #[error("unknown signer")]
    UnknownSigner,
    /// The signer's `not_after` passed.
    #[error("signer expired")]
    SignerExpired,
    /// The signature does not verify.
    #[error("bad signature")]
    BadSignature,
    /// `iat` is in the future beyond the skew.
    #[error("not yet valid")]
    NotYetValid,
    /// `exp` passed.
    #[error("expired")]
    Expired,
    /// Longer than `SESSION_MAX_S`.
    #[error("too long")]
    TooLong,
    /// A claim out of its grammar.
    #[error("bad claim: {0}")]
    BadClaim(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;

    fn sha256(bytes: &[u8]) -> String {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn claims() -> SessionClaims {
        SessionClaims {
            kid: "mac".into(),
            aud: SESSION_AUD.into(),
            caller_id: "mac".into(),
            session_id: "0199a1b2-0000-7000-8000-000000000002".into(),
            chat_id: None,
            grant_id: "default".into(),
            vm_id: "microvm-0199a1b2-0000-7000-8000-000000000001".into(),
            iat: 1_800_000_000,
            exp: 1_800_028_800,
        }
    }

    fn seven() -> SigningKey {
        SigningKey::from_seed(&[7u8; 32]).expect("seed")
    }

    /// The seed-7 key, in force until `not_after`, as the only signer `mac`.
    fn signers(not_after: u64) -> impl Fn(&str) -> Option<SignerKey> {
        let public_key = seven().public_key();
        move |kid: &str| (kid == "mac").then_some(SignerKey { public_key, not_after })
    }

    /// A token of these exact claim bytes, signed by `key`: what `mint` would refuse to make.
    fn token_of(key: &SigningKey, json: &[u8]) -> String {
        format!("{TOKEN_PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(json), URL_SAFE_NO_PAD.encode(key.sign(&signing_input(json))))
    }

    const NOW: u64 = 1_800_000_100;

    /// WM-T6.
    #[test]
    fn a_token_mints_and_verifies_and_its_bytes_are_frozen() {
        let c = claims();
        let json = serde_json::to_vec(&c).expect("json");
        assert_eq!(json.len(), 214);
        let input = signing_input(&json);
        assert_eq!(input.len(), 245);
        assert_eq!(sha256(&input), "716168ddcab654a6e2d307425f937ab4c7ed9ebb0eac55d1738a8cc2cd8fdb7e");
        let token = mint(&seven(), &c, NOW).expect("minted");
        assert_eq!(token.len(), 376);
        assert!(token.starts_with("v1.eyJraWQiOiJt"), "{}", &token[..16]);
        assert_eq!(sha256(token.as_bytes()), "6868a87572a53687730ed1745343e7e2ffcf04b049f1b63119f0a905eb8ee85e");

        let mut chat = claims();
        chat.chat_id = Some("0199a1b2-0000-4000-8000-000000000003".into());
        assert_eq!(serde_json::to_vec(&chat).expect("json").len(), 263);
        let chat_token = mint(&seven(), &chat, NOW).expect("minted");
        assert_eq!(chat_token.len(), 441);
        assert_eq!(sha256(chat_token.as_bytes()), "482627e5ae1f59083a24da25c8b5f2f5b32e31df59b24cf39fecde6a148887e7");

        let verified = verify(&token, NOW, &signers(u64::MAX)).expect("verifies");
        assert_eq!(verified.claims, c);
        assert_eq!(verify(&chat_token, NOW, &signers(u64::MAX)).expect("verifies").claims, chat);
        assert_eq!(peek(&token).expect("peeks"), c);
    }

    /// WM-T7.
    #[test]
    fn verify_refuses_every_bad_token() {
        let key = seven();
        let good = mint(&key, &claims(), NOW).expect("minted");
        let in_force = signers(u64::MAX);
        let check = |token: &str, now: u64| verify(token, now, &in_force);
        let malformed = |r: Result<VerifiedSession, SessionError>| matches!(r, Err(SessionError::Malformed(_)));
        let json = serde_json::to_vec(&claims()).expect("json");
        let with = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v: serde_json::Value = serde_json::from_slice(&json).expect("json");
            f(&mut v);
            token_of(&key, &serde_json::to_vec(&v).expect("json"))
        };

        let (claims_part, sig_part) = good[3..].split_once('.').expect("two parts");
        let mut changed = URL_SAFE_NO_PAD.decode(claims_part).expect("b64");
        // The last digit of `iat`: still the claims' shape, no longer the signed bytes.
        let at = changed.windows(16).position(|w| w == b"\"iat\":1800000000").expect("iat") + 15;
        changed[at] = b'1';
        let one_claim_byte = format!("v1.{}.{sig_part}", URL_SAFE_NO_PAD.encode(&changed));
        assert_eq!(check(&one_claim_byte, NOW), Err(SessionError::BadSignature));
        let mut sig = URL_SAFE_NO_PAD.decode(sig_part).expect("b64");
        sig[0] ^= 0x01;
        let one_sig_byte = format!("v1.{claims_part}.{}", URL_SAFE_NO_PAD.encode(&sig));
        assert_eq!(check(&one_sig_byte, NOW), Err(SessionError::BadSignature));
        let other_key = SigningKey::from_seed(&[1u8; 32]).expect("seed");
        assert_eq!(check(&token_of(&other_key, &json), NOW), Err(SessionError::BadSignature));
        assert_eq!(check(&with(&|v| v["kid"] = "other".into()), NOW), Err(SessionError::UnknownSigner));
        assert_eq!(verify(&good, NOW, &signers(NOW - 1)), Err(SessionError::SignerExpired));
        assert!(verify(&good, NOW, &signers(NOW)).is_ok(), "in force through its not_after");
        assert_eq!(check(&good, claims().exp), Err(SessionError::Expired));
        assert_eq!(check(&with(&|v| v["iat"] = (NOW + 301).into()), NOW), Err(SessionError::NotYetValid));
        assert!(check(&with(&|v| v["iat"] = (NOW + 300).into()), NOW).is_ok(), "the skew");
        let iat = claims().iat;
        assert_eq!(check(&with(&|v| v["exp"] = (iat + 28_801).into()), NOW), Err(SessionError::TooLong));
        assert_eq!(check(&with(&|v| v["aud"] = "relay-test".into()), NOW), Err(SessionError::BadClaim("aud")));
        assert!(malformed(check(&with(&|v| v["extra"] = 1.into()), NOW)), "an extra claim");
        assert!(malformed(check(&format!("v2.{}", &good[3..]), NOW)), "v2.");
        assert!(malformed(check(&format!("v1.{claims_part}"), NOW)), "two segments");
        assert!(malformed(check(&format!("{good}.x"), NOW)), "four segments");
        assert!(malformed(check(&format!("v1.{claims_part}==.{sig_part}"), NOW)), "padding");
        assert!(malformed(check(&format!("{good}{}", "A".repeat(2049 - good.len())), NOW)), "2049 bytes");
        let big = with(&|v| v["vm_id"] = "a".repeat(855).into());
        assert_eq!(URL_SAFE_NO_PAD.decode(big[3..].split_once('.').expect("parts").0).expect("b64").len(), 1025);
        assert!(malformed(check(&big, NOW)), "claims of 1025 bytes");
        let short = format!("v1.{claims_part}.{}", URL_SAFE_NO_PAD.encode(&sig[..63]));
        assert!(malformed(check(&short, NOW)), "a 63-byte signature");
        assert_eq!(check(&with(&|v| v["vm_id"] = "pending-x".into()), NOW), Err(SessionError::BadClaim("vm_id")));
        assert_eq!(check(&with(&|v| v["grant_id"] = "A".into()), NOW), Err(SessionError::BadClaim("grant_id")));
        assert_eq!(check(&with(&|v| v["session_id"] = "not-a-uuid".into()), NOW), Err(SessionError::BadClaim("session_id")));
        assert_eq!(check(&with(&|v| v["chat_id"] = "x".into()), NOW), Err(SessionError::BadClaim("chat_id")));

        // mint refuses the same claims before it signs.
        let bad = |f: &dyn Fn(&mut SessionClaims)| {
            let mut c = claims();
            f(&mut c);
            mint(&key, &c, NOW)
        };
        assert_eq!(bad(&|c| c.aud = "relay-test".into()), Err(SessionError::BadClaim("aud")));
        assert_eq!(bad(&|c| c.vm_id = "pending-x".into()), Err(SessionError::BadClaim("vm_id")));
        assert_eq!(bad(&|c| c.grant_id = "A".into()), Err(SessionError::BadClaim("grant_id")));
        assert_eq!(bad(&|c| c.session_id = "x".into()), Err(SessionError::BadClaim("session_id")));
        assert_eq!(bad(&|c| c.exp = c.iat + 28_801), Err(SessionError::TooLong));
        assert_eq!(bad(&|c| c.iat = NOW + 301), Err(SessionError::NotYetValid));
        assert_eq!(bad(&|c| c.exp = NOW), Err(SessionError::Expired));
        assert!(bad(&|c| c.vm_id = "a".repeat(128)).is_ok(), "a 128-character VM id");
    }
}
