//! The relay protocol's constants and the bytes a worker signs (plans/s13-contracts.md §P-proto-sdk.5.2,
//! 5.3). They live here, not in ai-env-relay-proto, so the proto crate stays the lead's generated code alone
//! (review A-M13): the worker, the relay, the Mac's signing agent and the VM client all reach this crate.

use crate::{ContentType, DEADLINE_CEILING, DEADLINE_DEFAULT};

/// The most bytes of one chunk's `data` (P-R18).
pub const CHUNK_MAX: usize = 65_536;
/// The most bytes of `params_json` (P-R12, P-R21).
pub const PARAMS_MAX: usize = 65_536;
/// The most bytes of one encoded `WorkerFrame`, the `Catalog`'s included: what the relay decodes, and what
/// a worker checks its catalog against at build (review A-M2).
pub const FRAME_MAX: usize = 262_144;
/// `Challenge.nonce`'s length (P-R6).
pub const NONCE_LEN: usize = 32;
/// An Ed25519 public key's length (P-R7).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// An Ed25519 signature's length (P-R8).
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// The private face's metadata key for the session token (P-R20).
pub const SESSION_HEADER: &str = "x-ai-env-session";
/// The private face's response metadata key for the relay's id of a call (review A-L11).
pub const REQUEST_ID_HEADER: &str = "x-ai-env-request-id";
/// The content type of a JSON output's chunks (P-R18).
pub const CONTENT_JSON: &str = ContentType::Json.as_str();
/// The content type of an NDJSON stream's chunks (P-R18).
pub const CONTENT_NDJSON: &str = ContentType::Ndjson.as_str();
/// The content type of a text output's or a line stream's chunks (P-R18).
pub const CONTENT_TEXT: &str = ContentType::Text.as_str();
/// `CallRequest.deadline_ms` 0 means this (P-R21).
pub const DEADLINE_DEFAULT_MS: u32 = DEADLINE_DEFAULT.as_millis() as u32;
/// A larger `CallRequest.deadline_ms` is clamped to this (P-R21).
pub const DEADLINE_MAX_MS: u32 = DEADLINE_CEILING.as_millis() as u32;

/// `Close.code` (P-R16): 0 to 4 are P's, 5 and 6 the relay's (review A-L2, R-27).
pub mod close {
    /// The relay stops or drains.
    pub const NORMAL: u32 = 0;
    /// The key left the whitelist or expired.
    pub const REVOKED: u32 = 1;
    /// A newer tunnel of the same `worker_id` took over.
    pub const SUPERSEDED: u32 = 2;
    /// A frame broke the protocol's rules.
    pub const PROTOCOL: u32 = 3;
    /// A source outside the entry's globs, or a name another live worker serves.
    pub const CATALOG_REFUSED: u32 = 4;
    /// No frame from the worker within the relay's ping budget.
    pub const PING_TIMEOUT: u32 = 5;
    /// The relay's whitelist went stale (it fails closed).
    pub const STALE: u32 = 6;
}

/// `Cancel.reason` tokens (P-R14, review A-L2): never a credential or a parameter.
pub mod cancel {
    /// The caller went away.
    pub const CALLER_GONE: &str = "caller_gone";
    /// The call's deadline passed.
    pub const DEADLINE: &str = "deadline";
    /// The call passed its byte cap.
    pub const BYTE_CAP: &str = "byte_cap";
    /// The call passed its chunk cap.
    pub const CHUNK_CAP: &str = "chunk_cap";
    /// The caller did not take the chunks in time.
    pub const CALLER_TOO_SLOW: &str = "caller_too_slow";
    /// The worker broke the chunk rules.
    pub const PROTOCOL: &str = "protocol";
    /// The relay is shutting down.
    pub const SHUTDOWN: &str = "shutdown";
}

/// The transcript's domain, 27 bytes.
pub const DOMAIN: &[u8] = b"ai-env/relay/worker-auth/v1";

/// The bytes a worker signs and the relay verifies (P-R25): `field(DOMAIN) ‖ field(relay_id) ‖ field(nonce) ‖
/// field(worker_id) ‖ field(alg as 4 big-endian bytes) ‖ field(public_key) ‖ field(protocol as 4 big-endian
/// bytes)`, where `field(b)` is `b`'s length as a 4-byte big-endian u32, then `b`. `alg` is the proto's `SigAlg`
/// number (`SIG_ALG_ED25519` is 1). It validates nothing: the callers check lengths and names first.
#[must_use]
pub fn transcript(relay_id: &str, nonce: &[u8], worker_id: &str, alg: u32, public_key: &[u8], protocol: u32) -> Vec<u8> {
    let alg = alg.to_be_bytes();
    let protocol = protocol.to_be_bytes();
    let fields: [&[u8]; 7] = [DOMAIN, relay_id.as_bytes(), nonce, worker_id.as_bytes(), &alg, public_key, &protocol];
    let mut out = Vec::with_capacity(fields.iter().map(|f| 4 + f.len()).sum());
    for f in fields {
        let len = u32::try_from(f.len()).expect("a transcript field is under 4 GiB");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// P-T1.
    #[test]
    fn the_transcript_is_length_prefixed_and_domain_separated() {
        let t = transcript("relay-test", &[7; 32], "w1", 1, &[1; 32], 1);
        let expected = [
            "0000001b61692d656e762f72656c61792f776f726b65722d617574682f76310000000a72656c61792d7465737400000020".to_string(),
            "07".repeat(32),
            "000000027731".to_string(),
            "00000004".to_string(),
            "00000001".to_string(),
            "00000020".to_string(),
            "01".repeat(32),
            "00000004".to_string(),
            "00000001".to_string(),
        ]
        .concat();
        assert_eq!(t.len(), 139);
        assert_eq!(hex(&t), expected);
        assert_eq!(DOMAIN.len(), 27);
        assert_ne!(transcript("ab", &[7; 32], "c", 1, &[1; 32], 1), transcript("a", &[7; 32], "bc", 1, &[1; 32], 1));
        // Without the prefixes these two concatenate to the same bytes (M-P1): the name's last byte moves into the nonce.
        let shifted: Vec<u8> = std::iter::once(b'b').chain([7; 32]).collect();
        assert_ne!(transcript("ab", &[7; 32], "c", 1, &[1; 32], 1), transcript("a", &shifted, "c", 1, &[1; 32], 1));
        let base = transcript("r", &[7; 32], "w", 1, &[1; 32], 1);
        for changed in [
            transcript("s", &[7; 32], "w", 1, &[1; 32], 1),
            transcript("r", &[8; 32], "w", 1, &[1; 32], 1),
            transcript("r", &[7; 32], "x", 1, &[1; 32], 1),
            transcript("r", &[7; 32], "w", 2, &[1; 32], 1),
            transcript("r", &[7; 32], "w", 1, &[2; 32], 1),
            transcript("r", &[7; 32], "w", 1, &[1; 32], 2),
        ] {
            assert_ne!(changed, base);
        }
    }

    /// P-T2, with review A-M2's, A-L2's and A-L11's additions.
    #[test]
    fn the_wire_constants_are_the_protocols() {
        assert_eq!((CHUNK_MAX, PARAMS_MAX, FRAME_MAX), (65_536, 65_536, 262_144));
        assert_eq!((NONCE_LEN, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN), (32, 32, 64));
        assert_eq!((SESSION_HEADER, REQUEST_ID_HEADER), ("x-ai-env-session", "x-ai-env-request-id"));
        assert_eq!(
            [CONTENT_JSON, CONTENT_NDJSON, CONTENT_TEXT],
            ["application/json", "application/x-ndjson", "text/plain; charset=utf-8"]
        );
        assert_eq!((DEADLINE_DEFAULT_MS, DEADLINE_MAX_MS), (30_000, 600_000));
        let codes = [close::NORMAL, close::REVOKED, close::SUPERSEDED, close::PROTOCOL, close::CATALOG_REFUSED, close::PING_TIMEOUT, close::STALE];
        assert_eq!(codes, [0, 1, 2, 3, 4, 5, 6]);
        let reasons = [cancel::CALLER_GONE, cancel::DEADLINE, cancel::BYTE_CAP, cancel::CHUNK_CAP, cancel::CALLER_TOO_SLOW, cancel::PROTOCOL, cancel::SHUTDOWN];
        assert_eq!(reasons, ["caller_gone", "deadline", "byte_cap", "chunk_cap", "caller_too_slow", "protocol", "shutdown"]);
        let distinct: std::collections::BTreeSet<_> = reasons.iter().collect();
        assert_eq!(distinct.len(), reasons.len());
    }
}
