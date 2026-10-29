//! The worker handshake (R-7 to R-13): the transcript, the nonce, `verify_proof`, `AuthFault`.
//!
//! The worker signs P's transcript (R-8), which the relay builds with P's own function and never re-implements;
//! the signature is checked with W/M's `PublicKey::verify` against the whitelisted key (R-10). Every fault reaches
//! the worker as the same `authentication failed` (R-11): the fault's word is for the tunnel line only.

use std::time::{Duration, SystemTime};

use ai_env_relay_proto::v1::{AuthProof, Hello, SigAlg};

use crate::files::{Loaded, Watched};
use crate::lists::{WorkerEntry, Workers};

/// P's transcript (P-R25) and its 27-byte domain, from ai-env-source's `wire` (review A-M13; was the proto crate's,
/// Q-R1).
pub use ai_env_source::wire::{transcript, DOMAIN as AUTH_DOMAIN};

/// `Challenge.nonce`'s length.
pub const NONCE_LEN: usize = ai_env_source::wire::NONCE_LEN;
/// The protocols this relay speaks.
pub const SUPPORTED_PROTOCOLS: [u32; 1] = [ai_env_relay_proto::PROTOCOL];

/// 32 bytes from aws-lc-rs's `SystemRandom`.
pub fn new_nonce() -> [u8; NONCE_LEN] {
    use aws_lc_rs::rand::SecureRandom;
    let mut nonce = [0u8; NONCE_LEN];
    // A failing system RNG leaves nothing safe to do: no handshake may proceed on a guessable nonce (R-13).
    aws_lc_rs::rand::SystemRandom::new().fill(&mut nonce).expect("the system random generator works");
    nonce
}

/// Why a handshake failed: for the tunnel line only (the worker sees `authentication failed`, P-R9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFault {
    /// The whitelist was never loaded.
    NotLoaded,
    /// The whitelist is stale.
    Stale,
    /// A frame out of shape.
    Malformed,
    /// Another protocol.
    BadProtocol,
    /// Another algorithm or key than the entry's.
    BadAlg,
    /// No entry for the worker id.
    UnknownWorker,
    /// The entry lapsed.
    Expired,
    /// The signature does not verify.
    BadSignature,
    /// A frame out of order.
    OutOfOrder,
    /// The time budget passed.
    Timeout,
    /// The stream ended.
    Eof,
}

impl AuthFault {
    /// The tunnel line's `reason` (R-65): not_loaded, stale, malformed, bad_protocol, bad_alg, unknown_worker,
    /// expired, bad_signature, out_of_order, timeout, eof.
    pub fn word(self) -> &'static str {
        match self {
            AuthFault::NotLoaded => "not_loaded",
            AuthFault::Stale => "stale",
            AuthFault::Malformed => "malformed",
            AuthFault::BadProtocol => "bad_protocol",
            AuthFault::BadAlg => "bad_alg",
            AuthFault::UnknownWorker => "unknown_worker",
            AuthFault::Expired => "expired",
            AuthFault::BadSignature => "bad_signature",
            AuthFault::OutOfOrder => "out_of_order",
            AuthFault::Timeout => "timeout",
            AuthFault::Eof => "eof",
        }
    }
}

/// R-10's checks once both frames are in; the signature through WM's `PublicKey::verify`.
pub fn verify_proof(
    workers: Option<&Workers>,
    relay_id: &str,
    nonce: &[u8; NONCE_LEN],
    hello: &Hello,
    proof: &AuthProof,
    now_unix: u64,
) -> Result<WorkerEntry, AuthFault> {
    let workers = workers.ok_or(AuthFault::NotLoaded)?;
    let shaped = ai_env_worker::globs::valid_id(&hello.worker_id)
        && hello.public_key.len() == ai_env_source::wire::ED25519_PUBLIC_KEY_LEN
        && proof.signature.len() == ai_env_source::wire::ED25519_SIGNATURE_LEN;
    if !shaped {
        return Err(AuthFault::Malformed);
    }
    if !SUPPORTED_PROTOCOLS.contains(&hello.protocol) {
        return Err(AuthFault::BadProtocol);
    }
    if hello.alg != SigAlg::Ed25519 as i32 {
        return Err(AuthFault::BadAlg);
    }
    // One key per worker id (LD-R6): the Hello's key must be the entry's byte for byte, else the pair is unknown.
    let entry = workers.entry(&hello.worker_id).ok_or(AuthFault::UnknownWorker)?;
    let key = entry.key();
    if entry.alg != "ed25519" || key.bytes().as_slice() != hello.public_key.as_slice() {
        return Err(AuthFault::UnknownWorker);
    }
    if workers.in_force(&hello.worker_id, now_unix).is_none() {
        return Err(AuthFault::Expired);
    }
    let signed = transcript(relay_id, nonce, &hello.worker_id, hello.alg as u32, &hello.public_key, hello.protocol);
    if !key.verify(&signed, &proof.signature) {
        return Err(AuthFault::BadSignature);
    }
    Ok(entry.clone())
}

/// The workers file as R-10's first check reads it: loaded (`NotLoaded`) and fresh (`Stale`, R-17).
pub(crate) fn whitelist(workers: &Watched<Workers>, now: SystemTime, max_stale: Duration) -> Result<Loaded<Workers>, AuthFault> {
    let loaded = workers.loaded().ok_or(AuthFault::NotLoaded)?;
    if !crate::files::is_fresh(loaded.fresh_at, now, max_stale) {
        return Err(AuthFault::Stale);
    }
    Ok(loaded)
}

/// `Hello.sdk_version` as logged (R-10): itself when it is `^[0-9A-Za-z.+-]{1,32}$`, else `?`.
pub(crate) fn sdk_label(v: &str) -> String {
    let ok = !v.is_empty() && v.len() <= 32 && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'));
    if ok { v.to_string() } else { "?".to_string() }
}

/// What the handshake keeps of a verified worker.
pub(crate) struct Authed {
    pub(crate) entry: WorkerEntry,
    pub(crate) hello: Hello,
    pub(crate) whitelist_version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_env_worker::keys::SigningKey;
    use ai_env_worker::policy;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn sha(b: &[u8]) -> String {
        hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b).as_ref())
    }

    fn nonce() -> [u8; NONCE_LEN] {
        std::array::from_fn(|i| i as u8)
    }

    fn hello(worker_id: &str, seed: u8) -> Hello {
        let key = SigningKey::from_seed(&[seed; 32]).unwrap().public_key();
        Hello { worker_id: worker_id.into(), alg: SigAlg::Ed25519 as i32, public_key: key.bytes().to_vec(), protocol: 1, sdk_version: "0.1.0".into() }
    }

    fn sign(seed: u8, relay_id: &str, nonce: &[u8; NONCE_LEN], h: &Hello) -> AuthProof {
        let t = transcript(relay_id, nonce, &h.worker_id, h.alg as u32, &h.public_key, h.protocol);
        AuthProof { signature: SigningKey::from_seed(&[seed; 32]).unwrap().sign(&t).to_vec() }
    }

    fn workers(not_after: &str) -> Workers {
        let key = SigningKey::from_seed(&[1; 32]).unwrap().public_key().b64();
        let entry = WorkerEntry { worker_id: "worker-a".into(), alg: "ed25519".into(), public_key: key, sources: vec!["example.alpha*".into()], not_after: not_after.into() };
        crate::lists::parse_workers(policy::render_workers(&[entry]).unwrap().as_bytes()).unwrap()
    }

    /// Unit 7.
    #[test]
    fn the_transcript_is_the_golden_bytes() {
        let key = SigningKey::from_seed(&[1; 32]).unwrap();
        let pk = key.public_key();
        let t = transcript("relay-test", &nonce(), "worker-a", 1, pk.bytes(), 1);
        assert_eq!(t.len(), 145);
        assert_eq!(
            hex(&t[..101]),
            "0000001b61692d656e762f72656c61792f776f726b65722d617574682f76310000000a72656c61792d7465737400000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000008776f726b65722d610000000400000001"
        );
        assert_eq!(hex(&t[101..105]), "00000020");
        assert_eq!(&t[105..137], pk.bytes().as_slice());
        assert_eq!(hex(&t[137..]), "0000000400000001");
        assert_eq!(sha(&t), "57e9fb1870d1bf5b87b5eb9be3a79e5b627f479a590faad275b02ebf01544700");
        assert_eq!(sha(pk.bytes()), "34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e");
        assert_eq!(sha(&key.sign(&t)), "b94fb69e27d782f3ba07b9bc73d443590a46f8b9126a092fe2cb854b175200a6");
        assert_eq!(AUTH_DOMAIN.len(), 27);
        // P's vector (P-T1).
        let p = transcript("relay-test", &[7; 32], "w1", 1, &[1; 32], 1);
        assert_eq!(p.len(), 139);
        assert_eq!(sha(&p), "1f2d4d18042412b57b84e89a4fa57f2c4e148f6e4d845f16d7dfceddf6c6ed9f");
    }

    /// Unit 8.
    #[test]
    fn verify_proof_accepts_the_golden_and_refuses_each_change() {
        let not_after = "2027-01-01T23:59:59Z";
        let w = workers(not_after);
        let now = policy::unix_of(not_after).unwrap() - 3600;
        let n = nonce();
        let h = hello("worker-a", 1);
        let proof = sign(1, "relay-test", &n, &h);
        let ok = verify_proof(Some(&w), "relay-test", &n, &h, &proof, now).expect("the golden proof");
        assert_eq!(ok.worker_id, "worker-a");

        let mut other_nonce = n;
        other_nonce[0] ^= 1;
        assert_eq!(verify_proof(Some(&w), "relay-test", &other_nonce, &h, &proof, now), Err(AuthFault::BadSignature));
        assert_eq!(verify_proof(Some(&w), "relay-other", &n, &h, &proof, now), Err(AuthFault::BadSignature));
        let hb = Hello { worker_id: "worker-b".into(), ..h.clone() };
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &hb, &sign(1, "relay-test", &n, &hb), now), Err(AuthFault::UnknownWorker));
        let h2 = hello("worker-a", 2);
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h2, &sign(2, "relay-test", &n, &h2), now), Err(AuthFault::UnknownWorker));
        let h0 = Hello { alg: 0, ..h.clone() };
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h0, &sign(1, "relay-test", &n, &h0), now), Err(AuthFault::BadAlg));
        let hp = Hello { protocol: 2, ..h.clone() };
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &hp, &sign(1, "relay-test", &n, &hp), now), Err(AuthFault::BadProtocol));
        let mut flipped = proof.clone();
        flipped.signature[10] ^= 0x01;
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &flipped, now), Err(AuthFault::BadSignature));
        let short = AuthProof { signature: proof.signature[..63].to_vec() };
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &short, now), Err(AuthFault::Malformed));
        let at = policy::unix_of(not_after).unwrap();
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &proof, at + 1), Err(AuthFault::Expired), "not_after one second before now");
        assert!(verify_proof(Some(&w), "relay-test", &n, &h, &proof, at).is_ok(), "not_after equal to now");
        assert_eq!(verify_proof(None, "relay-test", &n, &h, &proof, now), Err(AuthFault::NotLoaded));

        // The workers file as the tunnel reads it: not loaded, then stale (R-17).
        let dir = tempfile::tempdir().unwrap();
        let watched: Watched<Workers> = Watched::new(dir.path().join(crate::lists::WORKERS_FILE));
        let max = Duration::from_secs(900);
        let clock = SystemTime::UNIX_EPOCH + Duration::from_secs(now);
        assert!(matches!(whitelist(&watched, clock, max), Err(AuthFault::NotLoaded)));
        let body = policy::render_workers(&w.entries).unwrap();
        std::fs::write(dir.path().join(crate::lists::WORKERS_FILE), body).unwrap();
        watched.poll(Some(clock), crate::lists::parse_workers);
        assert!(whitelist(&watched, clock, max).is_ok());
        assert!(matches!(whitelist(&watched, clock + Duration::from_secs(901), max), Err(AuthFault::Stale)));
    }

    /// Unit 9.
    #[test]
    fn nonces_are_fresh() {
        let all: std::collections::HashSet<[u8; NONCE_LEN]> = (0..1000).map(|_| new_nonce()).collect();
        assert_eq!(all.len(), 1000);
        assert!(!all.contains(&[0u8; NONCE_LEN]));
    }

    #[test]
    fn sdk_versions_are_logged_only_in_their_shape() {
        assert_eq!(sdk_label("0.1.0+build-7"), "0.1.0+build-7");
        assert_eq!(sdk_label(""), "?");
        assert_eq!(sdk_label("0.1 beta"), "?");
        assert_eq!(sdk_label(&"1".repeat(33)), "?");
    }
}
