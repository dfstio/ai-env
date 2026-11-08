//! The worker handshake (R-7 to R-13): the transcript, the nonce, `verify_proof`, `AuthFault`.
//!
//! The worker signs P's transcript (R-8), which the relay builds with P's own function and never re-implements;
//! the signature is checked with W/M's `PublicKey::verify` against the whitelisted key (R-10). Every fault reaches
//! the worker as the same `authentication failed` (R-11): the fault's word is for the tunnel line only, and every
//! shaped `Hello` costs the same one verify (F5), so a refusal takes as long whether or not the id is whitelisted.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use ai_env_relay_proto::v1::{AuthProof, Hello, SigAlg};
use ai_env_worker::keys::{PublicKey, SigningKey};

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
    /// `open()`: no client certificate on the connection (R-126; `admit`'s config lets none through).
    NoCert,
    /// `open()`: no entry in force holds the connection's certificate (R-126).
    UnknownCert,
    /// The key is right and the certificate another's, or the entry holds none (R-127).
    CertMismatch,
}

impl AuthFault {
    /// The tunnel line's `reason` (R-65): not_loaded, stale, malformed, bad_protocol, bad_alg, unknown_worker,
    /// expired, bad_signature, out_of_order, timeout, eof, no_cert, unknown_cert, cert_mismatch.
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
            AuthFault::NoCert => "no_cert",
            AuthFault::UnknownCert => "unknown_cert",
            AuthFault::CertMismatch => "cert_mismatch",
        }
    }

    /// R-102: a fault of the peer's, counted toward its address's ban: every fault but the relay's own (`NotLoaded`,
    /// `Stale`) and `Eof` (the client left; a shutdown yields it too).
    pub fn is_fault(self) -> bool {
        match self {
            AuthFault::NotLoaded | AuthFault::Stale | AuthFault::Eof => false,
            AuthFault::Malformed
            | AuthFault::BadProtocol
            | AuthFault::BadAlg
            | AuthFault::UnknownWorker
            | AuthFault::Expired
            | AuthFault::BadSignature
            | AuthFault::OutOfOrder
            | AuthFault::Timeout
            | AuthFault::NoCert
            | AuthFault::UnknownCert
            | AuthFault::CertMismatch => true,
        }
    }
}

/// The throw-away key's seed (F5): a constant, the same in every relay. Its private half is public knowledge, so a
/// signature it verifies admits nobody: `verify_proof` checks against it only on its way to a fault.
const THROWAWAY_SEED: [u8; 32] = *b"ai-env relay: a key of no worker";

/// The throw-away key, made once: `RelayApp::new` makes it, so no refusal pays for it.
pub(crate) fn throwaway_key() -> PublicKey {
    static KEY: OnceLock<PublicKey> = OnceLock::new();
    *KEY.get_or_init(|| SigningKey::from_seed(&THROWAWAY_SEED).expect("a constant 32-byte seed is an Ed25519 key").public_key())
}

/// The one Ed25519 verify of a handshake (F5); the unit tests count the calls.
fn verify_once(key: &PublicKey, signed: &[u8], signature: &[u8]) -> bool {
    #[cfg(test)]
    tests::VERIFIES.with(|n| n.set(n.get() + 1));
    key.verify(signed, signature)
}

/// R-10's checks once both frames are in; the signature through WM's `PublicKey::verify`.
///
/// Every shaped `Hello` runs exactly one verify (F5): the entry's key for a pair in force, else the throw-away key,
/// and the fault R-10's order names first is returned after it. So a worker id that is unknown, holds another key or
/// lapsed costs what a whitelisted one does, and the time of a refusal says nothing about the whitelist. An unshaped
/// one (an id that is no id, a key or a signature of another length) is refused before anything is hashed.
///
/// R-127 is the last check: an entry with no `tls_fp`, no fingerprint presented, or the entry's `tls_fp` not the hex of
/// `cert_fp` is `CertMismatch`, so one worker's certificate never serves another's key (LD-R34).
pub fn verify_proof(
    workers: Option<&Workers>,
    relay_id: &str,
    nonce: &[u8; NONCE_LEN],
    hello: &Hello,
    proof: &AuthProof,
    cert_fp: Option<&[u8; 32]>,
    now_unix: u64,
) -> Result<WorkerEntry, AuthFault> {
    let shaped = ai_env_worker::globs::valid_id(&hello.worker_id)
        && hello.public_key.len() == ai_env_source::wire::ED25519_PUBLIC_KEY_LEN
        && proof.signature.len() == ai_env_source::wire::ED25519_SIGNATURE_LEN;
    if !shaped {
        // The lengths and the name before anything is hashed (P-R25), so a peer-sized field never reaches the
        // transcript (R-73). This fault is the frame's own, so refusing at once says nothing of the whitelist; R-10's
        // order still names `NotLoaded` first.
        return Err(if workers.is_none() { AuthFault::NotLoaded } else { AuthFault::Malformed });
    }
    // One key per worker id (LD-R6): the Hello's key must be the entry's byte for byte, else the pair is unknown.
    let entry = workers
        .and_then(|w| w.entry(&hello.worker_id))
        .filter(|e| e.alg == "ed25519")
        .map(|e| (e, e.key()))
        .filter(|(_, key)| key.bytes().as_slice() == hello.public_key.as_slice());
    let fault = if workers.is_none() {
        Some(AuthFault::NotLoaded)
    } else if !SUPPORTED_PROTOCOLS.contains(&hello.protocol) {
        Some(AuthFault::BadProtocol)
    } else if hello.alg != SigAlg::Ed25519 as i32 {
        Some(AuthFault::BadAlg)
    } else if entry.is_none() {
        Some(AuthFault::UnknownWorker)
    } else if workers.and_then(|w| w.in_force(&hello.worker_id, now_unix)).is_none() {
        Some(AuthFault::Expired)
    } else {
        None
    };
    let key = match (fault, entry) {
        (None, Some((_, key))) => key,
        _ => throwaway_key(),
    };
    let signed = transcript(relay_id, nonce, &hello.worker_id, hello.alg as u32, &hello.public_key, hello.protocol);
    let verified = verify_once(&key, &signed, &proof.signature);
    match (fault, entry) {
        (Some(fault), _) => Err(fault),
        (None, Some((e, _))) if verified => match (e.tls_fp.as_deref(), cert_fp) {
            (Some(held), Some(presented)) if held == hex::encode(presented) => Ok(e.clone()),
            _ => Err(AuthFault::CertMismatch),
        },
        _ => Err(AuthFault::BadSignature),
    }
}

/// The workers file as R-10's first check, and `open()`'s (R-126), read it: loaded (`NotLoaded`) and fresh (`Stale`, R-17).
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
    use ai_env_worker::policy;

    thread_local! {
        /// `verify_once`'s calls on this thread.
        pub(super) static VERIFIES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    /// `f`'s result and how many verifies it ran.
    fn counted<T>(f: impl FnOnce() -> T) -> (T, u32) {
        VERIFIES.with(|n| n.set(0));
        let out = f();
        (out, VERIFIES.with(std::cell::Cell::get))
    }

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

    /// The fingerprint of `worker-a`'s client certificate in `workers`, and another's.
    const CERT_A: [u8; 32] = [0xa1; 32];
    const CERT_B: [u8; 32] = [0xb2; 32];

    fn entry(not_after: &str, tls_fp: Option<String>) -> Workers {
        let key = SigningKey::from_seed(&[1; 32]).unwrap().public_key().b64();
        let entry = WorkerEntry { worker_id: "worker-a".into(), alg: "ed25519".into(), public_key: key, sources: vec!["example.alpha*".into()], not_after: not_after.into(), tls_fp };
        crate::lists::parse_workers(policy::render_workers(&[entry]).unwrap().as_bytes()).unwrap()
    }

    fn workers(not_after: &str) -> Workers {
        entry(not_after, Some(hex(&CERT_A)))
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
        let cert = Some(&CERT_A);
        let ok = verify_proof(Some(&w), "relay-test", &n, &h, &proof, cert, now).expect("the golden proof, with its certificate");
        assert_eq!(ok.worker_id, "worker-a");

        let mut other_nonce = n;
        other_nonce[0] ^= 1;
        assert_eq!(verify_proof(Some(&w), "relay-test", &other_nonce, &h, &proof, cert, now), Err(AuthFault::BadSignature));
        assert_eq!(verify_proof(Some(&w), "relay-other", &n, &h, &proof, cert, now), Err(AuthFault::BadSignature));
        let hb = Hello { worker_id: "worker-b".into(), ..h.clone() };
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &hb, &sign(1, "relay-test", &n, &hb), cert, now), Err(AuthFault::UnknownWorker));
        let h2 = hello("worker-a", 2);
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h2, &sign(2, "relay-test", &n, &h2), cert, now), Err(AuthFault::UnknownWorker));
        let h0 = Hello { alg: 0, ..h.clone() };
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h0, &sign(1, "relay-test", &n, &h0), cert, now), Err(AuthFault::BadAlg));
        let hp = Hello { protocol: 2, ..h.clone() };
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &hp, &sign(1, "relay-test", &n, &hp), cert, now), Err(AuthFault::BadProtocol));
        let mut flipped = proof.clone();
        flipped.signature[10] ^= 0x01;
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &flipped, cert, now), Err(AuthFault::BadSignature));
        let short = AuthProof { signature: proof.signature[..63].to_vec() };
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &short, cert, now), Err(AuthFault::Malformed));
        let at = policy::unix_of(not_after).unwrap();
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &proof, cert, at + 1), Err(AuthFault::Expired), "not_after one second before now");
        assert!(verify_proof(Some(&w), "relay-test", &n, &h, &proof, cert, at).is_ok(), "not_after equal to now");
        assert_eq!(verify_proof(None, "relay-test", &n, &h, &proof, cert, now), Err(AuthFault::NotLoaded));

        // R-127: the certificate is the last check. Another fingerprint, none, and an entry that holds none are each
        // `CertMismatch`; every other fault comes first (LD-R34), so the word means the key is right.
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &proof, Some(&CERT_B), now), Err(AuthFault::CertMismatch));
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &proof, None, now), Err(AuthFault::CertMismatch));
        let no_tls_fp = entry(not_after, None);
        assert_eq!(verify_proof(Some(&no_tls_fp), "relay-test", &n, &h, &proof, cert, now), Err(AuthFault::CertMismatch));
        assert_eq!(verify_proof(Some(&no_tls_fp), "relay-test", &n, &h, &proof, None, now), Err(AuthFault::CertMismatch), "none on either side is no match");
        for presented in [Some(&CERT_B), None] {
            assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &flipped, presented, now), Err(AuthFault::BadSignature));
            assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &proof, presented, at + 1), Err(AuthFault::Expired));
            assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h2, &sign(2, "relay-test", &n, &h2), presented, now), Err(AuthFault::UnknownWorker));
        }
        // The words of R-126 and R-127, each a fault of the peer's (R-102).
        for (fault, word) in [(AuthFault::NoCert, "no_cert"), (AuthFault::UnknownCert, "unknown_cert"), (AuthFault::CertMismatch, "cert_mismatch")] {
            assert_eq!(fault.word(), word);
            assert!(fault.is_fault(), "{word}");
        }

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

    /// F5: every outcome of `verify_proof` for a shaped `Hello` runs exactly one verify, a refusal's as a success's;
    /// an unshaped one runs none and hashes nothing, however large its id (P-R25). The throw-away key is no test
    /// list's key, and a proof made with it (its seed is in the source) admits nobody.
    #[test]
    fn every_outcome_verifies_once() {
        let not_after = "2027-01-01T23:59:59Z";
        let w = workers(not_after);
        let now = policy::unix_of(not_after).unwrap() - 3600;
        let n = nonce();
        let h = hello("worker-a", 1);
        let good = sign(1, "relay-test", &n, &h);
        let hb = Hello { worker_id: "worker-b".into(), ..h.clone() };
        let h2 = hello("worker-a", 2);
        let h0 = Hello { alg: 0, ..h.clone() };
        let hp = Hello { protocol: 2, ..h.clone() };
        let mut flipped = good.clone();
        flipped.signature[10] ^= 0x01;
        let short = AuthProof { signature: good.signature[..63].to_vec() };
        // A Hello as large as the public face decodes (`catalog_max_bytes`), its id all of it.
        let huge = Hello { worker_id: "w".repeat(256 * 1024), ..h.clone() };
        let lapsed = policy::unix_of(not_after).unwrap() + 1;
        let cases = [
            ("the golden proof", Some(&w), &h, good.clone(), now, Ok("worker-a"), 1),
            ("a flipped signature", Some(&w), &h, flipped, now, Err(AuthFault::BadSignature), 1),
            ("an unknown id", Some(&w), &hb, sign(1, "relay-test", &n, &hb), now, Err(AuthFault::UnknownWorker), 1),
            ("another key", Some(&w), &h2, sign(2, "relay-test", &n, &h2), now, Err(AuthFault::UnknownWorker), 1),
            ("a lapsed entry", Some(&w), &h, good.clone(), lapsed, Err(AuthFault::Expired), 1),
            ("another alg", Some(&w), &h0, sign(1, "relay-test", &n, &h0), now, Err(AuthFault::BadAlg), 1),
            ("another protocol", Some(&w), &hp, sign(1, "relay-test", &n, &hp), now, Err(AuthFault::BadProtocol), 1),
            ("no whitelist", None, &h, good.clone(), now, Err(AuthFault::NotLoaded), 1),
            ("a short signature", Some(&w), &h, short.clone(), now, Err(AuthFault::Malformed), 0),
            ("a 256 KiB worker id", Some(&w), &huge, good.clone(), now, Err(AuthFault::Malformed), 0),
            ("no whitelist, a short signature", None, &h, short, now, Err(AuthFault::NotLoaded), 0),
        ];
        for (what, list, hello, proof, at, want, n_verifies) in cases {
            let (got, verifies) = counted(|| verify_proof(list, "relay-test", &n, hello, &proof, Some(&CERT_A), at));
            assert_eq!(got.as_ref().map(|e| e.worker_id.as_str()), want.as_ref().copied(), "{what}");
            assert_eq!(verifies, n_verifies, "{what}: one verify for a shaped Hello, whatever the outcome; none for an unshaped one");
        }
        // R-127's fault comes after the one verify too.
        for (what, presented) in [("another certificate", Some(&CERT_B)), ("no certificate", None)] {
            let (got, verifies) = counted(|| verify_proof(Some(&w), "relay-test", &n, &h, &good, presented, now));
            assert_eq!(got, Err(AuthFault::CertMismatch), "{what}");
            assert_eq!(verifies, 1, "{what}");
        }

        let decoy = SigningKey::from_seed(&THROWAWAY_SEED).unwrap();
        assert_eq!(throwaway_key(), decoy.public_key());
        let test_keys: Vec<PublicKey> = [1u8, 2, 5, 7].iter().map(|s| SigningKey::from_seed(&[*s; 32]).unwrap().public_key()).collect();
        assert!(!test_keys.contains(&throwaway_key()), "no test seed's key");
        assert!(w.entries.iter().all(|e| e.key() != throwaway_key()), "in no list");
        let with_decoy = |worker_id: &str| {
            let hd = Hello { worker_id: worker_id.into(), public_key: decoy.public_key().bytes().to_vec(), ..h.clone() };
            let t = transcript("relay-test", &n, &hd.worker_id, hd.alg as u32, &hd.public_key, hd.protocol);
            let pd = AuthProof { signature: decoy.sign(&t).to_vec() };
            (hd, pd)
        };
        for (worker_id, at, want) in [("worker-a", now, AuthFault::UnknownWorker), ("worker-b", now, AuthFault::UnknownWorker)] {
            let (hd, pd) = with_decoy(worker_id);
            assert_eq!(verify_proof(Some(&w), "relay-test", &n, &hd, &pd, Some(&CERT_A), at), Err(want), "{worker_id}: the decoy's own proof");
        }
        // Signed with the decoy for the entry's own key: the decoy is never the entry's key, lapsed or not.
        let t = transcript("relay-test", &n, &h.worker_id, h.alg as u32, &h.public_key, h.protocol);
        let pd = AuthProof { signature: decoy.sign(&t).to_vec() };
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &pd, Some(&CERT_A), now), Err(AuthFault::BadSignature));
        assert_eq!(verify_proof(Some(&w), "relay-test", &n, &h, &pd, Some(&CERT_A), lapsed), Err(AuthFault::Expired));
    }

    /// Unit 51 (R-102): which faults count toward an address's ban: all but the relay's own and the client's leaving.
    #[test]
    fn a_fault_of_the_peers_counts_and_no_other() {
        let table = [
            (AuthFault::NotLoaded, false),
            (AuthFault::Stale, false),
            (AuthFault::Malformed, true),
            (AuthFault::BadProtocol, true),
            (AuthFault::BadAlg, true),
            (AuthFault::UnknownWorker, true),
            (AuthFault::Expired, true),
            (AuthFault::BadSignature, true),
            (AuthFault::OutOfOrder, true),
            (AuthFault::Timeout, true),
            (AuthFault::Eof, false),
            (AuthFault::NoCert, true),
            (AuthFault::UnknownCert, true),
            (AuthFault::CertMismatch, true),
        ];
        for (fault, counts) in table {
            assert_eq!(fault.is_fault(), counts, "{}", fault.word());
        }
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
