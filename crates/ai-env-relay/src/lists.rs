//! The three relay lists of WM-R7, parsed by ai-env-worker's `policy` (R never renders one). The writer (M's
//! `ai-env relay allow|revoke` and grant commands) and this reader share one implementation (LD-R5); the relay
//! adds only the 65 536-byte pre-check (`files::Watched`) and the unload on refusal (§R-relay.3.5).

use ai_env_worker::policy;

pub use ai_env_worker::policy::{Grant, SignerEntry, WorkerEntry};

/// The live directory's workers file.
pub const WORKERS_FILE: &str = "workers.json";
/// The live directory's token-signers file.
pub const SIGNERS_FILE: &str = "token-signers.json";
/// The live directory's grants file.
pub const GRANTS_FILE: &str = "grants.json";

/// The workers' whitelist.
#[derive(Debug, Clone, Default)]
pub struct Workers {
    /// Its entries.
    pub entries: Vec<WorkerEntry>,
}

/// The token signers.
#[derive(Debug, Clone, Default)]
pub struct Signers {
    /// Its entries.
    pub entries: Vec<SignerEntry>,
}

/// The grants.
#[derive(Debug, Clone, Default)]
pub struct Grants {
    /// Its entries.
    pub entries: Vec<Grant>,
}

fn text(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|_| "not UTF-8".to_string())
}

/// `policy::parse_workers` of the bytes as UTF-8; refused whole on any fault, the text `PolicyError`'s.
pub fn parse_workers(bytes: &[u8]) -> Result<Workers, String> {
    policy::parse_workers(text(bytes)?).map(|entries| Workers { entries }).map_err(|e| e.to_string())
}

/// `policy::parse_signers`, the same.
pub fn parse_signers(bytes: &[u8]) -> Result<Signers, String> {
    policy::parse_signers(text(bytes)?).map(|entries| Signers { entries }).map_err(|e| e.to_string())
}

/// `policy::parse_grants`, the same.
pub fn parse_grants(bytes: &[u8]) -> Result<Grants, String> {
    policy::parse_grants(text(bytes)?).map(|entries| Grants { entries }).map_err(|e| e.to_string())
}

impl Workers {
    /// The entry of `worker_id` (ids are unique, WM-R7) when in force at `now` (`now <= not_after_unix()`); R-10 tells
    /// an absent entry (`UnknownWorker`) from a lapsed one (`Expired`) through `entry`.
    pub fn in_force(&self, worker_id: &str, now: u64) -> Option<&WorkerEntry> {
        self.entry(worker_id).filter(|e| now <= e.not_after_unix())
    }

    /// The entry of `worker_id`, in force or not.
    pub fn entry(&self, worker_id: &str) -> Option<&WorkerEntry> {
        self.entries.iter().find(|e| e.worker_id == worker_id)
    }
}

impl Signers {
    /// The key `session::verify` needs for `signer_id` (`kid`), its own expiry checked there (WM-R6).
    pub fn key(&self, signer_id: &str) -> Option<ai_env_worker::session::SignerKey> {
        self.entries
            .iter()
            .find(|e| e.signer_id == signer_id)
            .map(|e| ai_env_worker::session::SignerKey { public_key: e.key(), not_after: e.not_after_unix() })
    }
}

impl Grants {
    /// The grant of `grant_id`; `Grant::allows(source, op)` is WM's rule match (R-47).
    pub fn get(&self, grant_id: &str) -> Option<&Grant> {
        self.entries.iter().find(|g| g.grant_id == grant_id)
    }
}

impl crate::files::Entries for Workers {
    fn entries(&self) -> usize {
        self.entries.len()
    }
}

impl crate::files::Entries for Signers {
    fn entries(&self) -> usize {
        self.entries.len()
    }
}

impl crate::files::Entries for Grants {
    fn entries(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::{Poll, Watched};
    use ai_env_worker::keys::SigningKey;

    fn key_b64(seed: u8) -> String {
        SigningKey::from_seed(&[seed; 32]).unwrap().public_key().b64()
    }

    /// Standard base64 with padding: a key of the wrong length, built at run time.
    fn b64(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                out.push(if i <= c.len() { A[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
            }
        }
        out
    }

    fn worker(id: &str, seed: u8, globs: &[&str], not_after: &str) -> WorkerEntry {
        WorkerEntry {
            worker_id: id.into(),
            alg: "ed25519".into(),
            public_key: key_b64(seed),
            sources: globs.iter().map(|g| g.to_string()).collect(),
            not_after: not_after.into(),
        }
    }

    /// Unit 3.
    #[test]
    fn a_list_the_shared_parser_refuses_is_unloaded() {
        let good = policy::render_workers(&[worker("worker-a", 1, &["example.alpha*"], "2027-01-01T23:59:59Z")]).unwrap();
        let parsed = parse_workers(good.as_bytes()).expect("W/M's rendering loads");
        assert_eq!(parsed.entries.len(), 1);

        let unknown_field = good.replacen("\"worker_id\"", "\"extra\":1,\"worker_id\"", 1);
        let short_key = good.replace(&key_b64(1), &b64(&[1u8; 31]));
        let many: Vec<WorkerEntry> = (0..40).map(|i| worker(&format!("worker-{i:02}"), i as u8 + 10, &["example.*"], "2027-01-01T23:59:59Z")).collect();
        let big = serde_json::to_string(&many).unwrap();
        assert!(big.len() > 4096);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(WORKERS_FILE);
        let watched: Watched<Workers> = Watched::new(path.clone());
        for bad in [unknown_field, short_key, big] {
            let shared = policy::parse_workers(&bad).expect_err("the shared parser refuses it").to_string();
            assert_eq!(parse_workers(bad.as_bytes()).unwrap_err(), shared, "PolicyError's text");
            std::fs::write(&path, &good).unwrap();
            assert!(matches!(watched.poll(None, parse_workers), Poll::Loaded { .. } | Poll::Confirmed));
            assert!(watched.loaded().is_some());
            std::fs::write(&path, bad.as_bytes()).unwrap();
            assert_eq!(watched.poll(None, parse_workers), Poll::Refused(shared));
            assert!(watched.loaded().is_none(), "a refused list is unloaded at once");
        }

        std::fs::write(&path, &good).unwrap();
        assert!(matches!(watched.poll(None, parse_workers), Poll::Loaded { .. }));
        let mut huge = good.into_bytes();
        huge.resize(65_537, b' ');
        std::fs::write(&path, &huge).unwrap();
        let called = std::cell::Cell::new(false);
        let outcome = watched.poll(None, |b| {
            called.set(true);
            parse_workers(b)
        });
        assert!(matches!(outcome, Poll::Refused(ref t) if t.contains("65536")), "{outcome:?}");
        assert!(!called.get(), "refused before parsing");
        assert!(watched.loaded().is_none());

        let signers = policy::render_signers(&[SignerEntry {
            signer_id: "mac".into(),
            alg: "ed25519".into(),
            public_key: key_b64(7),
            not_after: "2027-01-01T23:59:59Z".into(),
        }])
        .unwrap();
        assert_eq!(parse_signers(signers.as_bytes()).unwrap().entries.len(), 1);
        let grants = policy::render_grants(&[Grant { grant_id: "g-default".into(), allow: vec!["example.*/get".into(), "example.*/list".into()] }]).unwrap();
        assert_eq!(parse_grants(grants.as_bytes()).unwrap().entries.len(), 1);
        let bad_signers = signers.replacen("\"signer_id\"", "\"extra\":1,\"signer_id\"", 1);
        assert_eq!(parse_signers(bad_signers.as_bytes()).unwrap_err(), policy::parse_signers(&bad_signers).unwrap_err().to_string());
        let bad_grants = grants.replacen("\"grant_id\"", "\"extra\":1,\"grant_id\"", 1);
        assert_eq!(parse_grants(bad_grants.as_bytes()).unwrap_err(), policy::parse_grants(&bad_grants).unwrap_err().to_string());
        assert_eq!(parse_workers(&[0xff, 0xfe]).unwrap_err(), "not UTF-8");
    }

    /// Unit 4.
    #[test]
    fn an_entry_is_in_force_through_its_not_after_second() {
        let workers = Workers { entries: vec![worker("worker-a", 1, &["example.*"], "2026-10-29T23:59:59Z")] };
        let at = policy::unix_of("2026-10-29T23:59:59Z").unwrap();
        assert_eq!(at, 1_793_318_399);
        assert_eq!(workers.in_force("worker-a", at).map(|e| e.worker_id.as_str()), Some("worker-a"));
        assert!(workers.in_force("worker-a", at + 1).is_none());
        assert!(workers.entry("worker-a").is_some(), "R-10 tells Expired from UnknownWorker through entry");
        assert!(workers.entry("worker-b").is_none());
    }

    /// Unit 5.
    #[test]
    fn signers_hand_their_keys_to_the_verifier() {
        let signers = Signers {
            entries: vec![
                SignerEntry { signer_id: "mac".into(), alg: "ed25519".into(), public_key: key_b64(7), not_after: "2027-01-01T23:59:59Z".into() },
                SignerEntry { signer_id: "mac-2".into(), alg: "ed25519".into(), public_key: key_b64(8), not_after: "2027-02-01T23:59:59Z".into() },
            ],
        };
        let k = signers.key("mac").expect("mac is a signer");
        assert_eq!(k.public_key, SigningKey::from_seed(&[7; 32]).unwrap().public_key());
        assert_eq!(k.not_after, policy::unix_of("2027-01-01T23:59:59Z").unwrap());
        let k2 = signers.key("mac-2").expect("mac-2 is a signer");
        assert_eq!(k2.public_key, SigningKey::from_seed(&[8; 32]).unwrap().public_key());
        assert!(signers.key("mac-9").is_none());
    }

    /// Unit 6.
    #[test]
    fn a_grant_allows_a_pair_through_one_rule() {
        let grants = Grants { entries: vec![Grant { grant_id: "g-mixed".into(), allow: vec!["example.*/get".into(), "other.*/list".into()] }] };
        let g = grants.get("g-mixed").unwrap();
        assert!(g.allows("example.alpha", "get"));
        assert!(g.allows("other.x", "list"));
        assert!(!g.allows("example.alpha", "list"), "each half matches some rule, but no one rule matches both");
        assert!(!g.allows("other.x", "get"));
        assert!(grants.get("g-none").is_none());
    }
}
