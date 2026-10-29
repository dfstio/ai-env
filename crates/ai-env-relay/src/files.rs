//! The live directory: `Watched`, `Live`, freshness, `content_version` (R-14 to R-18).
//!
//! I's reload is the only writer (R-14): each file is replaced by one rename and only when its bytes change, and
//! `fetched` holds the unix seconds of its last successful fetch (§R-relay.3.5). That number is the freshness clock
//! (R-16); a file's own mtime never is.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use crate::lists::{Grants, Signers, Workers, GRANTS_FILE, SIGNERS_FILE, WORKERS_FILE};

/// The largest live file read.
pub const FILE_MAX_BYTES: u64 = 65_536;
/// The relay's chain and key.
pub const TLS_FILE: &str = "tls.pem";
/// The reload's time stamp.
pub const FETCHED_FILE: &str = "fetched";

/// The first 8 bytes of the content's SHA-256, big-endian: AuthOk.whitelist_version and the logs' `version`.
pub fn content_version(bytes: &[u8]) -> u64 {
    version_of(&sha256(bytes))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn version_of(sha: &[u8; 32]) -> u64 {
    let mut first = [0u8; 8];
    first.copy_from_slice(&sha[..8]);
    u64::from_be_bytes(first)
}

/// How many entries a loaded file holds, for the reload and `check` lines.
pub(crate) trait Entries {
    fn entries(&self) -> usize;
}

impl Entries for rustls::ServerConfig {
    fn entries(&self) -> usize {
        0
    }
}

/// A loaded file.
#[derive(Clone)]
pub struct Loaded<T> {
    /// Its parsed value.
    pub value: Arc<T>,
    /// `content_version` of its bytes.
    pub version: u64,
    /// SHA-256 of its bytes.
    pub sha256: [u8; 32],
    /// When the reload last confirmed it.
    pub fresh_at: Option<SystemTime>,
}

/// One look's outcome (R-15, R-16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    /// No file.
    Missing,
    /// The same file.
    Unchanged,
    /// The same content, confirmed fresh.
    Confirmed,
    /// A new content, loaded.
    Loaded {
        /// Its version.
        version: u64,
    },
    /// A new content, refused.
    Refused(String),
    /// Too old.
    Stale,
}

impl Poll {
    /// The reload line's `outcome` (R-67); None for the outcomes that write no line (R-19).
    pub(crate) fn word(&self) -> Option<&'static str> {
        match self {
            Poll::Missing => Some("missing"),
            Poll::Loaded { .. } => Some("loaded"),
            Poll::Refused(_) => Some("refused"),
            Poll::Stale => Some("stale"),
            Poll::Unchanged | Poll::Confirmed => None,
        }
    }
}

/// What the last look saw: (inode, size, mtime) or no file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Look {
    Never,
    Absent,
    Seen { ino: u64, size: u64, mtime: i64, mtime_ns: i64 },
}

/// One watched file.
pub struct Watched<T> {
    path: PathBuf,
    last: Mutex<Look>,
    loaded: Mutex<Option<Loaded<T>>>,
    /// `tls.pem` keeps its loaded value when a new one is refused (R-4); a JSON list is unloaded (R-15).
    keep_on_refusal: bool,
    /// The last look found it loaded and not fresh: `Stale` is reported once per turn (R-17).
    stale_seen: AtomicBool,
}

impl<T> Watched<T> {
    /// The file at `path`, not loaded yet.
    pub fn new(path: PathBuf) -> Self {
        Watched { path, last: Mutex::new(Look::Never), loaded: Mutex::new(None), keep_on_refusal: false, stale_seen: AtomicBool::new(false) }
    }

    /// `tls.pem`'s rule (R-4): a refused file leaves the loaded value in place.
    pub(crate) fn keeping_on_refusal(mut self) -> Self {
        self.keep_on_refusal = true;
        self
    }

    /// One look (R-15, R-16): `fetched_at` is the time written in the live directory's `fetched`, if any.
    pub fn poll(&self, fetched_at: Option<SystemTime>, parse: impl Fn(&[u8]) -> Result<T, String>) -> Poll {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let had = self.unload();
                let was = std::mem::replace(&mut *last, Look::Absent);
                // An absent file is reported once, when it goes (or at the first look), not at every tick.
                return if had || was != Look::Absent { Poll::Missing } else { Poll::Unchanged };
            }
            Err(e) => {
                *last = Look::Never;
                return self.refuse(format!("unreadable: {}", e.kind()));
            }
        };
        let look = Look::Seen { ino: meta.ino(), size: meta.size(), mtime: meta.mtime(), mtime_ns: meta.mtime_nsec() };
        if *last == look {
            self.refresh(fetched_at);
            return Poll::Unchanged;
        }
        *last = look;
        if !meta.is_file() {
            return self.refuse("not a regular file".into());
        }
        let bytes = match read_capped(&self.path) {
            Ok(b) => b,
            Err(e) => return self.refuse(e),
        };
        let sha = sha256(&bytes);
        let same = self.loaded.lock().unwrap_or_else(PoisonError::into_inner).as_ref().is_some_and(|l| l.sha256 == sha);
        if same {
            self.refresh(fetched_at);
            return Poll::Confirmed;
        }
        match parse(&bytes) {
            Ok(value) => {
                let version = version_of(&sha);
                *self.loaded.lock().unwrap_or_else(PoisonError::into_inner) =
                    Some(Loaded { value: Arc::new(value), version, sha256: sha, fresh_at: fetched_at });
                Poll::Loaded { version }
            }
            Err(text) => self.refuse(text),
        }
    }

    /// What is loaded, fresh or not.
    pub fn loaded(&self) -> Option<Loaded<T>> {
        let loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        loaded.as_ref().map(|l| Loaded { value: Arc::clone(&l.value), version: l.version, sha256: l.sha256, fresh_at: l.fresh_at })
    }

    /// The value when loaded and `now - fresh_at <= max_stale` (R-17); None otherwise.
    pub fn fresh(&self, now: SystemTime, max_stale: Duration) -> Option<Arc<T>> {
        self.loaded().filter(|l| is_fresh(l.fresh_at, now, max_stale)).map(|l| l.value)
    }

    /// R-16: while the on-disk content is the loaded content, `fresh_at` becomes the fetch time when that is newer.
    fn refresh(&self, fetched_at: Option<SystemTime>) {
        if let Some(l) = self.loaded.lock().unwrap_or_else(PoisonError::into_inner).as_mut() {
            if fetched_at > l.fresh_at {
                l.fresh_at = fetched_at;
            }
        }
    }

    fn unload(&self) -> bool {
        self.loaded.lock().unwrap_or_else(PoisonError::into_inner).take().is_some()
    }

    fn refuse(&self, text: String) -> Poll {
        if !self.keep_on_refusal {
            self.unload();
        }
        Poll::Refused(text)
    }

    /// R-17's report: an `Unchanged` or `Confirmed` look that finds the file turned stale is `Stale`, once.
    fn staleness(&self, outcome: Poll, now: SystemTime, max_stale: Duration) -> Poll {
        let stale = self.loaded().is_some_and(|l| !is_fresh(l.fresh_at, now, max_stale));
        let was = self.stale_seen.swap(stale, Ordering::SeqCst);
        match outcome {
            Poll::Unchanged | Poll::Confirmed if stale && !was => Poll::Stale,
            other => other,
        }
    }
}

/// R-17: fresh while `now - fresh_at <= max_stale`; a fetch time ahead of `now` is fresh.
pub(crate) fn is_fresh(fresh_at: Option<SystemTime>, now: SystemTime, max_stale: Duration) -> bool {
    match fresh_at {
        Some(t) => now.duration_since(t).map_or(true, |age| age <= max_stale),
        None => false,
    }
}

/// At most `FILE_MAX_BYTES + 1` bytes; more is refused before any parse (§R-relay.3.5).
fn read_capped(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("unreadable: {}", e.kind()))?;
    let mut bytes = Vec::new();
    file.take(FILE_MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|e| format!("unreadable: {}", e.kind()))?;
    if bytes.len() as u64 > FILE_MAX_BYTES {
        return Err(format!("over {FILE_MAX_BYTES} bytes"));
    }
    Ok(bytes)
}

/// The decimal unix seconds in `fetched`; unreadable or absent is none (R-16).
pub(crate) fn read_fetched(path: &Path) -> Option<SystemTime> {
    let mut text = String::new();
    File::open(path).ok()?.take(64).read_to_string(&mut text).ok()?;
    let secs: u64 = text.trim().parse().ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// The four watched files of the live directory and its `fetched` stamp.
pub struct Live {
    /// `workers.json`.
    pub workers: Watched<Workers>,
    /// `token-signers.json`.
    pub signers: Watched<Signers>,
    /// `grants.json`.
    pub grants: Watched<Grants>,
    /// `tls.pem`.
    pub tls: Watched<rustls::ServerConfig>,
    fetched: PathBuf,
}

impl Live {
    /// The live directory at `dir`.
    pub fn new(dir: &Path) -> Live {
        Live {
            workers: Watched::new(dir.join(WORKERS_FILE)),
            signers: Watched::new(dir.join(SIGNERS_FILE)),
            grants: Watched::new(dir.join(GRANTS_FILE)),
            tls: Watched::new(dir.join(TLS_FILE)).keeping_on_refusal(),
            fetched: dir.join(FETCHED_FILE),
        }
    }

    /// Polls all four in the order workers, token-signers, grants, tls; returns each one's outcome.
    pub fn poll(&self, now: SystemTime, max_stale: Duration) -> [(&'static str, Poll); 4] {
        let fetched_at = read_fetched(&self.fetched);
        let workers = self.workers.poll(fetched_at, crate::lists::parse_workers);
        let workers = self.workers.staleness(workers, now, max_stale);
        let signers = self.signers.poll(fetched_at, crate::lists::parse_signers);
        let signers = self.signers.staleness(signers, now, max_stale);
        let grants = self.grants.poll(fetched_at, crate::lists::parse_grants);
        let grants = self.grants.staleness(grants, now, max_stale);
        let tls = self.tls.poll(fetched_at, crate::tls::server_config);
        [("workers", workers), ("token-signers", signers), ("grants", grants), ("tls", tls)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_certs;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn workers_json(not_after: &str) -> String {
        let key = ai_env_worker::keys::SigningKey::from_seed(&[1; 32]).unwrap().public_key().b64();
        ai_env_worker::policy::render_workers(&[crate::lists::WorkerEntry {
            worker_id: "worker-a".into(),
            alg: "ed25519".into(),
            public_key: key,
            sources: vec!["example.alpha*".into()],
            not_after: not_after.into(),
        }])
        .unwrap()
    }

    /// Unit 25.
    #[test]
    fn a_live_file_is_fresh_as_of_its_fetch() {
        assert_eq!(content_version(b"{}"), 0x4413_6fa3_55b3_678a);
        let dir = tempfile::tempdir().unwrap();
        let live = Live::new(dir.path());
        let max = Duration::from_secs(900);
        let (t1, t2) = (1_800_000_000u64, 1_800_000_600u64);
        let body = workers_json("2027-12-31T23:59:59Z");
        std::fs::write(dir.path().join(WORKERS_FILE), &body).unwrap();

        let [(name, first), ..] = live.poll(at(t1), max);
        assert_eq!(name, "workers");
        assert_eq!(first, Poll::Loaded { version: content_version(body.as_bytes()) });
        assert!(live.workers.loaded().is_some());
        assert!(live.workers.fresh(at(t1), max).is_none(), "loaded with no fetch time is not fresh");

        std::fs::write(dir.path().join(FETCHED_FILE), format!("{t1}\n")).unwrap();
        live.poll(at(t1), max);
        assert!(live.workers.fresh(at(t1 + 900), max).is_some());
        assert!(live.workers.fresh(at(t1 + 901), max).is_none());

        std::fs::write(dir.path().join(FETCHED_FILE), format!("{t2}\n")).unwrap();
        assert_eq!(live.poll(at(t2), max)[0].1, Poll::Unchanged);
        assert!(live.workers.fresh(at(t2 + 900), max).is_some());
        assert!(live.workers.fresh(at(t2 + 901), max).is_none());

        // Rewritten with its old bytes (a new inode and mtime), `fetched` untouched: the mtime sets nothing.
        std::thread::sleep(Duration::from_millis(20));
        let tmp = dir.path().join("workers.tmp");
        std::fs::write(&tmp, &body).unwrap();
        std::fs::rename(&tmp, dir.path().join(WORKERS_FILE)).unwrap();
        assert_eq!(live.poll(at(t2), max)[0].1, Poll::Confirmed);
        assert_eq!(live.workers.loaded().unwrap().fresh_at, Some(at(t2)));

        std::fs::write(dir.path().join(FETCHED_FILE), "x\n").unwrap();
        live.poll(at(t2), max);
        assert_eq!(live.workers.loaded().unwrap().fresh_at, Some(at(t2)), "an unreadable fetched is no fetch time");

        std::fs::write(dir.path().join(WORKERS_FILE), b"[{\"worker_id\":").unwrap();
        assert!(matches!(live.poll(at(t2), max)[0].1, Poll::Refused(_)));
        assert!(live.workers.loaded().is_none());

        std::fs::write(dir.path().join(WORKERS_FILE), &body).unwrap();
        assert!(matches!(live.poll(at(t2), max)[0].1, Poll::Loaded { .. }));
        std::fs::remove_file(dir.path().join(WORKERS_FILE)).unwrap();
        assert_eq!(live.poll(at(t2), max)[0].1, Poll::Missing);
        assert!(live.workers.loaded().is_none());
        assert_eq!(live.poll(at(t2), max)[0].1, Poll::Unchanged, "an absent file is reported once");

        let ca = test_certs::Ca::new("test relay CA", [11; 32]);
        let leaf = ca.leaf(1, &["ai-env-relay"], &[[10, 42, 0, 20]], [12; 32]);
        std::fs::write(dir.path().join(TLS_FILE), test_certs::tls_pem(&leaf, &ca)).unwrap();
        assert!(matches!(live.poll(at(t2), max)[3].1, Poll::Loaded { .. }));
        let other = ca.leaf(2, &["ai-env-relay"], &[[10, 42, 0, 20]], [13; 32]);
        let mismatched = test_certs::tls_pem_with_key(&leaf, &ca, &other);
        std::fs::write(dir.path().join(TLS_FILE), mismatched).unwrap();
        assert!(matches!(live.poll(at(t2), max)[3].1, Poll::Refused(_)));
        assert!(live.tls.loaded().is_some(), "a refused tls.pem keeps the loaded config");
        std::fs::remove_file(dir.path().join(TLS_FILE)).unwrap();
        assert_eq!(live.poll(at(t2), max)[3].1, Poll::Missing);
        assert!(live.tls.loaded().is_none(), "a missing tls.pem is unloaded");
    }

    #[test]
    fn a_stale_list_is_reported_once_per_turn() {
        let dir = tempfile::tempdir().unwrap();
        let live = Live::new(dir.path());
        let max = Duration::from_secs(900);
        std::fs::write(dir.path().join(WORKERS_FILE), workers_json("2027-12-31T23:59:59Z")).unwrap();
        std::fs::write(dir.path().join(FETCHED_FILE), "1800000000\n").unwrap();
        assert!(matches!(live.poll(at(1_800_000_000), max)[0].1, Poll::Loaded { .. }));
        assert_eq!(live.poll(at(1_800_000_901), max)[0].1, Poll::Stale);
        assert_eq!(live.poll(at(1_800_000_902), max)[0].1, Poll::Unchanged);
        std::fs::write(dir.path().join(FETCHED_FILE), "1800000950\n").unwrap();
        assert_eq!(live.poll(at(1_800_000_950), max)[0].1, Poll::Unchanged);
        assert!(live.workers.fresh(at(1_800_000_950), max).is_some(), "a fresh fetch restores it");
        assert_eq!(live.poll(at(1_800_002_000), max)[0].1, Poll::Stale, "a second turn is reported again");
    }
}
