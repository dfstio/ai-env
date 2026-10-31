//! Tunnels, sources and catalog validation (R-19 to R-26, R-49). Synchronous only (R-75, a `make lint` guard):
//! nothing in this file awaits; methods return owned values, never a map guard.
//!
//! Tunnels are keyed by worker id, each with its connection's `conn_id`; a source entry names the (worker id,
//! conn id) that registered it, with the key that tunnel proved, and is live only while that pair is the worker's
//! current tunnel (R-25). Installs, teardowns and the poll's sweep (R-26) take one short lock so a catalog is pointed
//! whole or not at all (R-23); routing reads without it.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use ai_env_relay_proto::v1::{Close, RelayFrame, SourceDescriptor, SourceStatus};
use dashmap::DashMap;
use tokio_util::sync::CancellationToken;

use crate::calls::CallTable;
use crate::lists::{WorkerEntry, Workers};

/// The most sources of one catalog.
pub const SOURCES_MAX: usize = 64;
/// The most ops of one source.
pub const OPS_MAX: usize = 64;
/// The longest description.
pub const TEXT_MAX: usize = 2048;
/// The longest params schema.
pub const SCHEMA_MAX: usize = 16_384;
/// The most examples of one op.
pub const EXAMPLES_MAX: usize = 8;
/// The longest example.
pub const EXAMPLE_MAX: usize = 4096;
/// The longest version.
pub const VERSION_MAX: usize = 64;
/// The longest env tag.
pub const ENV_MAX: usize = 32;

/// Ends a tunnel: stores its Close frame, then cancels its token (both synchronous).
#[derive(Clone)]
pub struct Closer {
    token: CancellationToken,
    close: Arc<Mutex<Option<Close>>>,
}

impl Closer {
    /// A tunnel not closed yet.
    pub(crate) fn new() -> Closer {
        Closer { token: CancellationToken::new(), close: Arc::new(Mutex::new(None)) }
    }

    /// Stores `Close{code, reason}` and cancels the tunnel; the first close wins (one Close per tunnel, R-27).
    pub fn close(&self, code: u32, reason: &str) {
        {
            let mut stored = self.close.lock().unwrap_or_else(PoisonError::into_inner);
            if stored.is_none() && !self.token.is_cancelled() {
                *stored = Some(Close { code, reason: reason.to_string() });
            }
        }
        self.token.cancel();
    }

    /// Whether it was closed.
    pub fn is_closed(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Ends the tunnel with no Close frame (the worker ended its stream first).
    pub(crate) fn end(&self) {
        self.token.cancel();
    }

    /// The stored Close (the response stream yields it once, R-27; the teardown reads it too).
    pub(crate) fn stored(&self) -> Option<Close> {
        self.close.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The stored Close's code and reason, if any.
    pub(crate) fn peek(&self) -> Option<(u32, String)> {
        self.close.lock().unwrap_or_else(PoisonError::into_inner).as_ref().map(|c| (c.code, c.reason.clone()))
    }

    /// The token the tunnel's tasks wait on.
    pub(crate) fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

/// One live tunnel.
#[derive(Clone)]
pub struct TunnelHandle {
    /// The connection's id (R-24's `remove_if`).
    pub conn_id: u64,
    /// `AuthOk.tunnel_id`.
    pub tunnel_id: uuid::Uuid,
    /// The worker's id.
    pub worker_id: String,
    /// The worker's key.
    pub public_key: [u8; 32],
    /// `Hello.sdk_version`.
    pub sdk_version: String,
    /// The tunnel's outbound queue.
    pub tx: tokio::sync::mpsc::Sender<Result<RelayFrame, tonic::Status>>,
    /// Its calls.
    pub calls: Arc<CallTable>,
    /// Its closer.
    pub closer: Closer,
    /// The last frame's time, unix ms.
    pub last_seen_ms: Arc<AtomicI64>,
    /// When it authenticated, unix seconds.
    pub since_unix: u64,
    /// Its connection's peer, canonical (`PeerInfo.ip`): every poll judges it against the peers file (R-90).
    pub peer_ip: std::net::IpAddr,
}

/// Why a catalog was refused (R-21, R-23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogRefusal {
    /// No source.
    Empty,
    /// A field out of R-21's caps.
    Shape(String),
    /// A source outside the entry's globs.
    NotAllowed(String),
    /// A source listed twice.
    Twice(String),
    /// A source another live worker serves.
    Taken(String),
}

impl CatalogRefusal {
    /// R-21's and R-23's texts.
    pub fn reason(&self) -> String {
        match self {
            CatalogRefusal::Empty => "catalog: no source".to_string(),
            CatalogRefusal::Shape(text) => text.clone(),
            CatalogRefusal::NotAllowed(name) => format!("source {name} is not allowed for this worker"),
            CatalogRefusal::Twice(name) => format!("source {name} is listed twice"),
            CatalogRefusal::Taken(name) => format!("source {name} is served by another worker"),
        }
    }
}

/// Where a source's calls go.
pub enum Route {
    /// Its live tunnel and its descriptor.
    Live(TunnelHandle, Arc<SourceDescriptor>),
    /// Known, but no worker serves it now.
    Offline,
    /// Never seen.
    Unknown,
}

#[derive(Clone)]
struct SourceEntry {
    worker_id: String,
    conn_id: u64,
    /// The key its tunnel authenticated with: the sweep keeps the entry only while the whitelist holds it (R-26).
    public_key: [u8; 32],
    descriptor: Arc<SourceDescriptor>,
    /// When its tunnel went (unix ms); None while its tunnel is up.
    offline_since_ms: Option<i64>,
}

/// The tunnels and the sources.
pub struct Registry {
    tunnels: DashMap<String, TunnelHandle>,
    sources: DashMap<String, SourceEntry>,
    next_conn: AtomicU64,
    /// Installs, teardowns and the poll's sweep, one at a time (R-23's whole-or-nothing pointing).
    writes: Mutex<()>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Registry {
        Registry { tunnels: DashMap::new(), sources: DashMap::new(), next_conn: AtomicU64::new(1), writes: Mutex::new(()) }
    }

    /// A fresh connection id.
    pub fn next_conn_id(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::SeqCst)
    }

    /// R-21 to R-23: validate, point the names, replace the worker's tunnel (or this tunnel's own catalog);
    /// returns a superseded handle.
    pub fn install(&self, handle: TunnelHandle, entry: &WorkerEntry, catalog: Vec<SourceDescriptor>, now_ms: i64) -> Result<Option<TunnelHandle>, CatalogRefusal> {
        validate_catalog(entry, &catalog)?;
        let _writes = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        // Every check before any change: a refused catalog points nothing (R-22, R-23).
        for d in &catalog {
            let holder = self.sources.get(&d.name).map(|e| e.value().clone());
            if let Some(e) = holder {
                if e.worker_id != handle.worker_id && self.is_live(&e) {
                    return Err(CatalogRefusal::Taken(d.name.clone()));
                }
            }
        }
        let current = self.tunnels.get(&handle.worker_id).map(|t| t.value().clone());
        let superseded = current.filter(|t| t.conn_id != handle.conn_id);
        let names: BTreeSet<&str> = catalog.iter().map(|d| d.name.as_str()).collect();
        // The new catalog is the worker's whole set (R-23, R-28): every other entry of this worker goes, whatever its
        // conn_id, the replaced tunnel's and those earlier tunnels left offline alike (R-26). A call already routed
        // to one runs on in its own tunnel's call table.
        self.sources.retain(|name, e| e.worker_id != handle.worker_id || names.contains(name.as_str()));
        // A live entry's `last_seen` is its tunnel's; `now_ms` dates only a teardown (`remove`).
        let _ = now_ms;
        for d in catalog {
            let entry = SourceEntry {
                worker_id: handle.worker_id.clone(),
                conn_id: handle.conn_id,
                public_key: handle.public_key,
                descriptor: Arc::new(d),
                offline_since_ms: None,
            };
            self.sources.insert(entry.descriptor.name.clone(), entry);
        }
        self.tunnels.insert(handle.worker_id.clone(), handle);
        Ok(superseded)
    }

    /// R-24: `remove_if(conn_id == mine)`, then its sources offline; when `revoked`, every entry of the worker is
    /// removed instead, whatever its conn_id, except those of a newer tunnel that is now the worker's current one.
    pub fn remove(&self, worker_id: &str, conn_id: u64, now_ms: i64, revoked: bool) -> bool {
        let _writes = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        let removed = self.tunnels.remove_if(worker_id, |_, t| t.conn_id == conn_id).is_some();
        if revoked {
            // Nothing of a revoked worker stays offline (R-18, R-26), older tunnels' entries included. The reconnect
            // race's newer tunnel keeps its own (R-24): R-18's next poll and the sweep judge it.
            let current = self.tunnels.get(worker_id).map(|t| t.conn_id);
            self.sources.retain(|_, e| e.worker_id != worker_id || Some(e.conn_id) == current);
        } else {
            for mut e in self.sources.iter_mut() {
                if e.worker_id == worker_id && e.conn_id == conn_id && e.offline_since_ms.is_none() {
                    e.offline_since_ms = Some(now_ms);
                }
            }
        }
        removed
    }

    /// R-26's sweep, on each poll with the workers file loaded and fresh: every entry, live or offline, goes whose
    /// worker the file no longer allows, that is with no entry in force at `now_unix` holding the key that registered
    /// it, or with a name that entry's globs no longer allow. Each entry is judged by its own worker's entry alone, so
    /// no other worker's is touched. Returns how many went, and each tunnel that lost a live entry and is still its
    /// worker's current one: serve.rs closes those as R-18 does, so a catalog installed after R-18 read the live
    /// tunnels is never left cut and open.
    pub(crate) fn sweep(&self, workers: &Workers, now_unix: u64) -> (usize, Vec<TunnelHandle>) {
        let _writes = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        let before = self.sources.len();
        let mut cut = BTreeSet::new();
        self.sources.retain(|name, e| {
            let keep = workers.in_force(&e.worker_id, now_unix).is_some_and(|w| holds_key(w, &e.public_key) && w.allows_source(name));
            if !keep && e.offline_since_ms.is_none() {
                cut.insert((e.worker_id.clone(), e.conn_id));
            }
            keep
        });
        // After the retain, so no sources shard is held while a tunnels shard is read (install's order).
        let cut = cut
            .into_iter()
            .filter_map(|(worker_id, conn_id)| self.tunnels.get(&worker_id).map(|t| t.value().clone()).filter(|t| t.conn_id == conn_id))
            .collect();
        (before.saturating_sub(self.sources.len()), cut)
    }

    /// The route of `source` (R-25).
    pub fn route(&self, source: &str) -> Route {
        let Some(entry) = self.sources.get(source).map(|e| e.value().clone()) else {
            return Route::Unknown;
        };
        if entry.offline_since_ms.is_some() {
            return Route::Offline;
        }
        match self.tunnels.get(&entry.worker_id).map(|t| t.value().clone()) {
            Some(t) if t.conn_id == entry.conn_id => Route::Live(t, entry.descriptor),
            _ => Route::Offline,
        }
    }

    /// The descriptor `source` was registered with, live or offline (R-31 checks the op before `Offline`).
    pub(crate) fn descriptor(&self, source: &str) -> Option<Arc<SourceDescriptor>> {
        self.sources.get(source).map(|e| Arc::clone(&e.value().descriptor))
    }

    /// Every source (live and offline), sorted by name, with `available` and `last_seen_unix_ms` (R-49).
    pub fn statuses(&self) -> Vec<SourceStatus> {
        let entries: Vec<SourceEntry> = self.sources.iter().map(|e| e.value().clone()).collect();
        let mut out: Vec<SourceStatus> = entries
            .into_iter()
            .map(|e| {
                let tunnel = self.tunnels.get(&e.worker_id).map(|t| t.value().clone()).filter(|t| t.conn_id == e.conn_id && e.offline_since_ms.is_none());
                let (available, last_seen) = match (&tunnel, e.offline_since_ms) {
                    (Some(t), _) => (true, t.last_seen_ms.load(Ordering::SeqCst)),
                    (None, Some(ms)) => (false, ms),
                    (None, None) => (false, 0),
                };
                SourceStatus { descriptor: Some((*e.descriptor).clone()), available, last_seen_unix_ms: last_seen }
            })
            .collect();
        out.sort_by(|a, b| name_of(a).cmp(name_of(b)));
        out
    }

    /// The live tunnels.
    pub fn live(&self) -> Vec<TunnelHandle> {
        self.tunnels.iter().map(|t| t.value().clone()).collect()
    }

    /// How many tunnels are live.
    pub fn tunnels(&self) -> usize {
        self.tunnels.len()
    }

    /// Whether `worker_id` holds a tunnel (R-12's cap counts it once).
    pub(crate) fn holds(&self, worker_id: &str) -> bool {
        self.tunnels.contains_key(worker_id)
    }

    /// The names a tunnel registered (R-18's narrowing check).
    pub(crate) fn sources_of(&self, worker_id: &str, conn_id: u64) -> Vec<String> {
        self.sources.iter().filter(|e| e.worker_id == worker_id && e.conn_id == conn_id).map(|e| e.key().clone()).collect()
    }

    /// Live and offline sources (the status line).
    pub(crate) fn counts(&self) -> (usize, usize) {
        let live = self.statuses().iter().filter(|s| s.available).count();
        (live, self.sources.len() - live)
    }

    fn is_live(&self, e: &SourceEntry) -> bool {
        e.offline_since_ms.is_none() && self.tunnels.get(&e.worker_id).is_some_and(|t| t.conn_id == e.conn_id)
    }
}

fn name_of(s: &SourceStatus) -> &str {
    s.descriptor.as_ref().map_or("", |d| d.name.as_str())
}

/// Whether `entry` whitelists `key`: R-10's pair, `ed25519` and the key byte for byte (R-18 and R-26 alike).
pub(crate) fn holds_key(entry: &WorkerEntry, key: &[u8; 32]) -> bool {
    entry.alg == "ed25519" && ai_env_worker::keys::PublicKey::parse_b64(&entry.public_key).is_ok_and(|k| k.bytes() == key)
}

impl Default for Registry {
    /// `Registry::new()`.
    fn default() -> Self {
        Registry::new()
    }
}

/// Names through `ai_env_worker::globs::valid_id`, the entry's globs through `WorkerEntry::allows_source` (R-21);
/// after each source's R-21 checks, its text's control and format characters ([`text_fault`], R-115).
pub fn validate_catalog(entry: &WorkerEntry, catalog: &[SourceDescriptor]) -> Result<(), CatalogRefusal> {
    use ai_env_worker::globs::valid_id;
    if catalog.is_empty() {
        return Err(CatalogRefusal::Empty);
    }
    if catalog.len() > SOURCES_MAX {
        return Err(CatalogRefusal::Shape(format!("catalog: over {SOURCES_MAX} sources")));
    }
    let shape = |name: &str, what: String| CatalogRefusal::Shape(format!("source {name}: {what}"));
    let mut seen = BTreeSet::new();
    for d in catalog {
        if !valid_id(&d.name) {
            return Err(CatalogRefusal::Shape(format!("catalog: {:?} is not a source name", cut(&d.name, 64))));
        }
        if !entry.allows_source(&d.name) {
            return Err(CatalogRefusal::NotAllowed(d.name.clone()));
        }
        if !seen.insert(d.name.as_str()) {
            return Err(CatalogRefusal::Twice(d.name.clone()));
        }
        for (field, len, max) in [("version", d.version.len(), VERSION_MAX), ("description", d.description.len(), TEXT_MAX), ("env", d.env.len(), ENV_MAX)] {
            if len > max {
                return Err(shape(&d.name, format!("{field} over {max} bytes")));
            }
        }
        if d.ops.is_empty() || d.ops.len() > OPS_MAX {
            return Err(shape(&d.name, format!("1 to {OPS_MAX} ops, not {}", d.ops.len())));
        }
        let mut ops = BTreeSet::new();
        for op in &d.ops {
            if !valid_id(&op.name) {
                return Err(shape(&d.name, format!("{:?} is not an op name", cut(&op.name, 64))));
            }
            if !ops.insert(op.name.as_str()) {
                return Err(shape(&d.name, format!("op {} is listed twice", op.name)));
            }
            if op.description.len() > TEXT_MAX {
                return Err(shape(&d.name, format!("op {}: description over {TEXT_MAX} bytes", op.name)));
            }
            let schema_ok = op.params_json_schema.is_empty()
                || (op.params_json_schema.len() <= SCHEMA_MAX && serde_json::from_str::<serde_json::Value>(&op.params_json_schema).is_ok_and(|v| v.is_object()));
            if !schema_ok {
                return Err(shape(&d.name, format!("op {}: params_json_schema is not a JSON object of at most {SCHEMA_MAX} bytes", op.name)));
            }
            if op.examples.len() > EXAMPLES_MAX {
                return Err(shape(&d.name, format!("op {}: over {EXAMPLES_MAX} examples", op.name)));
            }
            if op.examples.iter().any(|x| x.len() > EXAMPLE_MAX || serde_json::from_str::<serde::de::IgnoredAny>(x).is_err()) {
                return Err(shape(&d.name, format!("op {}: an example is not JSON of at most {EXAMPLE_MAX} bytes", op.name)));
            }
        }
        if let Some(what) = text_fault(d) {
            return Err(shape(&d.name, what));
        }
    }
    Ok(())
}

/// Unicode 16.0's General_Category=Format (Cf) as inclusive ranges: 21 ranges, 170 code points (R-115). The bidi
/// embeddings, overrides and isolates, the zero-width spaces and joiners, the soft hyphen and the tag characters
/// among them: text a reader is not shown, or shown in another order.
pub const FORMAT_CHARS: [(u32, u32); 21] = [
    (0x00ad, 0x00ad),
    (0x0600, 0x0605),
    (0x061c, 0x061c),
    (0x06dd, 0x06dd),
    (0x070f, 0x070f),
    (0x0890, 0x0891),
    (0x08e2, 0x08e2),
    (0x180e, 0x180e),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x2064),
    (0x2066, 0x206f),
    (0xfeff, 0xfeff),
    (0xfff9, 0xfffb),
    (0x110bd, 0x110bd),
    (0x110cd, 0x110cd),
    (0x13430, 0x1343f),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0001, 0xe0001),
    (0xe0020, 0xe007f),
];

/// Whether `c` is a Cf character ([`FORMAT_CHARS`]).
fn is_format(c: char) -> bool {
    let c = u32::from(c);
    FORMAT_CHARS.iter().any(|&(first, last)| (first..=last).contains(&c))
}

/// R-115: what `version` and `env` refuse: any Cc character (U+0000 to U+001F, U+007F to U+009F: `char::is_control`)
/// or any Cf character.
fn refused_in_word(c: char) -> bool {
    c.is_control() || is_format(c)
}

/// R-115: what the descriptions, the examples and the schema refuse: any Cc character but TAB, LF and CR (a
/// description may run over lines; JSON's whitespace is theirs), or any Cf character.
fn refused_in_text(c: char) -> bool {
    (c.is_control() && !matches!(c, '\t' | '\n' | '\r')) || is_format(c)
}

/// R-115 (LD-R28): whether a JSON text R-21 took holds a refused character ([`refused_in_text`]), raw or in a string
/// it decodes to, keys and values alike, so an escaped `\u202e` is refused as the raw one is. Every `\` of valid JSON
/// opens an escape inside a string, so the escapes are decoded in order, each to its character (a surrogate pair's
/// two escapes to their one); a lone surrogate decodes to no character and refuses nothing. Everything else is the
/// raw text, already checked. An escape that is not JSON's is refused (R-21 took no such text).
fn json_refused(text: &str) -> bool {
    if text.chars().any(refused_in_text) {
        return true;
    }
    let b = text.as_bytes();
    // The UTF-16 unit of the four hex digits at `at` (a `\u` escape's).
    let unit = |at: usize| {
        let digits = b.get(at..at + 4).filter(|h| h.iter().all(u8::is_ascii_hexdigit))?;
        u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
    };
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            i += 1;
            continue;
        }
        let (code, len) = match b.get(i + 1) {
            Some(b'"') => (0x22, 2),
            Some(b'\\') => (0x5c, 2),
            Some(b'/') => (0x2f, 2),
            Some(b'b') => (0x08, 2),
            Some(b'f') => (0x0c, 2),
            Some(b'n') => (0x0a, 2),
            Some(b'r') => (0x0d, 2),
            Some(b't') => (0x09, 2),
            Some(b'u') => match (unit(i + 2), b.get(i + 6..i + 8), unit(i + 8)) {
                (Some(high @ 0xd800..=0xdbff), Some(br"\u"), Some(low @ 0xdc00..=0xdfff)) => (0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00), 12),
                (Some(one), _, _) => (one, 6),
                (None, _, _) => return true,
            },
            _ => return true,
        };
        if char::from_u32(code).is_some_and(refused_in_text) {
            return true;
        }
        i += len;
    }
    false
}

/// R-115: the first control or format character of a source, as its refusal's text after `source <name>: `, in this
/// order: `version`, `env`, `description`, then each op's `description`, examples and `params_json_schema`. Run after
/// the source's R-21 checks, so the JSON fields are JSON and the op names ids.
fn text_fault(d: &SourceDescriptor) -> Option<String> {
    const HOLDS: &str = "holds a control or format character";
    if d.version.chars().any(refused_in_word) {
        return Some(format!("version {HOLDS}"));
    }
    if d.env.chars().any(refused_in_word) {
        return Some(format!("env {HOLDS}"));
    }
    if d.description.chars().any(refused_in_text) {
        return Some(format!("description {HOLDS}"));
    }
    for op in &d.ops {
        if op.description.chars().any(refused_in_text) {
            return Some(format!("op {}: description {HOLDS}", op.name));
        }
        if op.examples.iter().any(|x| json_refused(x)) {
            return Some(format!("op {}: an example {HOLDS}", op.name));
        }
        if json_refused(&op.params_json_schema) {
            return Some(format!("op {}: params_json_schema {HOLDS}", op.name));
        }
    }
    None
}

/// At most `max` bytes of `s`, cut at a character boundary.
fn cut(s: &str, max: usize) -> &str {
    let mut i = s.len().min(max);
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ai_env_relay_proto::v1::OpDescriptor;

    fn entry(globs: &[&str]) -> WorkerEntry {
        WorkerEntry {
            worker_id: "worker-a".into(),
            alg: "ed25519".into(),
            public_key: String::new(),
            sources: globs.iter().map(|g| g.to_string()).collect(),
            not_after: "2027-01-01T23:59:59Z".into(),
            tls_fp: None,
        }
    }

    fn source(name: &str) -> SourceDescriptor {
        SourceDescriptor {
            name: name.into(),
            version: "1.0.0".into(),
            description: "a test source".into(),
            kind: 7,
            env: "test".into(),
            sensitivity: 2,
            ops: vec![OpDescriptor { name: "get".into(), output: 1, read_only: true, ..Default::default() }],
        }
    }

    /// Unit 1.
    #[test]
    fn catalog_names_follow_the_shared_id_rule() {
        let all = entry(&["*"]);
        for name in ["a", "example.alpha-1_x", &"a".repeat(64)] {
            assert_eq!(validate_catalog(&all, &[source(name)]), Ok(()), "{name}");
            assert!(ai_env_worker::globs::valid_id(name));
        }
        for name in ["A", "-a", ".a", "a b", &"a".repeat(65)] {
            let refused = validate_catalog(&all, &[source(name)]).unwrap_err();
            assert_eq!(refused.reason(), format!("catalog: {:?} is not a source name", cut(name, 64)));
            assert!(!ai_env_worker::globs::valid_id(name), "the shared rule says the same of {name}");
        }
    }

    /// Unit 2.
    #[test]
    fn every_entry_glob_binds_the_catalog() {
        let e = entry(&["other.*", "example.*"]);
        assert_eq!(validate_catalog(&e, &[source("example.alpha")]), Ok(()));
        assert_eq!(validate_catalog(&e, &[source("other.x")]), Ok(()), "the second glob is consulted too");
        for name in ["example", "xexample.a"] {
            assert_eq!(validate_catalog(&e, &[source(name)]).unwrap_err().reason(), format!("source {name} is not allowed for this worker"));
        }
    }

    #[test]
    fn catalog_shapes_are_bounded() {
        let e = entry(&["*"]);
        assert_eq!(validate_catalog(&e, &[]).unwrap_err().reason(), "catalog: no source");
        let many: Vec<_> = (0..65).map(|i| source(&format!("s{i}"))).collect();
        assert_eq!(validate_catalog(&e, &many).unwrap_err().reason(), "catalog: over 64 sources");
        assert_eq!(validate_catalog(&e, &[source("a"), source("a")]).unwrap_err().reason(), "source a is listed twice");
        let mut bad_op = source("a");
        bad_op.ops[0].name = "Bad".into();
        assert!(validate_catalog(&e, &[bad_op]).is_err());
        let mut schema = source("a");
        schema.ops[0].params_json_schema = "not json".into();
        assert!(validate_catalog(&e, &[schema]).is_err());
        let mut text = source("a");
        text.description = "d".repeat(2049);
        assert!(validate_catalog(&e, &[text]).is_err());
        let mut example = source("a");
        example.ops[0].examples = vec!["{\"n\":1}".into()];
        example.ops[0].params_json_schema = "{\"type\":\"object\"}".into();
        assert_eq!(validate_catalog(&e, &[example]), Ok(()));
    }

    fn key_of(seed: u8) -> ai_env_worker::keys::PublicKey {
        ai_env_worker::keys::SigningKey::from_seed(&[seed; 32]).unwrap().public_key()
    }

    /// `worker_id`'s whitelist entry: a seed's key, these globs, in force through 2027-01-01.
    pub(crate) fn whitelisted(worker_id: &str, seed: u8, globs: &[&str]) -> WorkerEntry {
        WorkerEntry { worker_id: worker_id.into(), public_key: key_of(seed).b64(), ..entry(globs) }
    }

    /// A tunnel of `worker_id` with a seed's key, on a fresh conn_id.
    pub(crate) fn tunnel(reg: &Registry, worker_id: &str, seed: u8) -> TunnelHandle {
        let (tx, _) = tokio::sync::mpsc::channel(4);
        TunnelHandle {
            conn_id: reg.next_conn_id(),
            tunnel_id: uuid::Uuid::nil(),
            worker_id: worker_id.into(),
            public_key: *key_of(seed).bytes(),
            sdk_version: "0.1.0".into(),
            tx,
            calls: Arc::new(CallTable::new(4)),
            closer: Closer::new(),
            last_seen_ms: Arc::new(AtomicI64::new(0)),
            since_unix: 0,
            peer_ip: std::net::IpAddr::from([198, 51, 100, 10]),
        }
    }

    pub(crate) fn catalog(names: &[&str]) -> Vec<SourceDescriptor> {
        names.iter().map(|n| source(n)).collect()
    }

    /// Each name's route.
    fn routes(reg: &Registry, names: &[&str]) -> Vec<&'static str> {
        let word = |r: Route| match r {
            Route::Live(..) => "live",
            Route::Offline => "offline",
            Route::Unknown => "unknown",
        };
        names.iter().map(|n| word(reg.route(n))).collect()
    }

    /// Every registered name, live or offline, sorted (`statuses`, R-49).
    fn listed(reg: &Registry) -> Vec<String> {
        reg.statuses().iter().map(|s| name_of(s).to_string()).collect()
    }

    /// The workers file holding these entries.
    pub(crate) fn file(entries: &[WorkerEntry]) -> Workers {
        Workers { entries: entries.to_vec() }
    }

    /// The sweep's clock: 2026-10-29, before every `not_after` of these tests but the lapsed one.
    pub(crate) fn now() -> u64 {
        ai_env_worker::policy::unix_of("2026-10-29T12:00:00Z").unwrap()
    }

    /// R-23 (amended): catalog A on conn 1, its teardown, then catalog B on conn 2 with nothing to supersede: the
    /// names only in A are gone, not offline. A superseded live tunnel is cut the same way, and another worker's
    /// offline name is never the installing worker's to drop.
    #[test]
    fn a_new_catalog_drops_what_its_worker_left_out_whatever_the_conn() {
        let reg = Registry::new();
        let a = whitelisted("worker-a", 1, &["example.*"]);
        let tb = tunnel(&reg, "worker-b", 2);
        reg.install(tb.clone(), &whitelisted("worker-b", 2, &["other.*"]), catalog(&["other.x"]), 0).unwrap();
        assert!(reg.remove("worker-b", tb.conn_id, 1, false));

        let t1 = tunnel(&reg, "worker-a", 1);
        assert!(reg.install(t1.clone(), &a, catalog(&["example.one", "example.two"]), 0).unwrap().is_none());
        assert!(reg.remove("worker-a", t1.conn_id, 5, false));
        assert_eq!(routes(&reg, &["example.one", "example.two"]), ["offline", "offline"]);

        let t2 = tunnel(&reg, "worker-a", 1);
        assert!(reg.install(t2.clone(), &a, catalog(&["example.two", "example.three"]), 10).unwrap().is_none(), "no tunnel to supersede");
        assert_eq!(routes(&reg, &["example.one", "example.two", "example.three"]), ["unknown", "live", "live"]);

        let t3 = tunnel(&reg, "worker-a", 1);
        let superseded = reg.install(t3, &a, catalog(&["example.three"]), 20).unwrap().expect("conn 2 superseded");
        assert_eq!(superseded.conn_id, t2.conn_id);
        assert_eq!(routes(&reg, &["example.two", "example.three"]), ["unknown", "live"]);
        assert!(!reg.remove("worker-a", t2.conn_id, 25, false), "conn 2's teardown leaves conn 3 alone (R-24)");
        assert_eq!(listed(&reg), ["example.three", "other.x"]);
        assert_eq!(routes(&reg, &["example.three", "other.x"]), ["live", "offline"]);
    }

    /// R-24 (amended) with R-18: a revoked tunnel's teardown leaves nothing of its worker, an older tunnel's offline
    /// entries included, and touches no other worker; a newer tunnel that is the worker's current one keeps its
    /// own (the reconnect race).
    #[test]
    fn a_revoked_teardown_leaves_nothing_of_its_worker() {
        let reg = Registry::new();
        let a = whitelisted("worker-a", 1, &["example.*"]);
        let tb = tunnel(&reg, "worker-b", 2);
        reg.install(tb, &whitelisted("worker-b", 2, &["other.*"]), catalog(&["other.x"]), 0).unwrap();
        let t1 = tunnel(&reg, "worker-a", 1);
        reg.install(t1.clone(), &a, catalog(&["example.old"]), 0).unwrap();
        reg.remove("worker-a", t1.conn_id, 5, false);
        let t2 = tunnel(&reg, "worker-a", 1);
        reg.install(t2.clone(), &a, catalog(&["example.new"]), 10).unwrap();
        // R-23 dropped conn 1's entry at that install; it is put back as an older tunnel would have left it, so the
        // teardown is pinned on its own.
        let old = SourceEntry { worker_id: "worker-a".into(), conn_id: t1.conn_id, public_key: t1.public_key, descriptor: Arc::new(source("example.old")), offline_since_ms: Some(5) };
        reg.sources.insert("example.old".into(), old);
        assert_eq!(routes(&reg, &["example.old", "example.new"]), ["offline", "live"]);
        assert!(reg.remove("worker-a", t2.conn_id, 20, true));
        assert_eq!(listed(&reg), ["other.x"], "nothing of worker-a, whatever the conn_id");
        assert_eq!(routes(&reg, &["other.x"]), ["live"]);

        let t3 = tunnel(&reg, "worker-a", 1);
        reg.install(t3.clone(), &a, catalog(&["example.one"]), 30).unwrap();
        let t4 = tunnel(&reg, "worker-a", 1);
        reg.install(t4, &a, catalog(&["example.one", "example.two"]), 40).unwrap();
        assert!(!reg.remove("worker-a", t3.conn_id, 50, true), "conn 4 superseded conn 3 before its revoked teardown ran");
        assert_eq!(routes(&reg, &["example.one", "example.two", "other.x"]), ["live", "live", "live"]);
    }

    /// R-26's sweep: every entry, live or offline, of a worker with no entry in force holding the key that
    /// registered it goes (removed from the file, its key replaced, lapsed); the other worker's stay.
    #[test]
    fn the_sweep_drops_a_worker_the_file_no_longer_holds() {
        let reg = Registry::new();
        let a = whitelisted("worker-a", 1, &["example.*"]);
        let b = whitelisted("worker-b", 2, &["other.*"]);
        let stopped = |names: &[&str]| {
            let t = tunnel(&reg, "worker-a", 1);
            reg.install(t.clone(), &a, catalog(names), 0).unwrap();
            assert!(reg.remove("worker-a", t.conn_id, 5, false));
        };
        stopped(&["example.one", "example.two"]);
        let tb = tunnel(&reg, "worker-b", 2);
        reg.install(tb, &b, catalog(&["other.x"]), 0).unwrap();
        assert_eq!(reg.sweep(&file(&[a.clone(), b.clone()]), now()).0, 0, "both allowed");
        assert_eq!(routes(&reg, &["example.one", "example.two", "other.x"]), ["offline", "offline", "live"]);

        assert_eq!(reg.sweep(&file(std::slice::from_ref(&b)), now()).0, 2, "worker-a revoked from the file");
        assert_eq!(listed(&reg), ["other.x"]);

        stopped(&["example.one"]);
        let rotated = whitelisted("worker-a", 3, &["example.*"]);
        assert_eq!(reg.sweep(&file(&[rotated, b.clone()]), now()).0, 1, "the same id under another key");
        stopped(&["example.one"]);
        let lapsed = WorkerEntry { not_after: "2026-10-01T23:59:59Z".into(), ..a.clone() };
        assert_eq!(reg.sweep(&file(&[lapsed, b.clone()]), now()).0, 1, "no longer in force");
        assert_eq!(listed(&reg), ["other.x"]);

        assert_eq!(reg.sweep(&file(std::slice::from_ref(&a)), now()).0, 1, "a live entry goes too");
        assert!(listed(&reg).is_empty());
        assert_eq!(reg.tunnels(), 1, "worker-b's tunnel stays registered: serve.rs closes it (R-18)");
    }

    /// R-26's sweep after narrowed globs: each worker's names are judged by its own entry alone.
    #[test]
    fn the_sweep_drops_the_names_narrowed_globs_no_longer_allow() {
        let reg = Registry::new();
        let a = whitelisted("worker-a", 1, &["example.*"]);
        let b = whitelisted("worker-b", 2, &["example.beta*"]);
        let ta = tunnel(&reg, "worker-a", 1);
        reg.install(ta.clone(), &a, catalog(&["example.alpha", "example.alpha.logs", "example.beta2"]), 0).unwrap();
        assert!(reg.remove("worker-a", ta.conn_id, 5, false));
        let tb = tunnel(&reg, "worker-b", 2);
        reg.install(tb, &b, catalog(&["example.beta"]), 0).unwrap();

        // worker-a narrowed to `example.alpha`: its other names go, `example.beta2` too although worker-b's globs
        // would allow it; worker-b's live name stays.
        let a_narrowed = WorkerEntry { sources: vec!["example.alpha".into()], ..a.clone() };
        assert_eq!(reg.sweep(&file(&[a_narrowed.clone(), b.clone()]), now()).0, 2);
        assert_eq!(listed(&reg), ["example.alpha", "example.beta"]);
        assert_eq!(routes(&reg, &["example.alpha", "example.beta"]), ["offline", "live"]);

        // worker-b narrowed away from its live name: that entry goes as well.
        let b_narrowed = WorkerEntry { sources: vec!["example.beta.*".into()], ..b.clone() };
        assert_eq!(reg.sweep(&file(&[a_narrowed, b_narrowed]), now()).0, 1);
        assert_eq!(listed(&reg), ["example.alpha"]);
    }

    /// R-26's sweep with R-18 (review finding 2): it hands back each tunnel that lost a live entry, once, while that
    /// tunnel is its worker's current one; a stopped worker's offline entries and a tunnel left whole hand back none.
    #[test]
    fn the_sweep_hands_back_the_live_tunnels_it_cut() {
        let reg = Registry::new();
        let a = whitelisted("worker-a", 1, &["example.*"]);
        let b = whitelisted("worker-b", 2, &["other.*"]);
        let c = whitelisted("worker-c", 5, &["more.*"]);
        let ta = tunnel(&reg, "worker-a", 1);
        reg.install(ta.clone(), &a, catalog(&["example.alpha", "example.alpha.logs"]), 0).unwrap();
        let tb = tunnel(&reg, "worker-b", 2);
        reg.install(tb, &b, catalog(&["other.x"]), 0).unwrap();
        let tc = tunnel(&reg, "worker-c", 5);
        reg.install(tc.clone(), &c, catalog(&["more.x"]), 0).unwrap();
        assert!(reg.remove("worker-c", tc.conn_id, 5, false));

        // worker-a narrowed to `example.alpha` and worker-c gone from the file: two entries go, one of them live.
        let a_narrowed = WorkerEntry { sources: vec!["example.alpha".into()], ..a };
        let (swept, cut) = reg.sweep(&file(&[a_narrowed.clone(), b.clone()]), now());
        assert_eq!(swept, 2);
        let cut: Vec<(String, u64)> = cut.iter().map(|t| (t.worker_id.clone(), t.conn_id)).collect();
        assert_eq!(cut, [("worker-a".to_string(), ta.conn_id)], "worker-a's tunnel alone");
        let (swept, cut) = reg.sweep(&file(&[a_narrowed, b]), now());
        assert_eq!((swept, cut.len()), (0, 0), "nothing left to cut");
        assert_eq!(listed(&reg), ["example.alpha", "other.x"]);
    }

    /// Unit 44 (R-115, LD-R28): U+202E in each of R-115's fields is refused with that field's text; a description
    /// with a tab, LF and CR passes, as do JSON's whitespace and escaped tabs in an example or a schema; `version`
    /// and `env` refuse a tab or an LF; C0, DEL and C1 controls are refused; the escapes are refused as the raw
    /// characters are (`{"a":"\u202e"}`, the six characters, in an example; in a schema's key; a tag character as its
    /// surrogate pair; `\u0007` and `\b`), while an escaped backslash before `u202e` and a lone surrogate decode to no
    /// refused character; the check follows the source's R-21 checks and names the first fault; `FORMAT_CHARS` holds
    /// 21 ranges and 170 code points, R-115's list as the contract writes it, each refused, and ordinary text passes;
    /// for every character the check refuses exactly what the client's `convert::strip_controls` (R-116) drops, TAB,
    /// LF and CR aside in `version` and `env`, so the two tables cannot drift apart. Kills M-R152 (a range shifted
    /// too), M-R153.
    #[test]
    fn catalog_text_holds_no_control_or_format_character() {
        /// The refusal of a catalog of one source `a` (its op `get` with a schema and an example), edited.
        fn check(edit: impl Fn(&mut SourceDescriptor)) -> Result<(), String> {
            let mut d = source("a");
            d.ops[0].params_json_schema = "{\"type\":\"object\"}".into();
            d.ops[0].examples = vec!["{\"n\":1}".into()];
            edit(&mut d);
            validate_catalog(&entry(&["*"]), &[d]).map_err(|r| r.reason())
        }
        let holds = |what: &str| -> Result<(), String> { Err(format!("source a: {what} holds a control or format character")) };
        let hex = |c: char| format!("U+{:04X}", u32::from(c));
        assert_eq!(check(|_| ()), Ok(()));

        // U+202E (RIGHT-TO-LEFT OVERRIDE), raw, in each field.
        let rlo = '\u{202e}';
        assert_eq!(check(|d| d.version = format!("1.0{rlo}")), holds("version"));
        assert_eq!(check(|d| d.env = format!("te{rlo}st")), holds("env"));
        assert_eq!(check(|d| d.description = format!("a {rlo}test source")), holds("description"));
        assert_eq!(check(|d| d.ops[0].description = format!("get {rlo}it")), holds("op get: description"));
        assert_eq!(check(|d| d.ops[0].examples.push(format!("{{\"a\":\"{rlo}\"}}"))), holds("op get: an example"));
        assert_eq!(check(|d| d.ops[0].params_json_schema = format!("{{\"type\":\"object\",\"title\":\"{rlo}\"}}")), holds("op get: params_json_schema"));

        // TAB, LF and CR: a description's line breaks and JSON's whitespace, never a version's or an env's.
        let lines = "one\ttwo\nthree\r\nfour";
        assert_eq!(check(|d| d.description = lines.into()), Ok(()));
        assert_eq!(check(|d| d.ops[0].description = lines.into()), Ok(()));
        assert_eq!(check(|d| d.ops[0].examples.push("{\n\t\"a\": \"x\\ty\\nz\\r\"\r\n}".into())), Ok(()), "JSON's whitespace; TAB, LF and CR escaped");
        assert_eq!(check(|d| d.ops[0].params_json_schema = "{\n\t\"type\": \"object\",\r\n\t\"title\": \"a\\tb\"\n}".into()), Ok(()));
        assert_eq!(check(|d| d.version = "1.0\t".into()), holds("version"));
        assert_eq!(check(|d| d.env = "te\nst".into()), holds("env"));

        // Cc: C0, DEL and C1.
        for c in ['\u{0}', '\u{7}', '\u{1b}', '\u{7f}', '\u{85}', '\u{9f}'] {
            assert_eq!(check(|d| d.version = format!("1{c}")), holds("version"), "{}", hex(c));
            assert_eq!(check(|d| d.description = format!("a{c}b")), holds("description"), "{}", hex(c));
            assert_eq!(check(|d| d.ops[0].description = format!("a{c}b")), holds("op get: description"), "{}", hex(c));
        }

        // The escapes, as JSON decodes them.
        assert_eq!(r#"{"a":"\u202e"}"#.len(), 14, "the escape is six ASCII characters");
        assert_eq!(check(|d| d.ops[0].examples.push(r#"{"a":"\u202e"}"#.into())), holds("op get: an example"));
        assert_eq!(check(|d| d.ops[0].params_json_schema = r#"{"type":"object","properties":{"\u202Ex":{}}}"#.into()), holds("op get: params_json_schema"), "a key");
        assert_eq!(check(|d| d.ops[0].examples.push(r#"["\udb40\udc01"]"#.into())), holds("op get: an example"), "U+E0001 as its surrogate pair");
        assert_eq!(check(|d| d.ops[0].examples.push(r#"{"a":"\u0007"}"#.into())), holds("op get: an example"));
        assert_eq!(check(|d| d.ops[0].examples.push(r#"{"a":"\b"}"#.into())), holds("op get: an example"));
        assert_eq!(check(|d| d.ops[0].examples.push(r#"{"a\"\\\/":"\u00e9\ud83d\ude00\\u202e"}"#.into())), Ok(()), "an escaped backslash, then the text u202e");
        assert_eq!(check(|d| d.ops[0].examples.push(r#"["\ud800","\udc00x","\ud800\u0041"]"#.into())), Ok(()), "a lone surrogate decodes to no character");

        // After the source's R-21 checks, the first fault named.
        assert_eq!(check(|d| d.version = format!("{}{rlo}", "1".repeat(64))), Err("source a: version over 64 bytes".into()), "R-21's cap first");
        let bad_op = |d: &mut SourceDescriptor| {
            d.ops[0].description = format!("x{rlo}");
            let op = OpDescriptor { name: "Bad".into(), ..d.ops[0].clone() };
            d.ops.push(op);
        };
        assert_eq!(check(bad_op), Err("source a: \"Bad\" is not an op name".into()), "R-21's op checks first");
        let env_and_op = |d: &mut SourceDescriptor| {
            d.env = format!("t{rlo}");
            d.ops[0].description = format!("x{rlo}");
        };
        assert_eq!(check(env_and_op), holds("env"));
        let description_and_schema = |d: &mut SourceDescriptor| {
            d.description = format!("x{rlo}");
            d.ops[0].params_json_schema = format!("{{\"title\":\"{rlo}\"}}");
        };
        assert_eq!(check(description_and_schema), holds("description"));
        let example_and_schema = |d: &mut SourceDescriptor| {
            d.ops[0].examples[0] = format!("[\"{rlo}\"]");
            d.ops[0].params_json_schema = format!("{{\"title\":\"{rlo}\"}}");
        };
        assert_eq!(check(example_and_schema), holds("op get: an example"));
        let mut b = source("b");
        b.description = format!("b{rlo}");
        assert_eq!(validate_catalog(&entry(&["*"]), &[source("a"), b]).unwrap_err().reason(), "source b: description holds a control or format character");

        // FORMAT_CHARS: Unicode 16.0's Cf, 21 ranges and 170 code points, sorted and apart, R-115's list as the
        // contract writes it (a range moved, cut or widened fails here); each refused.
        assert_eq!(FORMAT_CHARS.len(), 21);
        assert_eq!(FORMAT_CHARS.iter().map(|&(first, last)| last - first + 1).sum::<u32>(), 170);
        assert!(FORMAT_CHARS.iter().all(|&(first, last)| first <= last) && FORMAT_CHARS.windows(2).all(|w| w[0].1 + 1 < w[1].0), "sorted and apart");
        let r115 = "U+00AD, U+0600..U+0605, U+061C, U+06DD, U+070F, U+0890..U+0891, U+08E2, U+180E, U+200B..U+200F, U+202A..U+202E, U+2060..U+2064, U+2066..U+206F, U+FEFF, U+FFF9..U+FFFB, U+110BD, U+110CD, U+13430..U+1343F, U+1BCA0..U+1BCA3, U+1D173..U+1D17A, U+E0001, U+E0020..U+E007F";
        let code = |s: &str| u32::from_str_radix(s.strip_prefix("U+").unwrap(), 16).unwrap();
        let listed: Vec<(u32, u32)> = r115.split(", ").map(|r| r.split_once("..").map_or_else(|| (code(r), code(r)), |(first, last)| (code(first), code(last)))).collect();
        assert_eq!(FORMAT_CHARS.to_vec(), listed);
        for &(first, last) in &FORMAT_CHARS {
            for c in (first..=last).filter_map(char::from_u32) {
                assert_eq!(check(|d| d.description = format!("a{c}b")), holds("description"), "{}", hex(c));
                assert_eq!(check(|d| d.env = format!("t{c}")), holds("env"), "{}", hex(c));
            }
        }
        // The client's copy: for every character, `strip_controls` drops what the descriptions refuse, and `version`
        // and `env` refuse that and TAB, LF and CR.
        for c in (0..=0x10_ffff).filter_map(char::from_u32) {
            let dropped = ai_env_relay_client::convert::strip_controls(&c.to_string()).is_empty();
            assert_eq!(refused_in_text(c), dropped, "{}", hex(c));
            assert_eq!(refused_in_word(c), dropped || matches!(c, '\t' | '\n' | '\r'), "{}", hex(c));
        }
        // Ordinary text passes: a no-break space, accents, a dash, CJK, an emoji, and U+2065 (between two of the
        // ranges, not Cf).
        for c in ['\u{a0}', '\u{e9}', '\u{2013}', '\u{2065}', '\u{4e2d}', '\u{1f600}'] {
            assert_eq!(check(|d| d.description = format!("a{c}b")), Ok(()), "{}", hex(c));
            assert_eq!(check(|d| d.ops[0].examples.push(format!("[\"{c}\"]"))), Ok(()), "{}", hex(c));
        }
    }
}
