//! The request log: its lines, sinks, digest and refusal limiter (R-60 to R-68). Ids and hashes only: never a
//! param, a chunk's data, a token or a key.
//!
//! One JSON object per line, each kind with exactly its key set (`CALL_KEYS` … `STATUS_KEYS`), every key on every
//! line (an empty string or 0 when unknown). Values are ids, words and numbers (R-62): source and op names only when
//! they are ids, worker ids only when the handshake parsed them as such, and the peer's IP only on the tunnel and
//! peer lines.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use crate::calls::Outcome;
use crate::limits::TokenBucket;
use crate::serve::Clock;

/// Where the lines go.
pub trait Sink: Send + Sync + 'static {
    /// One line.
    fn write_line(&self, line: &str);
}

/// Lines a sink failed to write, for the status line's `log_dropped` (R-68). One relay runs per process.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// O_APPEND, one write per line; a failed write is counted, never fatal (R-68).
pub struct FileSink {
    file: File,
}

impl FileSink {
    /// The file at `path`, opened for appending.
    pub fn open(path: &Path) -> std::io::Result<FileSink> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new().create(true).append(true).mode(0o640).open(path)?;
        Ok(FileSink { file })
    }
}

impl Sink for FileSink {
    fn write_line(&self, line: &str) {
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        // One write: with O_APPEND a line is never split or interleaved; I's logrotate truncates in place (R-68).
        match (&self.file).write(&buf) {
            Ok(n) if n == buf.len() => {}
            _ => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The lines in memory (tests).
#[derive(Default)]
pub struct MemorySink {
    lines: Mutex<Vec<String>>,
}

impl MemorySink {
    /// Every line so far.
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

impl Sink for MemorySink {
    fn write_line(&self, line: &str) {
        self.lines.lock().unwrap_or_else(PoisonError::into_inner).push(line.to_string());
    }
}

/// A call line's keys (R-60).
pub const CALL_KEYS: [&str; 20] = [
    "ts", "ev", "request_id", "caller", "session", "vm", "grant", "source", "op", "worker", "tunnel", "params_hmac", "params_bytes", "bytes", "chunks",
    "truncated", "duration_ms", "outcome", "code", "suppressed",
];
/// A list line's keys (R-61).
pub const LIST_KEYS: [&str; 12] = ["ts", "ev", "request_id", "caller", "session", "vm", "grant", "sources", "duration_ms", "outcome", "code", "suppressed"];
/// A tunnel line's keys (R-65).
pub const TUNNEL_KEYS: [&str; 12] = ["ts", "ev", "tunnel", "worker", "peer", "sdk", "phase", "outcome", "reason", "sources", "duration_ms", "suppressed"];
/// A reload line's keys.
pub const RELOAD_KEYS: [&str; 7] = ["ts", "ev", "file", "outcome", "version", "entries", "age_s"];
/// A peer line's keys.
pub const PEER_KEYS: [&str; 6] = ["ts", "ev", "face", "peer", "reason", "suppressed"];
/// The status line's keys (R-67).
pub const STATUS_KEYS: [&str; 19] = [
    "ts", "ev", "relay_version", "protocol", "uptime_s", "tunnels", "sources_live", "sources_offline", "calls_in_flight", "sessions", "workers_version",
    "workers_age_s", "signers_version", "signers_age_s", "grants_version", "grants_age_s", "tls_loaded", "unknown_frames", "log_dropped",
];

/// R-63: the first 16 hex characters of HMAC-SHA256(key, params).
pub fn params_digest(key: &[u8; 32], params: &[u8]) -> String {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    let tag = aws_lc_rs::hmac::sign(&key, params);
    hex::encode(&tag.as_ref()[..8])
}

/// The status line's values: `STATUS_KEYS` but `ts` and `ev` (R's fields).
#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusLine {
    /// `RELAY_VERSION`.
    pub relay_version: String,
    /// `PROTOCOL`.
    pub protocol: u32,
    /// Seconds since the relay was built.
    pub uptime_s: u64,
    /// Live tunnels.
    pub tunnels: u64,
    /// Sources with a live tunnel.
    pub sources_live: u64,
    /// Sources whose tunnel went.
    pub sources_offline: u64,
    /// Calls pending in the live tunnels' tables.
    pub calls_in_flight: u64,
    /// Sessions kept (R-58).
    pub sessions: u64,
    /// `workers.json`'s version (16 hex), or "" when not loaded.
    pub workers_version: String,
    /// Seconds since its last confirmed fetch.
    pub workers_age_s: u64,
    /// `token-signers.json`'s version.
    pub signers_version: String,
    /// Seconds since its last confirmed fetch.
    pub signers_age_s: u64,
    /// `grants.json`'s version.
    pub grants_version: String,
    /// Seconds since its last confirmed fetch.
    pub grants_age_s: u64,
    /// Whether a TLS config is loaded.
    pub tls_loaded: bool,
    /// WorkerFrames with no known variant (P-R17).
    pub unknown_frames: u64,
    /// Lines a sink failed to write (R-68).
    pub log_dropped: u64,
}

/// The kinds R-66 limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Limited {
    /// Private-face request lines with outcome `unauthenticated` or `rate_limited`.
    Request,
    /// Tunnel lines with outcome `refused`.
    Tunnel,
    /// Peer lines.
    Peer,
}

struct Limiter {
    buckets: [TokenBucket; 3],
    suppressed: [u64; 3],
}

/// The request log.
pub struct RequestLog {
    sink: Arc<dyn Sink>,
    key: [u8; 32],
    limiter: Mutex<Limiter>,
}

/// A JSON line built key by key, in the order written.
struct Line(String);

impl Line {
    fn new(ts: SystemTime, ev: &str) -> Line {
        let mut l = Line(String::with_capacity(256));
        l.0.push('{');
        l.str("ts", &rfc3339_ms(ts)).str("ev", ev);
        l
    }

    fn key(&mut self, k: &str) -> &mut Line {
        if self.0.len() > 1 {
            self.0.push(',');
        }
        self.0.push('"');
        self.0.push_str(k);
        self.0.push_str("\":");
        self
    }

    fn str(&mut self, k: &str, v: &str) -> &mut Line {
        self.key(k);
        self.0.push_str(&serde_json::to_string(v).unwrap_or_else(|_| "\"\"".into()));
        self
    }

    fn num(&mut self, k: &str, v: impl Into<i128>) -> &mut Line {
        self.key(k);
        self.0.push_str(&v.into().to_string());
        self
    }

    fn bool(&mut self, k: &str, v: bool) -> &mut Line {
        self.key(k);
        self.0.push_str(if v { "true" } else { "false" });
        self
    }

    fn done(&mut self) -> String {
        self.0.push('}');
        std::mem::take(&mut self.0)
    }
}

/// `ts`: RFC 3339 UTC with milliseconds and `Z` (R-60).
pub(crate) fn rfc3339_ms(t: SystemTime) -> String {
    let since = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, rem % 3600 / 60, rem % 60, since.subsec_millis())
}

/// A call line's fixed values; its outcome, bytes, chunks and duration come when it ends.
#[derive(Debug, Clone, Default)]
pub(crate) struct CallFields {
    pub(crate) request_id: String,
    pub(crate) caller: String,
    pub(crate) session: String,
    pub(crate) vm: String,
    pub(crate) grant: String,
    pub(crate) source: String,
    pub(crate) op: String,
    pub(crate) worker: String,
    pub(crate) tunnel: String,
    pub(crate) params_hmac: String,
    pub(crate) params_bytes: u64,
}

/// What a call keeps to write its own line when it ends (`CallState::conclude`).
pub(crate) struct CallLog {
    pub(crate) log: Arc<RequestLog>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) fields: CallFields,
}

impl CallLog {
    /// The call's one line (R-61).
    pub(crate) fn write(&self, outcome: Outcome, bytes: u64, chunks: u64, duration_ms: u64) {
        let truncated = outcome == Outcome::Truncated;
        self.log.call(self.clock.now(), &self.fields, outcome.word(), outcome.code(), bytes, chunks, truncated, duration_ms);
    }
}

/// A list line's values.
#[derive(Debug, Clone, Default)]
pub(crate) struct ListFields {
    pub(crate) request_id: String,
    pub(crate) caller: String,
    pub(crate) session: String,
    pub(crate) vm: String,
    pub(crate) grant: String,
    pub(crate) sources: u64,
}

/// A tunnel line's values.
#[derive(Debug, Clone, Default)]
pub(crate) struct TunnelFields {
    pub(crate) tunnel: String,
    pub(crate) worker: String,
    pub(crate) peer: String,
    pub(crate) sdk: String,
    pub(crate) phase: &'static str,
    pub(crate) outcome: &'static str,
    pub(crate) reason: &'static str,
    pub(crate) sources: u64,
    pub(crate) duration_ms: u64,
}

impl RequestLog {
    /// A log into `sink`, digesting params with `key`, at most `refusals_per_min` refusal lines a minute.
    pub fn new(sink: Arc<dyn Sink>, key: [u8; 32], refusals_per_min: u32) -> RequestLog {
        let now = tokio::time::Instant::now();
        let bucket = || TokenBucket::new(refusals_per_min, refusals_per_min, now);
        RequestLog { sink, key, limiter: Mutex::new(Limiter { buckets: [bucket(), bucket(), bucket()], suppressed: [0; 3] }) }
    }

    /// R-63 with this process's key.
    pub(crate) fn digest(&self, params: &[u8]) -> String {
        params_digest(&self.key, params)
    }

    /// R-66: whether a line of `kind` may be written now, and the count it carries in `suppressed`.
    fn admit(&self, kind: Option<Limited>) -> Option<u64> {
        let Some(kind) = kind else { return Some(0) };
        let i = kind as usize;
        let mut l = self.limiter.lock().unwrap_or_else(PoisonError::into_inner);
        if l.buckets[i].take(tokio::time::Instant::now()) {
            Some(std::mem::take(&mut l.suppressed[i]))
        } else {
            l.suppressed[i] += 1;
            None
        }
    }

    /// One `ev:"call"` line (R-61, R-64).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn call(&self, ts: SystemTime, f: &CallFields, outcome: &str, code: i32, bytes: u64, chunks: u64, truncated: bool, duration_ms: u64) {
        let limited = matches!(outcome, "unauthenticated" | "rate_limited").then_some(Limited::Request);
        let Some(suppressed) = self.admit(limited) else { return };
        let line = Line::new(ts, "call")
            .str("request_id", &f.request_id)
            .str("caller", &f.caller)
            .str("session", &f.session)
            .str("vm", &f.vm)
            .str("grant", &f.grant)
            .str("source", &f.source)
            .str("op", &f.op)
            .str("worker", &f.worker)
            .str("tunnel", &f.tunnel)
            .str("params_hmac", &f.params_hmac)
            .num("params_bytes", f.params_bytes)
            .num("bytes", bytes)
            .num("chunks", chunks)
            .bool("truncated", truncated)
            .num("duration_ms", duration_ms)
            .str("outcome", outcome)
            .num("code", code)
            .num("suppressed", suppressed)
            .done();
        self.sink.write_line(&line);
    }

    /// One `ev:"list"` line (R-61); its refusals share the call lines' limit (R-66).
    pub(crate) fn list(&self, ts: SystemTime, f: &ListFields, outcome: &str, code: i32, duration_ms: u64) {
        let limited = matches!(outcome, "unauthenticated" | "rate_limited").then_some(Limited::Request);
        let Some(suppressed) = self.admit(limited) else { return };
        let line = Line::new(ts, "list")
            .str("request_id", &f.request_id)
            .str("caller", &f.caller)
            .str("session", &f.session)
            .str("vm", &f.vm)
            .str("grant", &f.grant)
            .num("sources", f.sources)
            .num("duration_ms", duration_ms)
            .str("outcome", outcome)
            .num("code", code)
            .num("suppressed", suppressed)
            .done();
        self.sink.write_line(&line);
    }

    /// One `ev:"tunnel"` line (R-65).
    pub(crate) fn tunnel(&self, ts: SystemTime, f: &TunnelFields) {
        let limited = (f.outcome == "refused").then_some(Limited::Tunnel);
        let Some(suppressed) = self.admit(limited) else { return };
        let line = Line::new(ts, "tunnel")
            .str("tunnel", &f.tunnel)
            .str("worker", &f.worker)
            .str("peer", &f.peer)
            .str("sdk", &f.sdk)
            .str("phase", f.phase)
            .str("outcome", f.outcome)
            .str("reason", f.reason)
            .num("sources", f.sources)
            .num("duration_ms", f.duration_ms)
            .num("suppressed", suppressed)
            .done();
        self.sink.write_line(&line);
    }

    /// One `ev:"reload"` line (R-67).
    pub(crate) fn reload(&self, ts: SystemTime, file: &str, outcome: &str, version: &str, entries: u64, age_s: u64) {
        let line = Line::new(ts, "reload")
            .str("file", file)
            .str("outcome", outcome)
            .str("version", version)
            .num("entries", entries)
            .num("age_s", age_s)
            .done();
        self.sink.write_line(&line);
    }

    /// One `ev:"peer"` line (R-2, R-66).
    pub(crate) fn peer(&self, ts: SystemTime, face: &str, peer: &str, reason: &str) {
        let Some(suppressed) = self.admit(Some(Limited::Peer)) else { return };
        let line = Line::new(ts, "peer").str("face", face).str("peer", peer).str("reason", reason).num("suppressed", suppressed).done();
        self.sink.write_line(&line);
    }

    /// One `ev:"status"` line (R-67).
    pub(crate) fn status(&self, ts: SystemTime, s: &StatusLine) {
        let line = Line::new(ts, "status")
            .str("relay_version", &s.relay_version)
            .num("protocol", s.protocol)
            .num("uptime_s", s.uptime_s)
            .num("tunnels", s.tunnels)
            .num("sources_live", s.sources_live)
            .num("sources_offline", s.sources_offline)
            .num("calls_in_flight", s.calls_in_flight)
            .num("sessions", s.sessions)
            .str("workers_version", &s.workers_version)
            .num("workers_age_s", s.workers_age_s)
            .str("signers_version", &s.signers_version)
            .num("signers_age_s", s.signers_age_s)
            .str("grants_version", &s.grants_version)
            .num("grants_age_s", s.grants_age_s)
            .bool("tls_loaded", s.tls_loaded)
            .num("unknown_frames", s.unknown_frames)
            .num("log_dropped", s.log_dropped)
            .done();
        self.sink.write_line(&line);
    }
}

/// Lines a sink failed to write so far.
pub(crate) fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn keys(line: &str) -> Vec<String> {
        let v: serde_json::Value = serde_json::from_str(line).expect("one JSON object");
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    }

    fn sorted(set: &[&str]) -> Vec<String> {
        let mut k: Vec<String> = set.iter().map(|s| s.to_string()).collect();
        k.sort();
        k
    }

    fn ts_shape(ts: &str) -> bool {
        let b = ts.as_bytes();
        b.len() == 24
            && b.iter().enumerate().all(|(i, c)| match i {
                4 | 7 => *c == b'-',
                10 => *c == b'T',
                13 | 16 => *c == b':',
                19 => *c == b'.',
                23 => *c == b'Z',
                _ => c.is_ascii_digit(),
            })
    }

    /// Unit 23.
    #[test]
    fn a_line_of_each_kind_has_exactly_its_keys() {
        let sink = Arc::new(MemorySink::default());
        let log = RequestLog::new(sink.clone(), [9; 32], 60);
        let ts = SystemTime::UNIX_EPOCH + Duration::from_millis(1_800_000_000_123);
        log.call(ts, &CallFields::default(), "ok", 0, 1, 1, false, 5);
        log.list(ts, &ListFields::default(), "ok", 0, 1);
        log.tunnel(ts, &TunnelFields { phase: "auth", outcome: "ok", ..TunnelFields::default() });
        log.reload(ts, "workers", "loaded", "0123456789abcdef", 1, 0);
        log.peer(ts, "public", "198.51.100.7", "rate_limited");
        log.status(ts, &StatusLine {
            relay_version: "0.0.0".into(),
            protocol: 1,
            uptime_s: 0,
            tunnels: 0,
            sources_live: 0,
            sources_offline: 0,
            calls_in_flight: 0,
            sessions: 0,
            workers_version: String::new(),
            workers_age_s: 0,
            signers_version: String::new(),
            signers_age_s: 0,
            grants_version: String::new(),
            grants_age_s: 0,
            tls_loaded: false,
            unknown_frames: 0,
            log_dropped: 0,
        });
        let lines = sink.lines();
        assert_eq!(lines.len(), 6);
        let sets: [&[&str]; 6] = [&CALL_KEYS, &LIST_KEYS, &TUNNEL_KEYS, &RELOAD_KEYS, &PEER_KEYS, &STATUS_KEYS];
        for (line, set) in lines.iter().zip(sets) {
            assert_eq!(keys(line), sorted(set), "{line}");
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let ts = v["ts"].as_str().unwrap();
            assert!(ts_shape(ts), "{ts}");
        }
        assert!(lines[0].contains("\"ts\":\"2027-01-15T08:00:00.123Z\""), "{}", lines[0]);
        assert_eq!(params_digest(&[9u8; 32], b"{\"n\":1}"), "adab7941a49a5256");
        assert_eq!(log.digest(b"{\"n\":1}"), "adab7941a49a5256");
    }

    /// Unit 24 (paused).
    #[tokio::test(start_paused = true)]
    async fn refusal_lines_are_limited_with_a_count() {
        let sink = Arc::new(MemorySink::default());
        let log = RequestLog::new(sink.clone(), [9; 32], 60);
        let ts = SystemTime::UNIX_EPOCH;
        for _ in 0..100 {
            log.call(ts, &CallFields::default(), "unauthenticated", 16, 0, 0, false, 0);
        }
        assert_eq!(sink.lines().len(), 60);
        for _ in 0..5 {
            log.call(ts, &CallFields::default(), "ok", 0, 0, 0, false, 0);
        }
        assert_eq!(sink.lines().len(), 65, "ok lines are never limited");
        // R-66's other two kinds, each with its own 60: tunnel lines with outcome `refused`, and peer lines.
        let refused = TunnelFields { phase: "auth", outcome: "refused", reason: "bad_signature", ..TunnelFields::default() };
        for _ in 0..70 {
            log.tunnel(ts, &refused);
            log.peer(ts, "public", "198.51.100.7", "rate_limited");
        }
        log.tunnel(ts, &TunnelFields { phase: "auth", outcome: "ok", ..TunnelFields::default() });
        assert_eq!(sink.lines().len(), 65 + 60 + 60 + 1, "60 of each kind; a tunnel line `ok` is never limited");
        tokio::time::sleep(Duration::from_secs(60)).await;
        log.call(ts, &CallFields::default(), "unauthenticated", 16, 0, 0, false, 0);
        log.tunnel(ts, &refused);
        log.peer(ts, "public", "198.51.100.7", "rate_limited");
        let lines = sink.lines();
        let last: Vec<serde_json::Value> = lines[lines.len() - 3..].iter().map(|l| serde_json::from_str(l).unwrap()).collect();
        let counts: Vec<(&str, u64)> = last.iter().map(|v| (v["ev"].as_str().unwrap(), v["suppressed"].as_u64().unwrap())).collect();
        assert_eq!(counts, [("call", 40), ("tunnel", 10), ("peer", 10)]);
        assert!(lines[..65].iter().all(|l| l.contains("\"suppressed\":0")));
    }
}
