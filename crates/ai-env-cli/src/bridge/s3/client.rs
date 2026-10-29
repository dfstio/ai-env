//! The Mac's own requests to the transcript store (S9 plan §5, G4): a
//! Mac-begun chat's upload (PutObject, or a multipart upload of
//! `MULTIPART_PART` parts with a signed sha256 each: CreateMultipartUpload,
//! UploadPart, ListParts, CompleteMultipartUpload, AbortMultipartUpload),
//! ListObjectsV2 of a session's prefix, and DeleteObject (gc, a compaction's
//! superseded keys, `forget --purge`). S12 (P): a purge (`session gc
//! --remote`, `forget --purge`) sends DeleteObjects in its place, up to 1000
//! keys a request, quiet, its body's SHA-256 signed
//! (`x-amz-sdk-checksum-algorithm`, `x-amz-checksum-sha256`); the keys S3
//! refused for a moment go again, and when S3 refuses the form every key
//! goes as its own DeleteObject ([`S3Client::delete_keys`]). An answer is an
//! error document only when its root element is `<Error>`
//! (`Reply::has_error`). Each is presigned like the VM's
//! (`S3Sign`, `x-amz-expected-bucket-owner` signed in every one) and sent
//! with exactly the headers it signed, by `tls::reqwest_client()` (S3 chains
//! to the Amazon roots: TLS 1.3, no proxy, no redirect), or
//! `tls::lab_http_client` under the lab's loopback S3. The Mac never sends a
//! GetObject or a HeadObject: the bucket policy refuses reads outside the
//! endpoint. S3's XML answers are read by a bounded hand-written reader
//! ([`xml_values`]), never a new crate. A request is held to its progress,
//! not to a budget of its whole (S10 F5, [`Waits`]): its body must hand a
//! new chunk within [`STALL_AFTER`], the answer's head come within
//! [`HEAD_WAIT`] of the body's end (and of its tail's drain, [`TAIL`]), each
//! chunk of the answer within [`CHUNK_WAIT`]; so a slow transfer that moves
//! goes on, and a dead uplink fails a try within a minute. An UploadPart, a
//! PutObject or a CompleteMultipartUpload that gets no answer, S3's 500 or
//! 503, its 409 `OperationAborted` or `ConditionalRequestConflict`
//! ([`RETRY_409`]), or its 400 `RequestTimeout` ([`RETRY_400`]), goes again
//! ([`PART_TRIES`]); a request with no answer names its cause, never its
//! URL. S11 (L5): an encoded object's PutObject and CreateMultipartUpload
//! send and sign `content-encoding` ([`encoding_header`]); an UploadPart
//! and a CompleteMultipartUpload never do (S3 checks each part's signed
//! sha256 of the stored bytes).
use super::presign::{request, write_headers};
use super::{PresignReq, S3Endpoint, S3Method, S3Sign, S3Target};
use crate::bridge::errors::BridgeError;
use crate::wire::s3::{PresignedUrl, S3Key, PRESIGN_EXPIRY};
use crate::wire::workspace::PartEncoding;
use futures_util::{StreamExt as _, TryStreamExt as _};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The largest XML answer read (ListParts of 10000 parts is under 2 MiB).
pub const XML_MAX: usize = 8 << 20;
/// S10 (F5): the longest a request's body may go without handing a new
/// chunk to the connection before its try is given up (`sent N of M bytes,
/// no progress for 60 s`). The kernel's send buffers take some of a stalled
/// body's bytes before its writes stop, so the window never gets shorter.
pub const STALL_AFTER: Duration = Duration::from_secs(60);
/// S10 (F5): the longest the answer's head may take once the body is all
/// handed to the connection (at once for a request without one).
pub const HEAD_WAIT: Duration = Duration::from_secs(120);
/// S10 (F5): the longest each chunk of the answer's body may take, so a
/// CompleteMultipartUpload's keep-alive whitespace keeps it going.
pub const CHUNK_WAIT: Duration = Duration::from_secs(60);
/// How many times the stage's bytes (an UploadPart; a PutObject, a file of
/// one part) and a CompleteMultipartUpload are sent at most: a try that got
/// no HTTP answer (a stall, a reset, a TLS error), S3's 500 or 503, one of
/// its 409s of [`RETRY_409`] or its 400 of [`RETRY_400`], goes again,
/// presigned anew. Safe: a part sent again replaces the one of its number,
/// a PutObject or a Complete that landed already answers 412
/// (`If-None-Match: *`), which is `Exists`, and a Complete S3 already made
/// answers `NoSuchUpload`, which a listing of the key then checks
/// (`S3Client::complete_multipart`).
pub const PART_TRIES: u32 = 3;
/// S10 (F5): the 409s S3 asks to be sent again: a conflicting operation was
/// in progress on the key, or a conditional write met another one.
pub const RETRY_409: [&str; 2] = ["OperationAborted", "ConditionalRequestConflict"];
/// S10 (F5): the 400 S3 asks to be sent again: it closed a request whose
/// body sent nothing for some 20 s (a stall shorter than [`STALL_AFTER`]
/// that S3's answer reached), which the AWS SDKs retry too.
pub const RETRY_400: [&str; 1] = ["RequestTimeout"];
/// S12 (P): the most keys one DeleteObjects names (S3's limit).
pub const DELETE_BATCH: usize = 1000;
/// S12 (P): the DeleteObject requests in flight at once when S3 refuses the
/// batch's form ([`Deleted::one_by_one`]).
pub const DELETE_PARALLEL: usize = 16;
/// S12 (P): the per-key codes of a DeleteObjects answer whose keys go again
/// (only the keys refused so), up to [`PART_TRIES`] rounds.
pub const KEY_RETRY: [&str; 4] = ["InternalError", "ServiceUnavailable", "SlowDown", "OperationAborted"];
/// S12 (P, P-R10): the codes of a 400 or 501 that refuse a batch's form (a
/// 405 refuses it whatever its code): S3 takes no DeleteObjects signed so, and
/// the fallback deletes every key as its own DeleteObject.
const BATCH_REFUSED: [&str; 3] = ["InvalidRequest", "MissingContentMD5", "NotImplemented"];
/// S10 (F5): the bytes of a body's end the connection may still hold once it
/// took the last chunk: the kernel's send buffer at its largest
/// (`net.inet.tcp.autosndbufmax`, 4 MiB on macOS) and hyper's own write
/// buffer. They drain at about the pace the connection took them, so the
/// head's wait is longer by the time the body's last `TAIL` bytes took
/// (`Progress::tail_took`): a slow uplink still moving them is never cut.
const TAIL: u64 = (4 << 20) + (512 << 10);
/// The longest a try's watchdog goes without looking at its body's progress.
const WATCH_EVERY: Duration = Duration::from_secs(1);
/// The wait before a write's next try, times the tries so far.
const RETRY_WAIT: Duration = Duration::from_millis(500);
/// The chunk a file range is streamed in.
const CHUNK: usize = 64 * 1024;
/// The namespace S3's request documents carry.
const XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// What a write did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Written {
    /// Stored: its `x-amz-version-id` (empty when the bucket answered none).
    Stored(String),
    /// 412: the key holds an object already (`If-None-Match: *`). A key of
    /// the store named by its bytes' sha256 holds those bytes.
    Exists,
}

/// One object a listing named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub key: String,
    pub size: u64,
}

/// One part ListParts named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedPart {
    pub number: u32,
    pub etag: String,
    pub size: u64,
    /// `ChecksumSHA256` as S3 stored it (base64), when it did.
    pub checksum: Option<String>,
}

/// S12 (P): a key a DeleteObjects (or, one by one, a DeleteObject) did not delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError {
    pub key: String,
    /// S3's `<Code>` (`[A-Za-z0-9]`, 1 to 64), or `HTTP <status>` for a DeleteObject refused without one.
    pub code: String,
}

/// S12 (P): what [`S3Client::delete_keys`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deleted {
    /// The keys S3 took (a delete marker each; a quiet answer names none of them).
    pub deleted: usize,
    /// The keys left, in the order `delete_keys` was given them: refused with a
    /// code outside [`KEY_RETRY`], or still refused at the last round.
    pub failed: Vec<KeyError>,
    /// S3 refused the batch's form at the first DeleteObjects, so every key went
    /// as a DeleteObject of its own, [`DELETE_PARALLEL`] at once.
    pub one_by_one: bool,
}

/// A request body.
pub enum Body {
    None,
    Bytes(Vec<u8>),
    /// `len` bytes of a file from `offset`, streamed (never buffered whole).
    File { path: std::path::PathBuf, offset: u64, len: u64 },
}

impl Body {
    fn len(&self) -> u64 {
        match self {
            Body::None => 0,
            Body::Bytes(b) => b.len() as u64,
            Body::File { len, .. } => *len,
        }
    }
}

/// The waits one try of a request is held to (S10 F5): [`Waits::DEFAULT`],
/// unless a test sets shorter ones ([`S3Client::with_waits`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waits {
    /// [`STALL_AFTER`]: no new chunk of the body handed for this long.
    pub stall: Duration,
    /// [`HEAD_WAIT`]: no answer's head this long after the body's end.
    pub head: Duration,
    /// [`CHUNK_WAIT`]: no chunk of the answer for this long.
    pub chunk: Duration,
}

impl Waits {
    pub const DEFAULT: Waits = Waits { stall: STALL_AFTER, head: HEAD_WAIT, chunk: CHUNK_WAIT };
}

/// The store's client on this Mac: `signer`'s credentials, one target.
pub struct S3Client<'a, S> {
    signer: &'a S,
    target: S3Target,
    http: reqwest::Client,
    waits: Waits,
    /// S10 (F5): where a stage counts what its file bodies handed the connection ([`S3Client::counting`]).
    pace: Option<Arc<AtomicU64>>,
}

/// A transport failure of `op`, scrubbed (the URL is registered with the scrubber while held).
fn transport(op: &'static str, e: &dyn std::fmt::Display) -> BridgeError {
    BridgeError::Sdk { op, message: crate::wire::redact::scrub(&e.to_string()).into_owned() }
}

/// A wait as an error names it: whole seconds, else milliseconds (a test's).
fn shown(d: Duration) -> String {
    if d.subsec_millis() == 0 {
        format!("{} s", d.as_secs())
    } else {
        format!("{} ms", d.as_millis())
    }
}

/// What a request's body handed the connection so far, and when it last did
/// (S10 F5): the file's stream ([`file_range`]) stamps it with each chunk,
/// the watchdog of `S3Client::try_send` reads it.
#[derive(Debug)]
struct Progress {
    start: std::time::Instant,
    bytes: AtomicU64,
    /// Milliseconds from `start` to the last chunk handed.
    at_ms: AtomicU64,
    /// The body's length less [`TAIL`]: the bytes handed past it are its tail.
    tail_from: u64,
    /// Milliseconds from `start` to the last chunk handed before the tail's first (`u64::MAX`: none yet).
    tail_ms: AtomicU64,
    /// A stage's count ([`S3Client::counting`]) and the most any try of this request handed so far: the bytes a
    /// later try hands again are counted once.
    pace: Option<(Arc<AtomicU64>, Arc<AtomicU64>)>,
}

impl Progress {
    /// The progress of one try of a body of `len` bytes, counted into `pace`.
    fn new(len: u64, pace: Option<(Arc<AtomicU64>, Arc<AtomicU64>)>) -> Arc<Progress> {
        Arc::new(Progress { start: std::time::Instant::now(), bytes: AtomicU64::new(0), at_ms: AtomicU64::new(0), tail_from: len.saturating_sub(TAIL), tail_ms: AtomicU64::new(u64::MAX), pace })
    }

    /// `n` bytes more handed, now.
    fn handed(&self, n: u64) {
        let before = self.bytes.fetch_add(n, Ordering::Relaxed);
        let after = before.saturating_add(n);
        let prev = self.at_ms.swap(u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX), Ordering::Relaxed);
        if before <= self.tail_from && after > self.tail_from {
            self.tail_ms.store(prev, Ordering::Relaxed);
        }
        if let Some((count, most)) = &self.pace {
            let most_before = most.fetch_max(after, Ordering::Relaxed);
            if after > most_before {
                count.fetch_add(after - most_before, Ordering::Relaxed);
            }
        }
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// When the last chunk was handed (the start before the first).
    fn last(&self) -> std::time::Instant {
        self.start + Duration::from_millis(self.at_ms.load(Ordering::Relaxed))
    }

    /// How long the body's last [`TAIL`] bytes took to be handed (nothing
    /// before they all were, or for a body handed at once): about what the
    /// connection's buffers take to drain them after the last chunk.
    fn tail_took(&self) -> Duration {
        match self.tail_ms.load(Ordering::Relaxed) {
            u64::MAX => Duration::ZERO,
            ms => self.last().saturating_duration_since(self.start + Duration::from_millis(ms)),
        }
    }

    /// When a try whose body of `total` bytes handed `handed` so far is
    /// given up without news: until the body is all handed, `waits.stall`
    /// after its last chunk; then `waits.head` after it, and the time its
    /// tail took ([`Self::tail_took`]), which the connection may still be
    /// sending.
    fn deadline(&self, handed: u64, total: u64, waits: &Waits) -> std::time::Instant {
        self.last() + if handed < total { waits.stall } else { waits.head + self.tail_took() }
    }
}

/// What a try that got no HTTP answer says, scrubbed: reqwest's error
/// without its URL, each cause of its chain after it (`error sending
/// request: …: connection reset by peer`), and whether it timed out, and
/// after how long: `after`, the time the try ran. That is its budget when
/// reqwest's timer fired, less when the OS timed out first (a connect, a
/// stalled send).
fn cause(e: reqwest::Error, after: Duration) -> String {
    let timed_out = e.is_timeout();
    let e = e.without_url();
    let mut text = e.to_string();
    let mut next = std::error::Error::source(&e);
    while let Some(c) = next {
        let s = c.to_string();
        if !s.is_empty() && !text.contains(&s) {
            text.push_str(": ");
            text.push_str(&s);
        }
        next = c.source();
    }
    if timed_out {
        text.push_str(&format!(" (timed out after {} s)", after.as_secs()));
    }
    crate::wire::redact::scrub(&text).into_owned()
}

/// What one try of a request got.
enum Tried {
    /// An HTTP answer, read whole.
    Answer(Reply),
    /// None (a timeout, a reset, a TLS error, an answer cut short): its cause ([`cause`]).
    NoAnswer(String),
}

impl<'a, S: S3Sign> S3Client<'a, S> {
    /// The client of `target`: HTTPS under the Amazon roots, or (debug
    /// builds) plain http to the lab's loopback S3.
    pub fn new(signer: &'a S, target: &S3Target) -> Result<S3Client<'a, S>, BridgeError> {
        let http = match target.endpoint {
            S3Endpoint::Aws => crate::bridge::tls::reqwest_client().map_err(|e| BridgeError::Sdk { op: "tls", message: format!("cannot build the HTTPS client: {e}") })?,
            S3Endpoint::Lab(addr) => lab_client(addr)?,
        };
        Ok(S3Client { signer, target: target.clone(), http, waits: Waits::DEFAULT, pace: None })
    }

    /// This client with `waits` in place of [`Waits::DEFAULT`] (a test's shorter ones).
    #[must_use]
    pub fn with_waits(mut self, waits: Waits) -> S3Client<'a, S> {
        self.waits = waits;
        self
    }

    /// This client again, each file body's bytes counted into `handed` as
    /// the connection takes them, answered or not (a byte a later try of the
    /// request hands again counted once): S10 (F5) the pace of a stage whose
    /// parts go side by side, which their answers alone put at a fraction of
    /// the uplink (eight 64 MiB parts on 5 MB/s: the first answered after
    /// 107 s, 64 MiB of some 537 MB sent).
    #[must_use]
    pub fn counting(&self, handed: &Arc<AtomicU64>) -> S3Client<'a, S> {
        S3Client { signer: self.signer, target: self.target.clone(), http: self.http.clone(), waits: self.waits, pace: Some(Arc::clone(handed)) }
    }

    /// The target this client writes to.
    #[must_use]
    pub fn target(&self) -> &S3Target {
        &self.target
    }

    /// Presign `method` on `key` with `query` and `headers` (the owner's
    /// added), send it with exactly those headers and `body`, and read the
    /// answer: its status, its `x-amz-version-id` and its body (at most
    /// [`XML_MAX`]), each try held to the client's [`Waits`]. With `tries`
    /// over 1, a try that got no HTTP answer, or an answer that asks to be
    /// sent again (`Reply::transient`: S3's 500 or 503, a 409 of
    /// [`RETRY_409`], a 400 of [`RETRY_400`]), goes again while tries are
    /// left, presigned anew, after [`RETRY_WAIT`] times the tries so far
    /// (logged); no answer at the last try is the error (`Sdk`, exit 7),
    /// naming its cause, how many tries and what S3 answered before, never
    /// the URL.
    #[allow(clippy::too_many_arguments)]
    async fn send(&self, op: &'static str, method: S3Method, key: Option<&str>, query: Vec<(String, String)>, headers: Vec<(String, String)>, body: Body, tries: u32) -> Result<Reply, BridgeError> {
        let req = request(method, &self.target, key.map(str::to_string), query, headers, PRESIGN_EXPIRY);
        // What an error names: the key (and the part), never the URL.
        let what = match (key, req.query.iter().find(|(n, _)| n == "partNumber")) {
            (Some(k), Some((_, n))) => format!("part {n} of {k}"),
            (Some(k), None) => k.to_string(),
            (None, _) => "the bucket".to_string(),
        };
        let mut tried = 0u32;
        // S3's answers to the tries sent again: the error names them.
        let mut answered: Vec<String> = Vec::new();
        // The most any try of this request handed: a stage's pace counts a byte sent again once.
        let most = Arc::new(AtomicU64::new(0));
        loop {
            tried += 1;
            let again = match self.try_send(op, &req, &body, &what, &most).await? {
                Tried::Answer(reply) if tried < tries && reply.transient() => {
                    let said = format!("HTTP {}{}", reply.status, error_code(&reply.body).map_or_else(String::new, |c| format!(" ({c})")));
                    answered.push(said.clone());
                    said
                }
                Tried::Answer(reply) => return Ok(reply),
                Tried::NoAnswer(cause) if tried < tries => format!("no answer ({cause})"),
                Tried::NoAnswer(cause) => {
                    let n = if tried == 1 {
                        String::new()
                    } else if answered.is_empty() {
                        format!(" in {tried} tries")
                    } else {
                        format!(" at the last of {tried} tries (S3 answered {} before)", answered.join(", "))
                    };
                    return Err(BridgeError::Sdk { op, message: format!("{what}: no answer{n}: {cause}") });
                }
            };
            tracing::warn!("{op}: {what}: {again}; sent again (try {} of {tries})", tried + 1);
            tokio::time::sleep(RETRY_WAIT * tried).await;
        }
    }

    /// One try of [`Self::send`], presigned now: the answer read whole, or
    /// no answer and its cause (scrubbed while the URL is held). No budget of
    /// the whole: a watchdog gives the try up once its body handed no new
    /// chunk for [`Waits::stall`] (`sent N of M bytes`, a stalled uplink), or
    /// once the body is all handed and no answer's head came within
    /// [`Waits::head`] and the time its last [`TAIL`] bytes took to be
    /// handed (the connection's buffers may still hold them); each chunk of
    /// the answer gets [`Waits::chunk`] (reqwest's `read_timeout` would be
    /// one timer from the send to the head, cutting a part still moving
    /// after a minute). A file's bytes count toward the client's pace
    /// ([`S3Client::counting`]), each once whatever try hands it (`most`).
    /// An error is final: the presign, the file, an answer over
    /// [`XML_MAX`].
    async fn try_send(&self, op: &'static str, req: &PresignReq, body: &Body, what: &str, most: &Arc<AtomicU64>) -> Result<Tried, BridgeError> {
        let url: PresignedUrl = self.signer.presign(req).await?;
        let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes()).map_err(|e| transport(op, &e))?;
        let mut rb = self.http.request(method, url.expose());
        for (name, value) in &req.headers {
            rb = rb.header(name.as_str(), value.as_str());
        }
        // A file's bytes count toward a stage's pace (`counting`); a request document's do not.
        let pace = self.pace.as_ref().filter(|_| matches!(body, Body::File { .. })).map(|c| (Arc::clone(c), Arc::clone(most)));
        let (progress, total) = (Progress::new(body.len(), pace), body.len());
        rb = match body {
            Body::None => rb,
            Body::Bytes(b) => {
                progress.handed(total);
                rb.body(b.clone())
            }
            Body::File { path, offset, len } => rb.body(file_range(path, *offset, *len, Arc::clone(&progress)).await?),
        };
        let sent = std::time::Instant::now();
        let send = rb.send();
        tokio::pin!(send);
        // The watchdog looks again at least this often: a chunk handed moves its deadline, the body's end turns the
        // stall's wait into the head's.
        let tick = (self.waits.stall.min(self.waits.head) / 4).clamp(Duration::from_millis(10), WATCH_EVERY);
        let mut resp = loop {
            // Until the body is all handed, its next chunk; then the answer's head, once its tail could drain.
            let handed = progress.bytes();
            let deadline = progress.deadline(handed, total, &self.waits);
            let now = std::time::Instant::now();
            if now >= deadline {
                let cause = if handed < total { format!("sent {handed} of {total} bytes, no progress for {}", shown(self.waits.stall)) } else { format!("the request sent, no answer within {}", shown(self.waits.head)) };
                return Ok(Tried::NoAnswer(cause));
            }
            tokio::select! {
                r = &mut send => match r {
                    Ok(resp) => break resp,
                    Err(e) => return Ok(Tried::NoAnswer(cause(e, sent.elapsed()))),
                },
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.min(now + tick))) => {}
            }
        };
        let status = resp.status().as_u16();
        let version_id = resp.headers().get("x-amz-version-id").and_then(|v| v.to_str().ok()).map(str::to_string);
        let etag = resp.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok()).map(str::to_string);
        let mut text = Vec::new();
        loop {
            match tokio::time::timeout(self.waits.chunk, resp.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    if text.len() + chunk.len() > XML_MAX {
                        return Err(BridgeError::Sdk { op, message: format!("{what}: the answer is larger than {} MiB", XML_MAX >> 20) });
                    }
                    text.extend_from_slice(&chunk);
                }
                Ok(Ok(None)) => break,
                Ok(Err(e)) => return Ok(Tried::NoAnswer(cause(e, sent.elapsed()))),
                Err(_) => return Ok(Tried::NoAnswer(format!("HTTP {status} came, then its answer stopped after {} bytes for {}", text.len(), shown(self.waits.chunk)))),
            }
        }
        Ok(Tried::Answer(Reply { status, version_id, etag, body: String::from_utf8_lossy(&text).into_owned() }))
    }

    /// PutObject of `body` (`len` bytes, `sha256` its digest) at `key`, new
    /// only (`If-None-Match: *`): stored with its version, or `Exists` (412).
    /// Up to [`PART_TRIES`] tries. S11 (L5): `encoding` is how `body` is
    /// stored (its `content-encoding`, sent and signed); `len` and `sha256`
    /// are the stored bytes'.
    pub async fn put_object(&self, key: &str, body: Body, len: u64, sha256: &str, encoding: Option<PartEncoding>) -> Result<Written, BridgeError> {
        const OP: &str = "s3 put";
        let mut headers = write_headers(len, sha256, true)?;
        headers.extend(encoding_header(encoding));
        let reply = self.send(OP, S3Method::Put, Some(key), Vec::new(), headers, body, PART_TRIES).await?;
        match reply.status {
            200 => Ok(Written::Stored(reply.version_id.unwrap_or_default())),
            412 => Ok(Written::Exists),
            s => Err(reply.error("put", s)),
        }
    }

    /// CreateMultipartUpload of `key` with SHA-256 part checksums: its upload
    /// id. S11 (L5): `encoding` is how the object is stored (its
    /// `content-encoding`, sent and signed here, the object's once complete).
    pub async fn create_multipart(&self, key: &str, encoding: Option<PartEncoding>) -> Result<String, BridgeError> {
        const OP: &str = "s3 create multipart upload";
        let mut headers = vec![("x-amz-checksum-algorithm".to_string(), "SHA256".to_string())];
        headers.extend(encoding_header(encoding));
        let reply = self.send(OP, S3Method::Post, Some(key), vec![("uploads".into(), String::new())], headers, Body::None, 1).await?;
        if reply.status != 200 || reply.has_error() {
            return Err(reply.error("create multipart upload", reply.status));
        }
        let id = xml_values(&reply.body, "UploadId").into_iter().next().filter(|id| !id.is_empty() && id.len() <= 1024 && id.bytes().all(|b| b.is_ascii_graphic()));
        id.ok_or_else(|| BridgeError::Sdk { op: OP, message: "the answer names no UploadId".into() })
    }

    /// UploadPart `number` of `upload_id` (`len` bytes, `sha256` signed): its
    /// ETag; up to [`PART_TRIES`] tries. The parts sent beside it share the
    /// uplink: each is held to its own progress, never to a budget its
    /// share of the uplink could outlast.
    pub async fn upload_part(&self, key: &str, upload_id: &str, number: u32, body: Body, len: u64, sha256: &str) -> Result<String, BridgeError> {
        const OP: &str = "s3 upload part";
        let query = vec![("uploadId".to_string(), upload_id.to_string()), ("partNumber".to_string(), number.to_string())];
        let reply = self.send(OP, S3Method::Put, Some(key), reorder(query), write_headers(len, sha256, false)?, body, PART_TRIES).await?;
        if reply.status != 200 {
            return Err(reply.error("upload part", reply.status));
        }
        reply.etag.filter(|e| !e.is_empty()).ok_or_else(|| BridgeError::Sdk { op: OP, message: format!("part {number}: the answer carries no ETag") })
    }

    /// ListParts of `upload_id` (every page): `None` when S3 knows no such upload (404 `NoSuchUpload`).
    pub async fn list_parts(&self, key: &str, upload_id: &str) -> Result<Option<Vec<ListedPart>>, BridgeError> {
        const OP: &str = "s3 list parts";
        let reply = self.send(OP, S3Method::Get, Some(key), vec![("uploadId".into(), upload_id.to_string())], Vec::new(), Body::None, 1).await?;
        if reply.status == 404 {
            return Ok(None);
        }
        if reply.status != 200 {
            return Err(reply.error("list parts", reply.status));
        }
        let mut parts = Vec::new();
        for part in xml_elements(&reply.body, "Part") {
            let field = |n: &str| xml_values(part, n).into_iter().next();
            let (Some(number), Some(etag), Some(size)) = (field("PartNumber").and_then(|n| n.parse().ok()), field("ETag"), field("Size").and_then(|s| s.parse().ok())) else {
                return Err(BridgeError::Sdk { op: OP, message: "a part without its number, ETag or size".into() });
            };
            parts.push(ListedPart { number, etag, size, checksum: field("ChecksumSHA256") });
        }
        Ok(Some(parts))
    }

    /// CompleteMultipartUpload of `upload_id` with `parts` (number, ETag,
    /// sha256 hex) in order, new only (`If-None-Match: *`), the object `len`
    /// bytes; up to [`PART_TRIES`] tries (S10 F5: S9 sent it once). A try
    /// whose answer was lost may have made the object, and S3 then knows the
    /// upload no more: a 404 `NoSuchUpload` is checked by a listing of the
    /// key, and the object there at `len` bytes is `Exists` (the key is its
    /// bytes' sha256), its version unknown, as after a 412.
    pub async fn complete_multipart(&self, key: &str, upload_id: &str, parts: &[(u32, String, String)], len: u64) -> Result<Written, BridgeError> {
        const OP: &str = "s3 complete multipart upload";
        let mut doc = format!("<CompleteMultipartUpload xmlns=\"{XMLNS}\">");
        for (n, etag, sha) in parts {
            let checksum = crate::wire::s3::sha256_b64(sha).ok_or_else(|| BridgeError::Config(format!("{OP}: part {n}'s sha256 is not 64 lowercase hex digits")))?;
            doc.push_str(&format!("<Part><ETag>{}</ETag><PartNumber>{n}</PartNumber><ChecksumSHA256>{checksum}</ChecksumSHA256></Part>", xml_escape(etag)));
        }
        doc.push_str("</CompleteMultipartUpload>");
        let headers = vec![("if-none-match".to_string(), "*".to_string())];
        let reply = self.send(OP, S3Method::Post, Some(key), vec![("uploadId".into(), upload_id.to_string())], headers, Body::Bytes(doc.into_bytes()), PART_TRIES).await?;
        if reply.status == 404 && error_code(&reply.body).as_deref() == Some("NoSuchUpload") && self.holds(key, len).await? {
            tracing::info!("{OP}: {key}: S3 knows the upload no more and lists the object at {len} bytes: complete");
            return Ok(Written::Exists);
        }
        match reply.status {
            // S3 can answer 200 and then an error document (the completion failed after the head went out).
            200 if reply.has_error() => Err(reply.error("complete multipart upload", 200)),
            200 => Ok(Written::Stored(reply.version_id.unwrap_or_default())),
            412 => Ok(Written::Exists),
            s => Err(reply.error("complete multipart upload", s)),
        }
    }

    /// Whether S3 lists the object `key` at `len` bytes (one ListObjectsV2 of
    /// the key as its prefix): a key of the store named by its bytes' sha256
    /// that holds `len` bytes holds those bytes.
    pub async fn holds(&self, key: &str, len: u64) -> Result<bool, BridgeError> {
        Ok(self.list(key).await?.iter().any(|o| o.key == key && o.size == len))
    }

    /// AbortMultipartUpload of `upload_id` (a 404 is an upload already gone).
    pub async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<(), BridgeError> {
        const OP: &str = "s3 abort multipart upload";
        let reply = self.send(OP, S3Method::Delete, Some(key), vec![("uploadId".into(), upload_id.to_string())], Vec::new(), Body::None, 1).await?;
        match reply.status {
            200 | 204 | 404 => Ok(()),
            s => Err(reply.error("abort multipart upload", s)),
        }
    }

    /// ListObjectsV2 of `prefix` (one of the store's, every page): the current, undeleted objects.
    pub async fn list(&self, prefix: &str) -> Result<Vec<Listed>, BridgeError> {
        const OP: &str = "s3 list";
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..10_000 {
            let mut query = vec![("list-type".to_string(), "2".to_string()), ("prefix".to_string(), prefix.to_string())];
            if let Some(t) = &token {
                query.push(("continuation-token".to_string(), t.clone()));
            }
            let reply = self.send(OP, S3Method::Get, None, query, Vec::new(), Body::None, 1).await?;
            if reply.status != 200 || reply.has_error() {
                return Err(reply.error("list", reply.status));
            }
            for item in xml_elements(&reply.body, "Contents") {
                let key = xml_values(item, "Key").into_iter().next().unwrap_or_default();
                let size = xml_values(item, "Size").into_iter().next().and_then(|s| s.parse().ok()).unwrap_or(0);
                if key.starts_with(prefix) {
                    out.push(Listed { key, size });
                }
            }
            let truncated = xml_values(&reply.body, "IsTruncated").into_iter().next().is_some_and(|t| t == "true");
            token = xml_values(&reply.body, "NextContinuationToken").into_iter().next().filter(|t| !t.is_empty());
            if !truncated || token.is_none() {
                return Ok(out);
            }
        }
        Err(BridgeError::Sdk { op: OP, message: format!("{prefix}: more than 10000 pages") })
    }

    /// DeleteObject of `key`'s current version (a delete marker: old versions
    /// expire after 30 days by the bucket's lifecycle). One try (S12, P-R13:
    /// sync's superseded keys, claude's views and the stager keep S11's
    /// answers and request order; a purge sends DeleteObjects).
    pub async fn delete(&self, key: &str) -> Result<(), BridgeError> {
        self.delete_tries(key, 1).await
    }

    /// S12 (P): DeleteObject of `key`'s current version, up to `tries` tries
    /// (`send`'s rules: no answer, a 500 or 503, a 409 of [`RETRY_409`], a 400
    /// of [`RETRY_400`] go again): 200 or 204, else `S3` (`s3 delete: HTTP
    /// <status> (<code>)`).
    async fn delete_tries(&self, key: &str, tries: u32) -> Result<(), BridgeError> {
        const OP: &str = "s3 delete";
        let reply = self.send(OP, S3Method::Delete, Some(key), Vec::new(), Vec::new(), Body::None, tries).await?;
        match reply.status {
            200 | 204 => Ok(()),
            s => Err(reply.error("delete", s)),
        }
    }

    /// S12 (P): DeleteObjects of `keys` (1 to [`DELETE_BATCH`] keys of the
    /// store, each once) in one request, quiet, its body's SHA-256 signed: the
    /// keys S3 did not delete, each with its code, in its answer's order.
    ///
    /// Refused before any request (`Config`, exit 1, P-R3), in this order: no
    /// key or more than [`DELETE_BATCH`]; a key [`S3Key::parse`] refuses
    /// (Debug-quoted, as presign's own text); a key twice. The request is a
    /// POST of the bucket itself, `delete` its one parameter (P-R1), its body
    /// [`delete_document`] and [`delete_headers`]' pair signed beside the
    /// owner. Up to [`PART_TRIES`] tries, presigned anew, as `send` sends
    /// again (P-R4: no answer, a 500 or 503, a 409 of [`RETRY_409`], a 400 of
    /// [`RETRY_400`], a 200 whose root is an error document of `InternalError`
    /// or of [`RETRY_409`]; S3 deletes again, a marker more). Then, on the
    /// last answer: a 200 `DeleteResult` is read by [`delete_errors`], whose
    /// refusal is `Sdk` (exit 7); a 200 error document is `S3` with its code;
    /// a 200 of any other root is `Sdk`; any other status is `S3`, so a
    /// refused form reads `s3 delete objects: HTTP 400 (InvalidRequest)`.
    pub async fn delete_batch(&self, keys: &[String]) -> Result<Vec<KeyError>, BridgeError> {
        const OP: &str = "s3 delete objects";
        if keys.is_empty() || keys.len() > DELETE_BATCH {
            return Err(BridgeError::Config(format!("{OP}: a batch of {} keys (1 to {DELETE_BATCH})", keys.len())));
        }
        if let Some(foreign) = keys.iter().find(|k| S3Key::parse(k).is_none()) {
            return Err(BridgeError::Config(format!("{OP}: {foreign:?} is no key of the store")));
        }
        let mut seen = std::collections::HashSet::with_capacity(keys.len());
        if let Some(twice) = keys.iter().find(|k| !seen.insert(k.as_str())) {
            return Err(BridgeError::Config(format!("{OP}: the batch names {twice} twice")));
        }
        let doc = delete_document(keys);
        let headers = delete_headers(doc.as_bytes());
        let reply = self.send(OP, S3Method::Post, None, vec![("delete".to_string(), String::new())], headers, Body::Bytes(doc.into_bytes()), PART_TRIES).await?;
        match (reply.status, root_element(&reply.body)) {
            (200, Some("DeleteResult")) => delete_errors(&reply.body, keys).map_err(|why| BridgeError::Sdk { op: OP, message: format!("the bucket: {why}") }),
            (200, Some("Error")) => Err(reply.error("delete objects", 200)),
            (200, _) => Err(BridgeError::Sdk { op: OP, message: "the bucket: the answer is no DeleteResult".into() }),
            (status, _) => Err(reply.error("delete objects", status)),
        }
    }

    /// S12 (P): every key of `keys` deleted: batches of [`DELETE_BATCH`], the
    /// keys S3 refused with a code of [`KEY_RETRY`] sent again, one DeleteObject
    /// each when S3 refuses the batch's form.
    ///
    /// Every key is checked before the first request (P-R7, P-R3's text:
    /// nothing is sent when a later batch would hold a foreign key, LD-P3); a
    /// key given twice is taken once, at its first place (LD-P2); no key sends
    /// nothing. Round 1 sends the keys in order, a batch at a time
    /// ([`Self::delete_batch`]); a key refused with a code of [`KEY_RETRY`]
    /// goes into the next round, one refused with any other code is `failed`
    /// with it. Rounds 2 and 3 ([`PART_TRIES`]) send only the keys the round
    /// before refused so, in order, batched again, after [`RETRY_WAIT`] times
    /// the rounds so far (logged); one still refused at round 3 is `failed`
    /// with its last code (P-R8, LD-P4). When S3 refuses round 1's first
    /// batch for its form (a 405, or a 400 or 501 of [`BATCH_REFUSED`]),
    /// nothing was deleted by a batch, and every key goes as a DeleteObject
    /// of its own instead ([`Deleted::one_by_one`], P-R10, LD-P5; no memory
    /// across calls, LD-P7). Any other error of a batch, a later batch's or
    /// round's form refusal among them, ends it: what earlier batches deleted
    /// stays deleted (P-R11, P-R12).
    pub async fn delete_keys(&self, keys: &[String]) -> Result<Deleted, BridgeError> {
        const OP: &str = "s3 delete objects";
        let mut seen = std::collections::HashSet::with_capacity(keys.len());
        let mut distinct: Vec<String> = Vec::with_capacity(keys.len());
        for key in keys {
            if S3Key::parse(key).is_none() {
                return Err(BridgeError::Config(format!("{OP}: {key:?} is no key of the store")));
            }
            if seen.insert(key.as_str()) {
                distinct.push(key.clone());
            }
        }
        // Each key's place among the distinct ones: `failed` keeps their order, whatever order S3 answers in.
        let place: std::collections::HashMap<&str, usize> = distinct.iter().enumerate().map(|(i, k)| (k.as_str(), i)).collect();
        // The places a round sends, in order, and the codes the round before refused them with.
        let (mut pending, mut codes): (Vec<usize>, Vec<String>) = ((0..distinct.len()).collect(), Vec::new());
        let mut failed: Vec<(usize, KeyError)> = Vec::new();
        for round in 1..=PART_TRIES {
            if pending.is_empty() {
                break;
            }
            if round > 1 {
                tracing::warn!("{OP}: S3 refused {} key(s) for now ({}); sent again (round {round} of {PART_TRIES})", pending.len(), codes.join(", "));
                tokio::time::sleep(RETRY_WAIT * (round - 1)).await;
            }
            let mut again: Vec<(usize, String)> = Vec::new();
            // The places this round's answers named: a key S3 named twice counts once.
            let mut named = std::collections::HashSet::new();
            for (n, batch) in pending.chunks(DELETE_BATCH).enumerate() {
                let names: Vec<String> = batch.iter().map(|&i| distinct[i].clone()).collect();
                let refused = match self.delete_batch(&names).await {
                    Ok(refused) => refused,
                    Err(e) if round == 1 && n == 0 && form_refused(&e) => return self.delete_one_by_one(&distinct, &e).await,
                    Err(e) => return Err(e),
                };
                for KeyError { key, code } in refused {
                    // `delete_errors` took only keys the batch named, each one of `place`'s.
                    let Some(&i) = place.get(key.as_str()) else { continue };
                    if !named.insert(i) {
                        continue;
                    }
                    if round < PART_TRIES && KEY_RETRY.contains(&code.as_str()) {
                        again.push((i, code));
                    } else {
                        failed.push((i, KeyError { key, code }));
                    }
                }
            }
            again.sort_by_key(|(i, _)| *i);
            codes = Vec::new();
            for (_, code) in &again {
                if !codes.contains(code) {
                    codes.push(code.clone());
                }
            }
            pending = again.into_iter().map(|(i, _)| i).collect();
        }
        failed.sort_by_key(|(i, _)| *i);
        Ok(Deleted { deleted: distinct.len() - failed.len(), failed: failed.into_iter().map(|(_, e)| e).collect(), one_by_one: false })
    }

    /// S12 (P, P-R10, LD-P6): every key of `keys` (distinct, checked) as a
    /// DeleteObject of its own, once S3 refused the batch's form (`refused`,
    /// logged once): [`DELETE_PARALLEL`] at once, as a restore pulls its
    /// subtree, each up to [`PART_TRIES`] tries. A key S3 refuses is `failed`
    /// with its code, or `HTTP <status>` without one, in the order given; any
    /// other error (no answer at the last try, a presign refusal) ends it, the
    /// singles in flight dropped.
    async fn delete_one_by_one(&self, keys: &[String], refused: &BridgeError) -> Result<Deleted, BridgeError> {
        tracing::warn!("s3 delete objects: S3 refused the batch's form ({refused}); {} object(s) deleted one by one, {DELETE_PARALLEL} at a time", keys.len());
        let singles = keys.iter().enumerate().map(|(i, key)| async move {
            match self.delete_tries(key, PART_TRIES).await {
                Ok(()) => Ok(None),
                Err(BridgeError::S3 { status, code, .. }) => Ok(Some((i, KeyError { key: key.clone(), code: code.unwrap_or_else(|| format!("HTTP {status}")) }))),
                Err(e) => Err(e),
            }
        });
        let done: Vec<Option<(usize, KeyError)>> = futures_util::stream::iter(singles).buffer_unordered(DELETE_PARALLEL).try_collect().await?;
        let mut failed: Vec<(usize, KeyError)> = done.into_iter().flatten().collect();
        failed.sort_by_key(|(i, _)| *i);
        Ok(Deleted { deleted: keys.len() - failed.len(), failed: failed.into_iter().map(|(_, e)| e).collect(), one_by_one: true })
    }
}

/// S12 (P, P-R10): whether `e`, a purge's first DeleteObjects' error, refuses
/// the batch's form: `S3` with status 405 (whatever its code), or 400 or 501
/// with a code of [`BATCH_REFUSED`].
fn form_refused(e: &BridgeError) -> bool {
    match e {
        BridgeError::S3 { status: 405, .. } => true,
        BridgeError::S3 { status: 400 | 501, code: Some(code), .. } => BATCH_REFUSED.contains(&code.as_str()),
        _ => false,
    }
}

/// S11 (L5): the `content-encoding` header an encoded object's PutObject
/// or CreateMultipartUpload sends and signs (`gzip`); none for identity.
#[must_use]
pub fn encoding_header(encoding: Option<PartEncoding>) -> Option<(String, String)> {
    encoding.map(|e| ("content-encoding".to_string(), e.word().to_string()))
}

/// S12 (P): the DeleteObjects body of `keys`: `<Delete xmlns="…">`, one
/// `<Object><Key>…</Key></Object>` per key in order (escaped), `<Quiet>true</Quiet>`.
/// P-R2: no XML declaration, no whitespace, no `VersionId` (current versions
/// only: a delete marker each, as [`S3Client::delete`]); the objects before
/// `<Quiet>`, the order the AWS CLI writes the `Delete` shape's members in
/// (LD-P1). `pub`: the live probe sends these bytes (LD-P12).
#[must_use]
pub fn delete_document(keys: &[String]) -> String {
    let mut doc = format!("<Delete xmlns=\"{XMLNS}\">");
    for key in keys {
        doc.push_str("<Object><Key>");
        doc.push_str(&xml_escape(key));
        doc.push_str("</Key></Object>");
    }
    doc.push_str("<Quiet>true</Quiet></Delete>");
    doc
}

/// S12 (P, P-R1): the two headers a DeleteObjects of `body` signs besides
/// the owner's, exactly: `x-amz-sdk-checksum-algorithm: SHA256`, then
/// `x-amz-checksum-sha256`, the standard padded base64 of the body's 32-byte
/// SHA-256 (what `wire::s3::sha256_b64` gives for its hex): what AWS's SDKs
/// send in place of `Content-MD5`. No `content-md5`, and no `content-length`
/// signed (reqwest sends the length, as for a CompleteMultipartUpload).
fn delete_headers(body: &[u8]) -> Vec<(String, String)> {
    use base64::Engine as _;
    let checksum = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body));
    vec![("x-amz-sdk-checksum-algorithm".to_string(), "SHA256".to_string()), ("x-amz-checksum-sha256".to_string(), checksum)]
}

/// Query pairs in `presign::SIGNABLE_QUERY`'s order.
fn reorder(mut query: Vec<(String, String)>) -> Vec<(String, String)> {
    let at = |n: &str| super::presign::SIGNABLE_QUERY.iter().position(|q| *q == n).unwrap_or(usize::MAX);
    query.sort_by_key(|(n, _)| at(n));
    query
}

#[cfg(debug_assertions)]
fn lab_client(addr: std::net::SocketAddr) -> Result<reqwest::Client, BridgeError> {
    crate::bridge::tls::lab_http_client(addr, &addr.ip().to_string())
}

#[cfg(not(debug_assertions))]
fn lab_client(_addr: std::net::SocketAddr) -> Result<reqwest::Client, BridgeError> {
    Err(BridgeError::Config("the lab S3 exists in debug builds only".into()))
}

/// `len` bytes of `path` from `offset` as a request body, read in chunks
/// (never buffered whole), each chunk stamped into `progress` as the
/// connection takes it (S10 F5: a stalled uplink stops taking them).
async fn file_range(path: &Path, offset: u64, len: u64, progress: Arc<Progress>) -> Result<reqwest::Body, BridgeError> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
    let mut file = tokio::fs::File::open(path).await.map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display()))))?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let stream = futures_util::stream::unfold((file.take(len), vec![0u8; CHUNK], progress), |(mut file, mut buf, progress)| async move {
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                progress.handed(n as u64);
                Some((Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::copy_from_slice(&buf[..n])), (file, buf, progress)))
            }
            Err(e) => Some((Err(e), (file, buf, progress))),
        }
    });
    Ok(reqwest::Body::wrap_stream(stream))
}

/// One answer.
struct Reply {
    status: u16,
    version_id: Option<String>,
    etag: Option<String>,
    body: String,
}

impl Reply {
    /// The body is an S3 error document: its root element is `<Error>` (S12,
    /// P-R6: a 200 DeleteResult naming keys' `<Error>`s is none, so `send`
    /// never sends a whole batch again for one key's error; a 200 whose root
    /// is `<Error>`, a CompleteMultipartUpload's late error, still is).
    fn has_error(&self) -> bool {
        root_element(&self.body) == Some("Error")
    }

    /// S3 asks for the request again: a 500 or a 503; a 409 of
    /// [`RETRY_409`]; a 400 of [`RETRY_400`]; a 200 whose body is an error document of
    /// `InternalError` or of [`RETRY_409`] (a CompleteMultipartUpload that
    /// failed after its head went out, which S3's documentation says to send
    /// again).
    fn transient(&self) -> bool {
        let code = error_code(&self.body);
        let code_in = |codes: &[&str]| code.as_deref().is_some_and(|c| codes.contains(&c));
        match self.status {
            500 | 503 => true,
            409 => code_in(&RETRY_409),
            400 => code_in(&RETRY_400),
            200 => self.has_error() && (code_in(&["InternalError"]) || code_in(&RETRY_409)),
            _ => false,
        }
    }

    /// The error of `op` answered with `status`, naming S3's `<Code>` when the body carries one.
    fn error(&self, op: &'static str, status: u16) -> BridgeError {
        BridgeError::S3 { op, status, code: error_code(&self.body) }
    }
}

/// S3's `<Code>` in an error document: at most 64 characters of `[A-Za-z0-9]`.
#[must_use]
pub fn error_code(body: &str) -> Option<String> {
    let at = body.find("<Error>")?;
    xml_values(&body[at..], "Code").into_iter().next().filter(|c| (1..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// S12 (P, P-R6): the name of `xml`'s root element, `None` when no element
/// starts there. Skipped first, in any number and order: XML's whitespace
/// (S3's keep-alive spaces and newlines before a late error), declarations
/// `<?…?>` and comments `<!--…-->`; then the root is the name after `<` up
/// to whitespace, `>` or `/` (an XML name: a letter or `_`, then letters,
/// digits, `_`, `-`, `.`, `:`). Anything else there (a byte order mark,
/// text, an unclosed declaration or comment, `<!DOCTYPE`) is `None`.
fn root_element(xml: &str) -> Option<&str> {
    const SPACE: [char; 4] = [' ', '\t', '\r', '\n'];
    let mut rest = xml;
    loop {
        rest = rest.trim_start_matches(SPACE);
        if let Some(after) = rest.strip_prefix("<?") {
            rest = &after[after.find("?>")? + 2..];
        } else if let Some(after) = rest.strip_prefix("<!--") {
            rest = &after[after.find("-->")? + 3..];
        } else {
            break;
        }
    }
    let after = rest.strip_prefix('<')?;
    let name = &after[..after.find(|c: char| SPACE.contains(&c) || c == '>' || c == '/')?];
    let mut chars = name.chars();
    let first = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    (first && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))).then_some(name)
}

/// S12 (P, P-R5): a 200 DeleteResult's per-key errors, in its order: every
/// `<Error>` element's first `<Key>` and first `<Code>` (entities decoded; a
/// code that is not `[A-Za-z0-9]{1,64}` counts as none). `Err` names why the
/// answer is refused: an error without its key or its code, or one naming a
/// key `sent` (the request's) does not hold. `<Deleted>` elements (a verbose
/// answer's) and every `<Message>` are never read (PC-3).
fn delete_errors(body: &str, sent: &[String]) -> Result<Vec<KeyError>, String> {
    let sent: std::collections::HashSet<&str> = sent.iter().map(String::as_str).collect();
    let mut out = Vec::new();
    for error in xml_elements(body, "Error") {
        let key = xml_values(error, "Key").into_iter().next();
        let code = xml_values(error, "Code").into_iter().next().filter(|c| (1..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric()));
        let (Some(key), Some(code)) = (key, code) else {
            return Err("the answer names an error without its key or code".into());
        };
        if !sent.contains(key.as_str()) {
            return Err("the answer names an error of a key the request did not name".into());
        }
        out.push(KeyError { key, code });
    }
    Ok(out)
}

/// The text of every `<name>…</name>` element of `xml`, in order, its
/// entities decoded (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&#N;`,
/// `&#xH;`); an element with attributes counts (`<name a="…">`), a
/// self-closing one is empty. Bounded by the input: no recursion, no
/// allocation beyond the values.
#[must_use]
pub fn xml_values(xml: &str, name: &str) -> Vec<String> {
    xml_elements(xml, name).into_iter().map(xml_unescape).collect()
}

/// The raw inner text of every `<name>…</name>` element of `xml`, in order (not nested in itself).
#[must_use]
pub fn xml_elements<'x>(xml: &'x str, name: &str) -> Vec<&'x str> {
    let (open, close) = (format!("<{name}"), format!("</{name}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find(&open) {
        let after = &rest[at + open.len()..];
        // `<Name>`, `<Name attr…>` or `<Name/>`; not `<NameOther>`.
        let Some(end) = after.find('>') else { break };
        let head = &after[..end];
        if !(head.is_empty() || head.starts_with(char::is_whitespace) || head == "/" || head.ends_with('/') && head.starts_with(char::is_whitespace)) {
            rest = after;
            continue;
        }
        if head.ends_with('/') {
            out.push("");
            rest = &after[end + 1..];
            continue;
        }
        let body = &after[end + 1..];
        let Some(stop) = body.find(&close) else { break };
        out.push(&body[..stop]);
        rest = &body[stop + close.len()..];
    }
    out
}

/// `text` with XML's entities decoded; an unknown or malformed one is kept as it is.
fn xml_unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(semi) = tail.find(';').filter(|s| *s <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &tail[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `text` safe inside an XML element.
fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader takes S3's documents as they come: a listing's keys and
    /// sizes, its continuation, a ListParts answer, an error's code (only
    /// `[A-Za-z0-9]`, at most 64), entities decoded, a near-miss element
    /// name and a self-closing element.
    #[test]
    fn the_xml_reader_takes_s3s_answers_and_nothing_else() {
        let list = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>b</Name><IsTruncated>true</IsTruncated><NextContinuationToken>1/a+b=</NextContinuationToken><Contents><Key>v1/s/vm/g1/base</Key><Size>48213</Size></Contents><Contents><Key>v1/s/a&amp;b</Key><Size>7</Size></Contents></ListBucketResult>";
        assert_eq!(xml_values(list, "Key"), ["v1/s/vm/g1/base", "v1/s/a&b"]);
        assert_eq!(xml_values(list, "Size"), ["48213", "7"]);
        assert_eq!(xml_values(list, "NextContinuationToken"), ["1/a+b="]);
        assert_eq!(xml_values(list, "IsTruncated"), ["true"]);
        assert_eq!(xml_elements(list, "Contents").len(), 2);
        assert!(xml_values(list, "Name").len() == 1 && xml_values(list, "Na").is_empty(), "a near miss is no element");
        let parts = "<ListPartsResult><Part><PartNumber>1</PartNumber><ETag>&quot;0123&quot;</ETag><Size>67108864</Size><ChecksumSHA256>R0VUCg==</ChecksumSHA256></Part><Part><PartNumber>2</PartNumber><ETag>\"4567\"</ETag><Size>5</Size></Part></ListPartsResult>";
        let p = xml_elements(parts, "Part");
        assert_eq!((xml_values(p[0], "ETag"), xml_values(p[1], "ChecksumSHA256")), (vec!["\"0123\"".to_string()], Vec::<String>::new()));
        assert_eq!(error_code("<?xml version=\"1.0\"?>\n<Error><Code>PreconditionFailed</Code><Message>m</Message></Error>").as_deref(), Some("PreconditionFailed"));
        assert_eq!(error_code("<Error><Code>Bad Code</Code></Error>"), None, "not [A-Za-z0-9]");
        assert_eq!(error_code(&format!("<Error><Code>{}</Code></Error>", "A".repeat(65))), None);
        assert_eq!(error_code("<Code>NoErrorDocument</Code>"), None);
        assert_eq!(xml_values("<a><Key/><Key>x</Key></a>", "Key"), ["", "x"]);
        assert_eq!(xml_unescape("&#65;&#x42;&bogus;&"), "AB&bogus;&");
        assert_eq!(xml_escape("\"a&b<\""), "&quot;a&amp;b&lt;&quot;");
        assert_eq!(reorder(vec![("partNumber".into(), "1".into()), ("uploadId".into(), "u".into())]).iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["uploadId", "partNumber"]);
    }

    /// S10 F5: a try is held to its progress, never to a budget of its
    /// whole (S9's was 30 s plus its bytes at 1 MB/s, 567 s for a 64 MiB part
    /// beside seven others, three tries of which a dead uplink took): the
    /// contract's waits (a minute without a new chunk of the body, two
    /// minutes for the head after it, a minute a chunk of the answer); and
    /// what S3 asks to be sent again: a 500 or a 503, its two transient 409s
    /// and nothing else of 409, its 400 `RequestTimeout` (a body idle for
    /// some 20 s) and no other 400, and a 200 whose body is an
    /// `InternalError` (a Complete that failed after its head), never a
    /// plain 200, a 404 or another error in a 200.
    #[test]
    fn a_try_waits_for_progress_and_409s_of_s3s_two_codes_go_again() {
        assert_eq!((STALL_AFTER, HEAD_WAIT, CHUNK_WAIT), (Duration::from_secs(60), Duration::from_secs(120), Duration::from_secs(60)));
        assert_eq!(Waits::DEFAULT, Waits { stall: STALL_AFTER, head: HEAD_WAIT, chunk: CHUNK_WAIT });
        assert_eq!((shown(STALL_AFTER), shown(Duration::from_millis(300))), ("60 s".to_string(), "300 ms".to_string()));
        let reply = |status: u16, code: Option<&str>| Reply { status, version_id: None, etag: None, body: code.map_or_else(String::new, |c| format!("<?xml version=\"1.0\"?>\n<Error><Code>{c}</Code><Message>m</Message></Error>")) };
        for (status, code) in [(500, Some("InternalError")), (503, Some("SlowDown")), (503, None), (409, Some("OperationAborted")), (409, Some("ConditionalRequestConflict")), (400, Some("RequestTimeout")), (200, Some("InternalError")), (200, Some("OperationAborted"))] {
            assert!(reply(status, code).transient(), "{status} {code:?}");
        }
        for (status, code) in [(409, Some("BucketAlreadyExists")), (409, None), (400, Some("BadDigest")), (400, None), (200, None), (200, Some("AccessDenied")), (404, Some("NoSuchUpload")), (412, Some("PreconditionFailed")), (403, Some("AccessDenied"))] {
            assert!(!reply(status, code).transient(), "{status} {code:?}");
        }
    }

    /// S10 F5: the head's wait is longer by the time a body's last [`TAIL`]
    /// bytes took to be handed, which the connection's buffers may still
    /// hold once the last chunk went (a slow uplink drains them at about
    /// that pace): the time from the last chunk before the tail to the last
    /// of all; nothing for a body handed at once, or none. And what a stage
    /// counts of a request ([`S3Client::counting`]) is the most any of its
    /// tries handed: a byte a later try sends again counts once; another
    /// request's count adds to it.
    #[test]
    fn a_bodys_tail_lengthens_the_head_wait_and_a_byte_sent_again_counts_once() {
        let p = Progress::new(TAIL + (3 << 20), None);
        p.handed(2 << 20);
        std::thread::sleep(Duration::from_millis(150));
        // Past the body's length less the tail (3 MiB): the tail began after the first chunk.
        p.handed(2 << 20);
        std::thread::sleep(Duration::from_millis(150));
        p.handed(TAIL - (1 << 20));
        let total = TAIL + (3 << 20);
        assert_eq!(p.bytes(), total);
        assert!(p.tail_took() >= Duration::from_millis(290) && p.tail_took() < Duration::from_secs(5), "{:?}", p.tail_took());
        assert_eq!(p.deadline(total, total, &Waits::DEFAULT), p.last() + HEAD_WAIT + p.tail_took(), "the head's wait, and the tail's time");
        assert_eq!(p.deadline(total - 1, total, &Waits::DEFAULT), p.last() + STALL_AFTER, "a body not all handed: the stall's wait alone");
        let at_once = Progress::new(4096, None);
        at_once.handed(4096);
        assert!(at_once.tail_took() < Duration::from_millis(100), "{:?}", at_once.tail_took());
        assert_eq!(Progress::new(0, None).tail_took(), Duration::ZERO);
        let (count, most) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let first = Progress::new(8 << 20, Some((Arc::clone(&count), Arc::clone(&most))));
        first.handed(3 << 20);
        let second = Progress::new(8 << 20, Some((Arc::clone(&count), Arc::clone(&most))));
        second.handed(2 << 20);
        assert_eq!(count.load(Ordering::Relaxed), 3 << 20, "the second try's first 2 MiB went with the first's");
        second.handed(6 << 20);
        assert_eq!(count.load(Ordering::Relaxed), 8 << 20);
        let other = Progress::new(1 << 20, Some((Arc::clone(&count), Arc::new(AtomicU64::new(0)))));
        other.handed(1 << 20);
        assert_eq!(count.load(Ordering::Relaxed), 9 << 20, "another request's bytes");
    }

    /// S10 F5, the watchdog on loopback (a raw listener as S3, waits of a
    /// test's): a body the connection stops taking (the listener reads 64
    /// KiB of a 16 MiB part, then nothing, past what the kernel's buffers
    /// take) gives the try up after the stall wait, naming what it sent of
    /// what; a request taken whole and never answered, after the head wait,
    /// counted from the body's end however long the stall's wait (a list,
    /// which has no body; a small PutObject whose stall wait is ten
    /// seconds); a head then an answer that stops, after the chunk wait.
    /// Each is a try with no answer (exit 7), and none names the URL.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn a_stalled_body_head_or_answer_ends_the_try_after_its_wait() {
        use crate::bridge::s3::{LAB_BUCKET, LAB_OWNER};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let waits = Waits { stall: Duration::from_millis(700), head: Duration::from_millis(700), chunk: Duration::from_millis(700) };
        /// A listener that takes one connection: reads at most `take` bytes, then answers `answer` (or nothing) and holds it.
        async fn server(take: usize, answer: Option<&'static [u8]>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut s, _) = l.accept().await.unwrap();
                let mut got = vec![0u8; 64 * 1024];
                let mut read = 0;
                while read < take {
                    match s.read(&mut got).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => read += n,
                    }
                }
                if let Some(a) = answer {
                    let _ = s.write_all(a).await;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(s);
            });
            (addr, task)
        }
        let signer = crate::bridge::api::FakeMicrovmApi::new();
        let target = |addr| S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(addr) };
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("part");
        let len: u64 = 16 << 20;
        std::fs::write(&file, vec![b'x'; len as usize]).unwrap();
        let sha = "a".repeat(64);
        let key = crate::wire::s3::S3Key::Mac { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), sha256: sha.clone() }.render();
        // The body stops being taken: the stall.
        let (addr, task) = server(64 * 1024, None).await;
        let client = S3Client::new(&signer, &target(addr)).unwrap().with_waits(waits);
        let t = std::time::Instant::now();
        let e = client.upload_part(&key, "u1", 1, Body::File { path: file.clone(), offset: 0, len }, len, &sha).await.unwrap_err().to_string();
        task.abort();
        let sent = e.strip_prefix(&format!("aws s3 upload part: part 1 of {key}: no answer in 3 tries: sent ")).unwrap_or_else(|| panic!("{e}"));
        let (n, rest) = sent.split_once(' ').unwrap();
        assert!(n.parse::<u64>().is_ok_and(|n| n < len) && rest == format!("of {len} bytes, no progress for 700 ms"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(20), "three tries, each within its stall: {:?}", t.elapsed());
        assert!(!e.contains("http") && !e.contains(&addr.to_string()) && !e.contains("X-Amz"), "{e}");
        // Taken whole, never answered: the head wait (one try: a listing).
        let (addr, task) = server(1, None).await;
        let e = S3Client::new(&signer, &target(addr)).unwrap().with_waits(waits).list("v1/x/").await.unwrap_err();
        task.abort();
        assert_eq!(e.to_string(), "aws s3 list: the bucket: no answer: the request sent, no answer within 700 ms");
        assert_eq!(crate::errors::CliError::from(e).exit_code(), 7);
        // A head, then an answer that stops: the chunk wait.
        let (addr, task) = server(1, Some(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n<ListBucketResult>")).await;
        let e = S3Client::new(&signer, &target(addr)).unwrap().with_waits(waits).list("v1/x/").await.unwrap_err().to_string();
        task.abort();
        assert_eq!(e, "aws s3 list: the bucket: no answer: HTTP 200 came, then its answer stopped after 18 bytes for 700 ms");
        // A body handed whole, never answered: the head wait runs from the body's end, never after the stall's.
        let small = tmp.path().join("small");
        std::fs::write(&small, vec![b'y'; 4096]).unwrap();
        let (addr, task) = server(4096, None).await;
        let slow_stall = Waits { stall: Duration::from_secs(10), head: Duration::from_millis(500), ..waits };
        let t = std::time::Instant::now();
        let e = S3Client::new(&signer, &target(addr)).unwrap().with_waits(slow_stall).put_object(&key, Body::File { path: small, offset: 0, len: 4096 }, 4096, &sha, None).await.unwrap_err().to_string();
        task.abort();
        assert_eq!(e, format!("aws s3 put: {key}: no answer in 3 tries: the request sent, no answer within 500 ms"));
        assert!(t.elapsed() < Duration::from_secs(8), "three head waits and the waits between, no stall's: {:?}", t.elapsed());
    }

    /// S10 F5: a body that keeps moving is never cut, however long it takes
    /// past the stall wait: a listener that reads a 24 MiB PutObject at 6
    /// MiB/s (some 4 s, well past what the kernel's buffers take at once)
    /// stores it at the first try under a stall wait of 1.5 s. The watchdog
    /// counts from the last chunk handed, never from the try's start: a
    /// timer would give the try up while its bytes still move.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn a_slow_body_that_moves_is_never_cut() {
        use crate::bridge::s3::{LAB_BUCKET, LAB_OWNER};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        /// What the listener reads per second.
        const RATE: u64 = 6 << 20;
        let len: u64 = 24 << 20;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            // The head, then the body's bytes counted, each read paced at the rate.
            let (mut head, mut body): (Vec<u8>, Option<u64>) = (Vec::new(), None);
            while body.is_none_or(|b| b < len) {
                let n = match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                match body.as_mut() {
                    Some(b) => *b += n as u64,
                    None => {
                        head.extend_from_slice(&buf[..n]);
                        body = head.windows(4).position(|w| w == b"\r\n\r\n").map(|at| (head.len() - at - 4) as u64);
                    }
                }
                tokio::time::sleep(Duration::from_micros(n as u64 * 1_000_000 / RATE)).await;
            }
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nx-amz-version-id: v7\r\nContent-Length: 0\r\n\r\n").await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let signer = crate::bridge::api::FakeMicrovmApi::new();
        let target = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(addr) };
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("body");
        std::fs::write(&file, vec![b'x'; len as usize]).unwrap();
        let sha = "a".repeat(64);
        let key = crate::wire::s3::S3Key::Mac { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), sha256: sha.clone() }.render();
        let waits = Waits { stall: Duration::from_millis(1500), head: Duration::from_secs(30), chunk: Duration::from_secs(30) };
        let client = S3Client::new(&signer, &target).unwrap().with_waits(waits);
        let t = std::time::Instant::now();
        let stored = client.put_object(&key, Body::File { path: file, offset: 0, len }, len, &sha, None).await;
        task.abort();
        assert_eq!(stored.unwrap(), Written::Stored("v7".into()));
        assert!(t.elapsed() > waits.stall * 2, "a transfer longer than the stall wait: {:?}", t.elapsed());
    }

    /// A request that gets no answer names its cause, never its URL: a
    /// timeout says it timed out and after how long (reqwest's own error,
    /// from a loopback listener that takes the connection and never
    /// answers); through `send`, one try of a request alone (a listing of a
    /// listener that closes every connection unanswered) is `no answer: `
    /// and the cause (exit 7), with nothing of the URL, its signature or the
    /// address in it.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn no_answer_names_its_cause_never_the_url() {
        use crate::bridge::s3::{LAB_BUCKET, LAB_OWNER};
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap();
        let held = tokio::spawn(async move {
            let (s, _) = silent.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        });
        let http = crate::bridge::tls::lab_http_client(addr, &addr.ip().to_string()).unwrap();
        let url = format!("http://{addr}/{LAB_BUCKET}/k?X-Amz-Signature={}", "5".repeat(64));
        let e = http.get(&url).timeout(Duration::from_secs(1)).send().await.unwrap_err();
        held.abort();
        let text = cause(e, Duration::from_secs(1));
        assert!(text.starts_with("error sending request: ") && text.ends_with(" (timed out after 1 s)"), "{text}");
        assert!(!text.contains("http") && !text.contains(&addr.to_string()) && !text.contains("X-Amz") && !text.contains("redacted"), "{text}");
        let closing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = closing.local_addr().unwrap();
        let closer = tokio::spawn(async move {
            while let Ok((s, _)) = closing.accept().await {
                drop(s);
            }
        });
        let signer = crate::bridge::api::FakeMicrovmApi::new();
        let target = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(addr) };
        let e = S3Client::new(&signer, &target).unwrap().list("v1/x/").await.unwrap_err();
        closer.abort();
        let text = e.to_string();
        let rest = text.strip_prefix("aws s3 list: the bucket: no answer: error sending request: ").unwrap_or_else(|| panic!("{text}"));
        assert!(!rest.is_empty() && !text.contains("http") && !text.contains(&addr.to_string()) && !text.contains("X-Amz") && !text.contains("redacted"), "{text}");
        assert_eq!(crate::errors::CliError::from(e).exit_code(), 7);
    }

    /// S12 (P, P-R6): an answer is an error document only when its root
    /// element is `<Error>`, past whitespace (S3's keep-alive spaces and
    /// newlines), declarations and comments in any order; a byte order mark,
    /// text, an unclosed declaration or comment, or `<!DOCTYPE` first is no
    /// root. So a 200 DeleteResult naming one key's `InternalError` is neither
    /// an error document nor sent again (one key's error never sends its
    /// batch again), a late `InternalError` after the keep-alive spaces is
    /// both, and a CompleteMultipartUploadResult whose ETag holds an escaped
    /// `<Error>` is neither. And the batch's frozen numbers (§3.8).
    #[test]
    fn a_key_error_in_a_delete_result_is_no_error_document() {
        assert_eq!(root_element("  \n\r\n\t<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- a comment -->\n<Error><Code>InternalError</Code></Error>"), Some("Error"));
        assert_eq!(root_element("<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"), Some("DeleteResult"));
        assert_eq!(root_element("<!-- one --><?xml version=\"1.0\"?><!-- two --><a/>"), Some("a"), "comments and declarations in any order");
        for none in ["", "text <Error>", "<?xml version=\"1.0\" encoding=\"UTF-8\"", "<!-- open <Error>", "\u{feff}<Error>", "< Error>", "<!DOCTYPE x><Error>", "<Error"] {
            assert_eq!(root_element(none), None, "{none:?}");
        }
        let reply = |body: &str| Reply { status: 200, version_id: None, etag: None, body: body.to_string() };
        let result = reply("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Error><Key>k</Key><Code>InternalError</Code><Message>We encountered an internal error. Please try again.</Message></Error></DeleteResult>");
        assert!(!result.has_error() && !result.transient(), "one key's error is no error document: the batch is not sent again");
        let late = reply(&format!("{}\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InternalError</Code><Message>m</Message></Error>", " ".repeat(40)));
        assert!(late.has_error() && late.transient(), "a late error after the keep-alive spaces goes again");
        let complete = reply("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUploadResult><Bucket>b</Bucket><ETag>&lt;Error&gt;</ETag></CompleteMultipartUploadResult>");
        assert!(!complete.has_error() && !complete.transient());
        assert_eq!((KEY_RETRY, DELETE_BATCH, DELETE_PARALLEL), (["InternalError", "ServiceUnavailable", "SlowDown", "OperationAborted"], 1000, 16));
        assert_eq!(BATCH_REFUSED, ["InvalidRequest", "MissingContentMD5", "NotImplemented"]);
    }

    /// S12 (P, P-R5): the DeleteResult reader takes S3's answers and nothing
    /// else: a quiet answer with no error (self-closing, or empty) leaves no
    /// key; two errors are two keys left, in the answer's order, each with
    /// its code (entities decoded, `<Message>` never read); a verbose
    /// answer's `<Deleted>` entries are never read; an error without its
    /// code, without its key, with a code that is not `[A-Za-z0-9]{1,64}`
    /// (`Bad Code`, 65 characters), or naming a key the request did not name
    /// refuses the whole answer.
    #[test]
    fn the_delete_result_reader_takes_s3s_answer_and_nothing_else() {
        let sent = vec!["v1/a".to_string(), "v1/b&c".to_string(), "v1/d".to_string()];
        let doc = |inner: &str| format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{inner}</DeleteResult>");
        assert_eq!(delete_errors("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>", &sent), Ok(Vec::new()));
        assert_eq!(delete_errors(&doc(""), &sent), Ok(Vec::new()));
        let two = doc("<Error><Key>v1/d</Key><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error><Deleted><Key>v1/a</Key></Deleted><Error><Key>v1/b&amp;c</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>");
        assert_eq!(delete_errors(&two, &sent), Ok(vec![KeyError { key: "v1/d".into(), code: "SlowDown".into() }, KeyError { key: "v1/b&c".into(), code: "AccessDenied".into() }]), "the answer's order, entities decoded");
        let verbose = doc("<Deleted><Key>v1/a</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>fv9</DeleteMarkerVersionId></Deleted><Deleted><Key>v1/zz</Key></Deleted>");
        assert_eq!(delete_errors(&verbose, &sent), Ok(Vec::new()), "a verbose answer's Deleted entries are never read");
        let long = format!("<Error><Key>v1/a</Key><Code>{}</Code></Error>", "A".repeat(65));
        for (inner, why) in [
            ("<Error><Key>v1/a</Key><Message>AccessDenied</Message></Error>", "the answer names an error without its key or code"),
            ("<Error><Code>AccessDenied</Code></Error>", "the answer names an error without its key or code"),
            ("<Error><Key>v1/a</Key><Code>Bad Code</Code></Error>", "the answer names an error without its key or code"),
            (long.as_str(), "the answer names an error without its key or code"),
            ("<Error><Key>v1/d</Key><Code>SlowDown</Code></Error><Error><Key>v1/zz</Key><Code>AccessDenied</Code></Error>", "the answer names an error of a key the request did not name"),
        ] {
            assert_eq!(delete_errors(&doc(inner), &sent), Err(why.to_string()), "{inner}");
        }
    }

    /// S12 (P, P-R1, P-R2): the DeleteObjects body of two keys is S3's quiet
    /// form byte for byte (the objects in order, then `<Quiet>`; no
    /// declaration, no whitespace, no `VersionId`), 298 bytes whose SHA-256
    /// is a known answer (computed apart with `shasum -a 256`, 25 Oct 2026);
    /// the pair it signs is the SDK's algorithm and that digest in standard
    /// base64, what `wire::s3::sha256_b64` gives for its hex. A key is escaped.
    #[test]
    fn the_delete_document_and_its_checksum_are_s3s_quiet_form() {
        let s = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let keys = vec![format!("v1/{s}/mac/b094ab054161cac4f8714d6855dc32bf0488f8eed1c4790aec8f054577f7c5c2"), format!("v1/{s}/vm/g1/base")];
        let doc = delete_document(&keys);
        assert_eq!(doc, format!("<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Object><Key>{}</Key></Object><Object><Key>{}</Key></Object><Quiet>true</Quiet></Delete>", keys[0], keys[1]));
        assert_eq!(doc.len(), 298);
        assert_eq!(hex::encode(Sha256::digest(doc.as_bytes())), "1386c936b42422a089883736d1101195fcc1f7698adc754ddd0efd4162f8ba30");
        let pair = vec![("x-amz-sdk-checksum-algorithm".to_string(), "SHA256".to_string()), ("x-amz-checksum-sha256".to_string(), "E4bJNrQkIqCJiDc20RARlfzB92mK3HVN3Q79QWL4ujA=".to_string())];
        assert_eq!(delete_headers(doc.as_bytes()), pair);
        assert_eq!(crate::wire::s3::sha256_b64("1386c936b42422a089883736d1101195fcc1f7698adc754ddd0efd4162f8ba30").as_deref(), Some(pair[1].1.as_str()), "sha256_b64 of its hex");
        assert_eq!(delete_document(&["v1/a&b<c>\"d".to_string()]), "<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Object><Key>v1/a&amp;b&lt;c&gt;&quot;d</Key></Object><Quiet>true</Quiet></Delete>");
    }

    /// S12 (P, P-R3, P-R7): `delete_batch` refuses before it sends anything
    /// (`Config`, exit 1): no key, 1001 keys, a key that is none of the
    /// store's (Debug-quoted), a key twice; `delete_keys` of no key is
    /// nothing done, and it checks every key before its first batch, so 1000
    /// good keys with a foreign one after them send nothing either. S3 is a
    /// loopback listener that never accepts, the client's waits a test's
    /// short ones: nothing ever connected to it.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn delete_batch_refuses_an_empty_an_oversized_or_a_foreign_batch_before_sending() {
        use crate::bridge::s3::{LAB_BUCKET, LAB_OWNER};
        /// The `Config` text of `r`, its exit 1.
        fn config<T: std::fmt::Debug>(r: Result<T, BridgeError>) -> String {
            match r {
                Err(BridgeError::Config(m)) => {
                    assert_eq!(crate::errors::CliError::from(BridgeError::Config(m.clone())).exit_code(), 1);
                    m
                }
                other => panic!("expected Config, got {other:?}"),
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(listener.local_addr().unwrap()) };
        let signer = crate::bridge::api::FakeMicrovmApi::new();
        let waits = Waits { stall: Duration::from_millis(300), head: Duration::from_millis(300), chunk: Duration::from_millis(300) };
        let client = S3Client::new(&signer, &target).unwrap().with_waits(waits);
        let good = |i: usize| S3Key::Mac { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), sha256: format!("{i:064x}") }.render();
        let thousand: Vec<String> = (0..DELETE_BATCH).map(good).collect();
        assert_eq!(config(client.delete_batch(&[]).await), "s3 delete objects: a batch of 0 keys (1 to 1000)");
        let over: Vec<String> = (0..=DELETE_BATCH).map(good).collect();
        assert_eq!(config(client.delete_batch(&over).await), "s3 delete objects: a batch of 1001 keys (1 to 1000)");
        assert_eq!(config(client.delete_batch(&[good(0), "v1/not/ours".into()]).await), "s3 delete objects: \"v1/not/ours\" is no key of the store");
        assert_eq!(config(client.delete_batch(&[good(0), good(1), good(0)]).await), format!("s3 delete objects: the batch names {} twice", good(0)));
        assert_eq!(client.delete_keys(&[]).await.unwrap(), Deleted::default(), "no key: nothing done");
        let mut foreign = thousand;
        foreign.push("x/_egress-check/short".into());
        assert_eq!(config(client.delete_keys(&foreign).await), "s3 delete objects: \"x/_egress-check/short\" is no key of the store");
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "nothing connected to S3");
    }

    /// S12 (P, P-R4, P-R5): a 200 is taken only as a DeleteResult that
    /// `delete_errors` reads. A 200 of another form (an empty body, a
    /// listing's document) is `aws s3 delete objects: the bucket: the answer
    /// is no DeleteResult`, and a DeleteResult naming an error of a key the
    /// request did not name is refused with that reason; each is `Sdk`, exit
    /// 7, never no key refused (the answer of a misdirected or garbled request
    /// says nothing of the keys sent). S3 is a loopback listener that takes
    /// one request whole and answers it once, the client's waits a test's.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn a_delete_objects_answer_of_another_form_is_refused() {
        use crate::bridge::s3::{LAB_BUCKET, LAB_OWNER};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        /// A listener that takes one request whole (its head, then its `Content-Length`'s bytes), answers `answer`, and closes.
        async fn answering(answer: Vec<u8>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut s, _) = l.accept().await.unwrap();
                let (mut got, mut buf) = (Vec::new(), vec![0u8; 64 * 1024]);
                loop {
                    if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
                        let len = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
                        if got.len() >= end + 4 + len {
                            break;
                        }
                    }
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(&answer).await;
                let _ = s.shutdown().await;
            });
            (addr, task)
        }
        let ok = |body: &str| format!("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes();
        let session = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let key = S3Key::Mac { session: session.into(), sha256: "a".repeat(64) }.render();
        let another = S3Key::Mac { session: session.into(), sha256: "b".repeat(64) }.render();
        let signer = crate::bridge::api::FakeMicrovmApi::new();
        let waits = Waits { stall: Duration::from_secs(2), head: Duration::from_secs(2), chunk: Duration::from_secs(2) };
        for (answer, why) in [
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(), "the answer is no DeleteResult"),
            (ok("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult/>"), "the answer is no DeleteResult"),
            (ok(&format!("<DeleteResult xmlns=\"{XMLNS}\"><Error><Key>{another}</Key><Code>AccessDenied</Code></Error></DeleteResult>")), "the answer names an error of a key the request did not name"),
        ] {
            let (addr, task) = answering(answer).await;
            let target = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(addr) };
            let e = S3Client::new(&signer, &target).unwrap().with_waits(waits).delete_batch(std::slice::from_ref(&key)).await.unwrap_err();
            task.abort();
            assert!(matches!(&e, BridgeError::Sdk { op: "s3 delete objects", message } if *message == format!("the bucket: {why}")), "{why}: {e:?}");
            assert_eq!(e.to_string(), format!("aws s3 delete objects: the bucket: {why}"));
            assert_eq!(crate::errors::CliError::from(e).exit_code(), 7, "{why}");
        }
    }
}
