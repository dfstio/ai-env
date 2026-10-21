//! The Mac's own requests to the transcript store (S9 plan §5, G4): a
//! Mac-begun chat's upload (PutObject, or a multipart upload of
//! `MULTIPART_PART` parts with a signed sha256 each: CreateMultipartUpload,
//! UploadPart, ListParts, CompleteMultipartUpload, AbortMultipartUpload),
//! ListObjectsV2 of a session's prefix, and DeleteObject (gc, a compaction's
//! superseded keys, `forget --purge`). Each is presigned like the VM's
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
//! URL.
use super::presign::{request, write_headers};
use super::{PresignReq, S3Endpoint, S3Method, S3Sign, S3Target};
use crate::bridge::errors::BridgeError;
use crate::wire::s3::{PresignedUrl, PRESIGN_EXPIRY};
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
    /// Up to [`PART_TRIES`] tries.
    pub async fn put_object(&self, key: &str, body: Body, len: u64, sha256: &str) -> Result<Written, BridgeError> {
        const OP: &str = "s3 put";
        let reply = self.send(OP, S3Method::Put, Some(key), Vec::new(), write_headers(len, sha256, true)?, body, PART_TRIES).await?;
        match reply.status {
            200 => Ok(Written::Stored(reply.version_id.unwrap_or_default())),
            412 => Ok(Written::Exists),
            s => Err(reply.error("put", s)),
        }
    }

    /// CreateMultipartUpload of `key` with SHA-256 part checksums: its upload id.
    pub async fn create_multipart(&self, key: &str) -> Result<String, BridgeError> {
        const OP: &str = "s3 create multipart upload";
        let headers = vec![("x-amz-checksum-algorithm".to_string(), "SHA256".to_string())];
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
    /// expire after 30 days by the bucket's lifecycle).
    pub async fn delete(&self, key: &str) -> Result<(), BridgeError> {
        const OP: &str = "s3 delete";
        let reply = self.send(OP, S3Method::Delete, Some(key), Vec::new(), Vec::new(), Body::None, 1).await?;
        match reply.status {
            200 | 204 => Ok(()),
            s => Err(reply.error("delete", s)),
        }
    }
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
    /// The body is an S3 error document.
    fn has_error(&self) -> bool {
        self.body.contains("<Error>")
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
        let e = S3Client::new(&signer, &target(addr)).unwrap().with_waits(slow_stall).put_object(&key, Body::File { path: small, offset: 0, len: 4096 }, 4096, &sha).await.unwrap_err().to_string();
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
        let stored = client.put_object(&key, Body::File { path: file, offset: 0, len }, len, &sha).await;
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
}
