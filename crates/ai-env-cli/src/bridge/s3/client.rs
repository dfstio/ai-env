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
//! ([`xml_values`]), never a new crate. A request's budget allows for the
//! requests sent beside it ([`budget`]); an UploadPart or a PutObject that
//! gets no answer, or S3's 500 or 503, goes again ([`PART_TRIES`]); a
//! request with no answer names its cause, never its URL.
use super::presign::{request, write_headers};
use super::{PresignReq, S3Endpoint, S3Method, S3Sign, S3Target};
use crate::bridge::errors::BridgeError;
use crate::wire::s3::{PresignedUrl, PRESIGN_EXPIRY};
use std::path::Path;
use std::time::Duration;

/// The largest XML answer read (ListParts of 10000 parts is under 2 MiB).
pub const XML_MAX: usize = 8 << 20;
/// One request's budget beyond its body (sent at 1 MB/s, `dataplane::MIN_RATE`).
const REQUEST_BASE: Duration = Duration::from_secs(30);
/// How many times the stage's bytes (an UploadPart; a PutObject, a file of
/// one part) are sent at most: a try that got no HTTP answer (a timeout, a
/// reset, a TLS error) or S3's 500 or 503 goes again, presigned anew. Safe:
/// a part sent again replaces the one of its number, and a PutObject that
/// landed already answers 412 (`If-None-Match: *`), which is `Exists`.
pub const PART_TRIES: u32 = 3;
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

/// The store's client on this Mac: `signer`'s credentials, one target.
pub struct S3Client<'a, S> {
    signer: &'a S,
    target: S3Target,
    http: reqwest::Client,
}

/// A transport failure of `op`, scrubbed (the URL is registered with the scrubber while held).
fn transport(op: &'static str, e: &dyn std::fmt::Display) -> BridgeError {
    BridgeError::Sdk { op, message: crate::wire::redact::scrub(&e.to_string()).into_owned() }
}

/// The budget of a request of `bytes` sent while `shared` requests in all
/// (itself included) share the uplink: [`REQUEST_BASE`], plus its bytes
/// `shared` times over at `dataplane::MIN_RATE`, the slowest whole transfer
/// a budget allows (its share of it). `shared` 1: a request alone.
#[must_use]
pub fn budget(bytes: u64, shared: usize) -> Duration {
    let shared = u64::try_from(shared.max(1)).unwrap_or(u64::MAX);
    REQUEST_BASE + Duration::from_secs(bytes.saturating_mul(shared).div_ceil(crate::bridge::dataplane::MIN_RATE))
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
        Ok(S3Client { signer, target: target.clone(), http })
    }

    /// The target this client writes to.
    #[must_use]
    pub fn target(&self) -> &S3Target {
        &self.target
    }

    /// Presign `method` on `key` with `query` and `headers` (the owner's
    /// added), send it with exactly those headers and `body`, and read the
    /// answer: its status, its `x-amz-version-id` and its body (at most
    /// [`XML_MAX`]). Its budget is [`budget`] of its body with `shared`
    /// requests in flight. With `tries` over 1, a try that got no HTTP
    /// answer, or S3's 500 or 503, goes again while tries are left,
    /// presigned anew, after [`RETRY_WAIT`] times the tries so far (logged);
    /// no answer at the last try is the error (`Sdk`, exit 7), naming its
    /// cause, how many tries and what S3 answered before (a 500 or 503),
    /// never the URL.
    #[allow(clippy::too_many_arguments)]
    async fn send(&self, op: &'static str, method: S3Method, key: Option<&str>, query: Vec<(String, String)>, headers: Vec<(String, String)>, body: Body, shared: usize, tries: u32) -> Result<Reply, BridgeError> {
        let req = request(method, &self.target, key.map(str::to_string), query, headers, PRESIGN_EXPIRY);
        // What an error names: the key (and the part), never the URL.
        let what = match (key, req.query.iter().find(|(n, _)| n == "partNumber")) {
            (Some(k), Some((_, n))) => format!("part {n} of {k}"),
            (Some(k), None) => k.to_string(),
            (None, _) => "the bucket".to_string(),
        };
        let timeout = budget(body.len(), shared);
        let mut tried = 0u32;
        // S3's answers to the tries sent again (a 500 or 503): the error names them.
        let mut answered: Vec<String> = Vec::new();
        loop {
            tried += 1;
            let again = match self.try_send(op, &req, &body, timeout, &what).await? {
                Tried::Answer(reply) if tried < tries && matches!(reply.status, 500 | 503) => {
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
    /// no answer and its cause (scrubbed while the URL is held). An error is
    /// final: the presign, the file, an answer over [`XML_MAX`].
    async fn try_send(&self, op: &'static str, req: &PresignReq, body: &Body, timeout: Duration, what: &str) -> Result<Tried, BridgeError> {
        let url: PresignedUrl = self.signer.presign(req).await?;
        let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes()).map_err(|e| transport(op, &e))?;
        let mut rb = self.http.request(method, url.expose()).timeout(timeout);
        for (name, value) in &req.headers {
            rb = rb.header(name.as_str(), value.as_str());
        }
        rb = match body {
            Body::None => rb,
            Body::Bytes(b) => rb.body(b.clone()),
            Body::File { path, offset, len } => rb.body(file_range(path, *offset, *len).await?),
        };
        let sent = std::time::Instant::now();
        let mut resp = match rb.send().await {
            Ok(resp) => resp,
            Err(e) => return Ok(Tried::NoAnswer(cause(e, sent.elapsed()))),
        };
        let status = resp.status().as_u16();
        let version_id = resp.headers().get("x-amz-version-id").and_then(|v| v.to_str().ok()).map(str::to_string);
        let etag = resp.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok()).map(str::to_string);
        let mut text = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if text.len() + chunk.len() > XML_MAX {
                        return Err(BridgeError::Sdk { op, message: format!("{what}: the answer is larger than {} MiB", XML_MAX >> 20) });
                    }
                    text.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => return Ok(Tried::NoAnswer(cause(e, sent.elapsed()))),
            }
        }
        Ok(Tried::Answer(Reply { status, version_id, etag, body: String::from_utf8_lossy(&text).into_owned() }))
    }

    /// PutObject of `body` (`len` bytes, `sha256` its digest) at `key`, new
    /// only (`If-None-Match: *`): stored with its version, or `Exists` (412).
    /// Sent alone, up to [`PART_TRIES`] times.
    pub async fn put_object(&self, key: &str, body: Body, len: u64, sha256: &str) -> Result<Written, BridgeError> {
        const OP: &str = "s3 put";
        let reply = self.send(OP, S3Method::Put, Some(key), Vec::new(), write_headers(len, sha256, true)?, body, 1, PART_TRIES).await?;
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
        let reply = self.send(OP, S3Method::Post, Some(key), vec![("uploads".into(), String::new())], headers, Body::None, 1, 1).await?;
        if reply.status != 200 || reply.has_error() {
            return Err(reply.error("create multipart upload", reply.status));
        }
        let id = xml_values(&reply.body, "UploadId").into_iter().next().filter(|id| !id.is_empty() && id.len() <= 1024 && id.bytes().all(|b| b.is_ascii_graphic()));
        id.ok_or_else(|| BridgeError::Sdk { op: OP, message: "the answer names no UploadId".into() })
    }

    /// UploadPart `number` of `upload_id` (`len` bytes, `sha256` signed): its
    /// ETag. `shared`: the parts sent at once, this one included (its
    /// [`budget`] allows for them); up to [`PART_TRIES`] tries.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_part(&self, key: &str, upload_id: &str, number: u32, body: Body, len: u64, sha256: &str, shared: usize) -> Result<String, BridgeError> {
        const OP: &str = "s3 upload part";
        let query = vec![("uploadId".to_string(), upload_id.to_string()), ("partNumber".to_string(), number.to_string())];
        let reply = self.send(OP, S3Method::Put, Some(key), reorder(query), write_headers(len, sha256, false)?, body, shared, PART_TRIES).await?;
        if reply.status != 200 {
            return Err(reply.error("upload part", reply.status));
        }
        reply.etag.filter(|e| !e.is_empty()).ok_or_else(|| BridgeError::Sdk { op: OP, message: format!("part {number}: the answer carries no ETag") })
    }

    /// ListParts of `upload_id` (every page): `None` when S3 knows no such upload (404 `NoSuchUpload`).
    pub async fn list_parts(&self, key: &str, upload_id: &str) -> Result<Option<Vec<ListedPart>>, BridgeError> {
        const OP: &str = "s3 list parts";
        let reply = self.send(OP, S3Method::Get, Some(key), vec![("uploadId".into(), upload_id.to_string())], Vec::new(), Body::None, 1, 1).await?;
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
    /// sha256 hex) in order, new only (`If-None-Match: *`).
    pub async fn complete_multipart(&self, key: &str, upload_id: &str, parts: &[(u32, String, String)]) -> Result<Written, BridgeError> {
        const OP: &str = "s3 complete multipart upload";
        let mut doc = format!("<CompleteMultipartUpload xmlns=\"{XMLNS}\">");
        for (n, etag, sha) in parts {
            let checksum = crate::wire::s3::sha256_b64(sha).ok_or_else(|| BridgeError::Config(format!("{OP}: part {n}'s sha256 is not 64 lowercase hex digits")))?;
            doc.push_str(&format!("<Part><ETag>{}</ETag><PartNumber>{n}</PartNumber><ChecksumSHA256>{checksum}</ChecksumSHA256></Part>", xml_escape(etag)));
        }
        doc.push_str("</CompleteMultipartUpload>");
        let headers = vec![("if-none-match".to_string(), "*".to_string())];
        let reply = self.send(OP, S3Method::Post, Some(key), vec![("uploadId".into(), upload_id.to_string())], headers, Body::Bytes(doc.into_bytes()), 1, 1).await?;
        match reply.status {
            // S3 can answer 200 and then an error document (the completion failed after the head went out).
            200 if reply.has_error() => Err(reply.error("complete multipart upload", 200)),
            200 => Ok(Written::Stored(reply.version_id.unwrap_or_default())),
            412 => Ok(Written::Exists),
            s => Err(reply.error("complete multipart upload", s)),
        }
    }

    /// AbortMultipartUpload of `upload_id` (a 404 is an upload already gone).
    pub async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<(), BridgeError> {
        const OP: &str = "s3 abort multipart upload";
        let reply = self.send(OP, S3Method::Delete, Some(key), vec![("uploadId".into(), upload_id.to_string())], Vec::new(), Body::None, 1, 1).await?;
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
            let reply = self.send(OP, S3Method::Get, None, query, Vec::new(), Body::None, 1, 1).await?;
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
        let reply = self.send(OP, S3Method::Delete, Some(key), Vec::new(), Vec::new(), Body::None, 1, 1).await?;
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

/// `len` bytes of `path` from `offset` as a request body, read in chunks (never buffered whole).
async fn file_range(path: &Path, offset: u64, len: u64) -> Result<reqwest::Body, BridgeError> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
    let mut file = tokio::fs::File::open(path).await.map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display()))))?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let stream = futures_util::stream::unfold((file.take(len), vec![0u8; CHUNK]), |(mut file, mut buf)| async move {
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => Some((Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::copy_from_slice(&buf[..n])), (file, buf))),
            Err(e) => Some((Err(e), (file, buf))),
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

    /// B6 (a): eight 64 MiB parts at once share the Mac's uplink, so a
    /// part's budget allows for all eight at `dataplane::MIN_RATE`: 30 s
    /// plus 8 × 64 MiB at 1 MB/s, 567 s (it was 98 s, a part alone's, which
    /// eight parts on a 5 MB/s uplink outlast). A request alone keeps its
    /// budget; none in flight counts as one; it saturates, never overflows.
    #[test]
    fn a_parts_budget_allows_for_the_parts_beside_it() {
        use crate::wire::s3::{MULTIPART_PARALLEL, MULTIPART_PART};
        assert_eq!(budget(MULTIPART_PART, MULTIPART_PARALLEL), Duration::from_secs(567), "eight in flight");
        let eight = MULTIPART_PART * MULTIPART_PARALLEL as u64;
        assert!(budget(MULTIPART_PART, MULTIPART_PARALLEL) >= REQUEST_BASE + Duration::from_secs(eight / crate::bridge::dataplane::MIN_RATE), "the eight parts' bytes at MIN_RATE");
        // The live uplink, near 5 MB/s: eight parts at once take 107 s, past a part alone's budget, within the shared one.
        let live = Duration::from_secs(eight / 5_000_000);
        assert!(budget(MULTIPART_PART, 1) < live && live < budget(MULTIPART_PART, MULTIPART_PARALLEL), "{live:?}");
        assert_eq!(budget(MULTIPART_PART, 1), Duration::from_secs(98), "alone: as before");
        assert_eq!((budget(0, 8), budget(1000, 0)), (REQUEST_BASE, budget(1000, 1)));
        assert!(budget(u64::MAX, usize::MAX) > REQUEST_BASE);
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
