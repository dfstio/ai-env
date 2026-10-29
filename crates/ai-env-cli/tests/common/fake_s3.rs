//! The tests' S3 (S9, plans/s9-contracts.md §8.1): a loopback S3 on its own
//! thread and current-thread runtime (as `fake_endpoint.rs`), plain HTTP/1.1
//! over tokio sockets, path-style (`/<bucket>/<key>`), versioned, one bucket
//! (`s3::LAB_BUCKET`, owner `s3::LAB_OWNER`). It takes what the transcript
//! store sends it: the Mac's own presigned requests under
//! `AI_ENV_BRIDGE_LAB_S3_ADDR` (with the fake API), and the VM's curl through
//! the fake curl with `S3CURL_REAL`.
//!
//! Authentication is query-string SigV4 only, checked by signing the request
//! again with `aws-sigv4` (its `X-Amz-Date`, `LAB_KEY_ID`, `LAB_SECRET`,
//! `eu-central-1`, `s3`, S3's settings: the path encoded once and never
//! normalised, an unsigned payload): a mismatch is 403
//! `SignatureDoesNotMatch`; past `X-Amz-Date` plus `X-Amz-Expires`, any
//! `x-amz-*` header not signed (as S3: "There were headers present in the
//! request which were not signed"; `x-amz-checksum-mode` included), an
//! `x-amz-expected-bucket-owner` other than `LAB_OWNER`, or none signed
//! (stricter than S3: every request of ours signs it) 403 `AccessDenied`;
//! another bucket 404 `NoSuchBucket`.
//!
//! Objects: a PUT needs its `Content-Length` (411 `MissingContentLength`;
//! chunked is 501 `NotImplemented`), an `x-amz-checksum-sha256` must be its
//! body's (400 `BadDigest`), `If-None-Match: *` over a current version is
//! 412 `PreconditionFailed`; else a new version `fv<n>` (200,
//! `x-amz-version-id`, an `ETag` of the sha256's first 32 hex digits, the
//! checksum echoed). A GET reads a `versionId` (404 `NoSuchVersion`) or the
//! current version (404 `NoSuchKey`, also behind a delete marker);
//! `x-amz-checksum-mode: ENABLED` echoes the checksum. A DELETE adds a
//! delete marker (204, `x-amz-delete-marker: true`). Multipart uploads
//! (`?uploads`, `?partNumber=&uploadId=`, ListParts, Complete with its parts
//! in order and `If-None-Match` honoured, abort) and ListObjectsV2
//! (`?list-type=2&prefix=`, `max-keys` 1000 by default, a
//! `continuation-token`) answer S3's XML. A script ([`FakeS3::script`])
//! makes the next requests answer a status, cut their answer or wait; a
//! part's script ([`FakeS3::script_part`]) does it to the next uploads of
//! one part number only, whatever else is in flight, and (S10 F5) a
//! PutObject's ([`FakeS3::script_put`]) and a CompleteMultipartUpload's
//! ([`FakeS3::script_complete`]) to the next of those only. S10 (F5) adds
//! what a slow or lossy network does: a body that stops being read after
//! some bytes ([`S3Action::Stall`]), a body read whole and never answered
//! ([`S3Action::Silent`]), a request done whose answer is lost
//! ([`S3Action::Drop`]), and a body read at a set pace
//! ([`S3Action::Throttle`]: an uplink the parts in flight share); a scripted
//! status may be a 409 (`OperationAborted`, `ConditionalRequestConflict`)
//! or a 400 (`RequestTimeout`).
//! S11 (L5, the compressed stage): a PutObject's `content-encoding` header
//! is stored with its version, a CreateMultipartUpload's with its upload and
//! given to the version its Complete makes, and a GET of that version
//! answers `Content-Encoding: <stored>` (its bytes as stored, never decoded);
//! [`S3Action::NoContentEncoding`] makes the next GET answer without it.
//! S11 (C4): every PUT (a PutObject or an UploadPart) is counted in flight
//! from its head until its answer goes ([`FakeS3::max_in_flight`],
//! [`FakeS3::flights`]).
//! S12 (P, plans/s12-contracts.md §P12): DeleteObjects, a POST of the bucket
//! itself with `delete` (a POST of a key with it stays 405), authenticated as
//! every request (an unsigned `x-amz-*` header is 403 `AccessDenied`), then
//! taken as S3 takes it: without `x-amz-checksum-sha256` (a `content-md5` is
//! never read), or with an `x-amz-sdk-checksum-algorithm` other than
//! `SHA256`, 400 `InvalidRequest`; a checksum other than its body's 400
//! `BadDigest`; a body that is no `Delete` of 1 to 1000 `<Object>`s, each
//! with one non-empty `<Key>` and no `<VersionId>` (a `<Quiet>` of `true` or
//! `false` when present), 400 `MalformedXML`, nothing deleted. Else each key
//! in order gets a delete marker (a verbose answer names it `<Deleted>`,
//! with its marker's version) or, scripted ([`FakeS3::script_key_errors`]),
//! its own `<Error>` and stays as it is, in a 200 `DeleteResult`. Its own
//! script ([`FakeS3::script_delete`]) is taken before the queue's, and every
//! action applies to it (a scripted `Status` of 200 is an error document,
//! `Drop` deletes and loses the answer); [`FakeS3::plant_after_delete`]
//! writes an object once the handler answered 200 (one that lands after a
//! purge's listing). [`S3Request::delete_keys`] records each DeleteObjects'
//! keys, in its body's order. Every DeleteObject (a DELETE of a key, not an
//! abort) is counted in flight from its head until its answer goes, apart
//! from S11's PUTs ([`FakeS3::max_deletes_in_flight`]: the fallback's bound).
//! Every request is recorded ([`S3Request`]): never a signature's or a
//! credential's value.
#![allow(dead_code)]

use ai_env_cli::bridge::s3::{LAB_BUCKET, LAB_KEY_ID, LAB_OWNER, LAB_SECRET};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The region every lab URL is signed for.
const REGION: &str = "eu-central-1";
/// The longest request head the fake reads.
const HEAD_MAX: usize = 64 * 1024;
/// One connection's whole budget.
const CONNECTION_LIMIT: Duration = Duration::from_secs(600);

/// One object version or delete marker, as [`FakeS3::objects`] lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Object {
    pub key: String,
    pub version_id: String,
    pub len: u64,
    /// Lowercase hex (empty for a delete marker).
    pub sha256: String,
    pub delete_marker: bool,
    /// The key's newest version.
    pub current: bool,
    /// S11: the `content-encoding` it was stored with (a PutObject's, or its
    /// CreateMultipartUpload's), which a GET answers.
    pub content_encoding: Option<String>,
}

/// One request as it came: never the X-Amz-Signature or X-Amz-Credential values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Request {
    pub method: String,
    /// The object's key (empty: the bucket itself).
    pub key: String,
    /// The query's parameter names, in order.
    pub query_names: Vec<String>,
    /// An UploadPart's part number.
    pub part: Option<u32>,
    /// `X-Amz-SignedHeaders`, split.
    pub signed_headers: Vec<String>,
    pub content_length: Option<u64>,
    /// `Transfer-Encoding: chunked`.
    pub chunked: bool,
    /// The status answered; 0 when no whole answer went out (a cut,
    /// [`S3Action::CutAfter`], or a body that never came).
    pub status: u16,
    /// S3's `<Code>` of an error.
    pub code: Option<String>,
    /// S12 (P): a DeleteObjects' keys (`POST /<bucket>?delete`), in its body's
    /// order, once its body came whole, whatever the answer (a scripted one
    /// too); empty for any other request.
    pub delete_keys: Vec<String>,
}

/// What the next request does instead of (or before) its own answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3Action {
    /// Its body read, answer `status` with this `<Code>`.
    Status { status: u16, code: &'static str },
    /// A read's answer stops after this many bytes of its body; a write's
    /// connection closes once this many bytes of its body came, unanswered.
    CutAfter { bytes: u64 },
    /// Wait this long, then answer as usual.
    Delay(Duration),
    /// S10 (F5): read this many bytes of the body, then nothing more and no
    /// answer, the connection held open (a stalled uplink: the client's
    /// writes back up once the kernel's buffers are full).
    Stall { after: u64 },
    /// S10 (F5): read the body whole, then no answer, the connection held open.
    Silent,
    /// S10 (F5): do the request (an object stored, an upload completed),
    /// then close the connection with no answer (one lost on the way).
    Drop,
    /// S10 (F5): read the body at this many bytes a second, then answer as
    /// usual (one of the parts that share an uplink).
    Throttle { per_s: u64 },
    /// S11: the next GET (a request of another method leaves it queued)
    /// answers as usual but without its `Content-Encoding` (a proxy that
    /// dropped it).
    NoContentEncoding,
}

#[derive(Debug, Clone)]
struct Version {
    id: String,
    bytes: Vec<u8>,
    sha256: String,
    delete_marker: bool,
    /// S11: the `content-encoding` it was stored with.
    content_encoding: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Upload {
    key: String,
    /// Part number → its bytes and its quoted ETag.
    parts: BTreeMap<u32, (Vec<u8>, String)>,
    /// S11: the CreateMultipartUpload's `content-encoding`, the completed version's.
    content_encoding: Option<String>,
}

#[derive(Debug, Default)]
struct State {
    /// Key → its versions, oldest first.
    objects: BTreeMap<String, Vec<Version>>,
    versions: u64,
    uploads: BTreeMap<String, Upload>,
    upload_ids: u64,
    requests: Vec<S3Request>,
    script: VecDeque<S3Action>,
    /// Part number → what its next UploadParts do (taken before `script`).
    part_script: BTreeMap<u32, VecDeque<S3Action>>,
    /// What the next PutObjects (not a part) do (taken before `script`).
    put_script: VecDeque<S3Action>,
    /// What the next CompleteMultipartUploads do (taken before `script`).
    complete_script: VecDeque<S3Action>,
    /// S11 (C4): the PUTs in flight now, the most at once so far, and each
    /// one's start (`true`, its head read) and end (`false`), by key, in order.
    in_flight: usize,
    max_in_flight: usize,
    flights: Vec<(bool, String)>,
    /// S12 (P): what the next DeleteObjects do (taken before `script`).
    delete_script: VecDeque<S3Action>,
    /// S12 (P): key → the codes its next DeleteObjects answer for it, one each.
    key_errors: BTreeMap<String, VecDeque<&'static str>>,
    /// S12 (P): an object written once the next DeleteObjects answered 200, one each, in order.
    after_delete: VecDeque<(String, Vec<u8>)>,
    /// S12 (P): the DeleteObjects of a key in flight now, and the most at once so far (beside S11's PUTs, never with them).
    deletes_in_flight: usize,
    max_deletes_in_flight: usize,
}

impl State {
    fn current(&self, key: &str) -> Option<&Version> {
        self.objects.get(key).and_then(|v| v.last()).filter(|v| !v.delete_marker)
    }

    fn add(&mut self, key: &str, bytes: Vec<u8>, delete_marker: bool) -> String {
        self.add_encoded(key, bytes, delete_marker, None)
    }

    fn add_encoded(&mut self, key: &str, bytes: Vec<u8>, delete_marker: bool, content_encoding: Option<String>) -> String {
        self.versions += 1;
        let id = format!("fv{}", self.versions);
        let sha256 = if delete_marker { String::new() } else { hex::encode(Sha256::digest(&bytes)) };
        self.objects.entry(key.to_string()).or_default().push(Version { id: id.clone(), bytes, sha256, delete_marker, content_encoding });
        id
    }
}

type Shared = Arc<Mutex<State>>;

/// S11 (C4): one PUT in flight, from its head until its answer goes (dropped).
struct InFlight {
    shared: Shared,
    key: String,
}

impl InFlight {
    fn start(shared: &Shared, key: &str) -> InFlight {
        let mut st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        st.in_flight += 1;
        st.max_in_flight = st.max_in_flight.max(st.in_flight);
        st.flights.push((true, key.to_string()));
        InFlight { shared: shared.clone(), key: key.to_string() }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut st = self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        st.in_flight = st.in_flight.saturating_sub(1);
        st.flights.push((false, std::mem::take(&mut self.key)));
    }
}

/// S12 (P): one DeleteObject in flight, from its head until its answer goes (dropped), as [`InFlight`] counts a PUT.
struct DeleteInFlight(Shared);

impl DeleteInFlight {
    fn start(shared: &Shared) -> DeleteInFlight {
        let mut st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        st.deletes_in_flight += 1;
        st.max_deletes_in_flight = st.max_deletes_in_flight.max(st.deletes_in_flight);
        DeleteInFlight(shared.clone())
    }
}

impl Drop for DeleteInFlight {
    fn drop(&mut self) {
        let mut st = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        st.deletes_in_flight = st.deletes_in_flight.saturating_sub(1);
    }
}

/// The fake S3 (the module doc). Dropped, it stops its thread.
pub struct FakeS3 {
    addr: SocketAddr,
    shared: Shared,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for FakeS3 {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl FakeS3 {
    /// Listen on 127.0.0.1 (a free port).
    #[must_use]
    pub fn start() -> FakeS3 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the fake S3");
        listener.set_nonblocking(true).expect("a nonblocking listener");
        let addr = listener.local_addr().expect("the fake S3's address");
        let shared: Shared = Arc::new(Mutex::new(State::default()));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let s = shared.clone();
        let thread = std::thread::Builder::new()
            .name("fake-s3".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("the fake S3's runtime");
                rt.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).expect("a tokio listener");
                    let accept = async {
                        while let Ok((client, _)) = listener.accept().await {
                            let _ = client.set_nodelay(true);
                            let s = s.clone();
                            tokio::spawn(async move {
                                let _ = tokio::time::timeout(CONNECTION_LIMIT, serve(client, s)).await;
                            });
                        }
                    };
                    tokio::select! {
                        () = accept => {}
                        _ = stopped => {}
                    }
                });
                rt.shutdown_background();
            })
            .expect("the fake S3's thread");
        FakeS3 { addr, shared, stop: Some(stop), thread: Some(thread) }
    }

    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `s3::LAB_BUCKET`.
    #[must_use]
    pub fn bucket(&self) -> &'static str {
        LAB_BUCKET
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every version and delete marker, by key, oldest first.
    #[must_use]
    pub fn objects(&self) -> Vec<S3Object> {
        let st = self.state();
        let mut out = Vec::new();
        for (key, versions) in &st.objects {
            for (i, v) in versions.iter().enumerate() {
                out.push(S3Object {
                    key: key.clone(),
                    version_id: v.id.clone(),
                    len: v.bytes.len() as u64,
                    sha256: v.sha256.clone(),
                    delete_marker: v.delete_marker,
                    current: i + 1 == versions.len(),
                    content_encoding: v.content_encoding.clone(),
                });
            }
        }
        out
    }

    /// The current version's bytes (none behind a delete marker).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.state().current(key).map(|v| v.bytes.clone())
    }

    /// Plant an object: its version id.
    pub fn put(&self, key: &str, bytes: &[u8]) -> String {
        self.state().add(key, bytes.to_vec(), false)
    }

    /// S11: plant an object stored with `content_encoding` (its bytes as
    /// given, never encoded here): its version id.
    pub fn put_encoded(&self, key: &str, bytes: &[u8], content_encoding: &str) -> String {
        self.state().add_encoded(key, bytes.to_vec(), false, Some(content_encoding.to_string()))
    }

    /// Every request so far, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<S3Request> {
        self.state().requests.clone()
    }

    /// S11 (C4): the most PUTs (PutObjects and UploadParts) in flight at once so far.
    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.state().max_in_flight
    }

    /// S11 (C4): every PUT's start (`true`, once its head came) and end
    /// (`false`, just before its answer goes, or once its connection ended
    /// unanswered), by key, in order.
    #[must_use]
    pub fn flights(&self) -> Vec<(bool, String)> {
        self.state().flights.clone()
    }

    /// S12 (P): the most DeleteObjects of a key in flight at once so far, each from its head until its answer goes
    /// (or its connection ended unanswered): the purge's fallback holds them to `client::DELETE_PARALLEL`.
    #[must_use]
    pub fn max_deletes_in_flight(&self) -> usize {
        self.state().max_deletes_in_flight
    }

    /// Queue `actions` for the next requests, in order.
    pub fn script(&self, actions: Vec<S3Action>) {
        self.state().script.extend(actions);
    }

    /// Queue `actions` for the next UploadParts of part `number` (of any
    /// upload), in order: one each, before [`FakeS3::script`]'s queue, which
    /// such a request leaves alone; once they are taken, that part's
    /// requests take the queue's again.
    pub fn script_part(&self, number: u32, actions: Vec<S3Action>) {
        self.state().part_script.entry(number).or_default().extend(actions);
    }

    /// Queue `actions` for the next PutObjects (a part's upload is no
    /// PutObject), as [`FakeS3::script_part`] does for a part.
    pub fn script_put(&self, actions: Vec<S3Action>) {
        self.state().put_script.extend(actions);
    }

    /// Queue `actions` for the next CompleteMultipartUploads, as
    /// [`FakeS3::script_part`] does for a part.
    pub fn script_complete(&self, actions: Vec<S3Action>) {
        self.state().complete_script.extend(actions);
    }

    /// S12 (P): queue `actions` for the next DeleteObjects, as [`FakeS3::script_put`] does for a PutObject.
    pub fn script_delete(&self, actions: Vec<S3Action>) {
        self.state().delete_script.extend(actions);
    }

    /// S12 (P): the next DeleteObjects that name `key` answer, one each, an `<Error>` of the next of `codes` for it, and leave it as it is.
    pub fn script_key_errors(&self, key: &str, codes: &[&'static str]) {
        self.state().key_errors.entry(key.to_string()).or_default().extend(codes.iter().copied());
    }

    /// S12 (P): once the handler answered the next DeleteObjects 200 (its markers added; a scripted answer is not the
    /// handler's), write `key` with `bytes` (a new current version): an object that lands after a purge's listing.
    pub fn plant_after_delete(&self, key: &str, bytes: &[u8]) {
        self.state().after_delete.push_back((key.to_string(), bytes.to_vec()));
    }

    /// A URL of this fake signed now with `LAB_KEY_ID` and `LAB_SECRET`, for
    /// tests that drive the shim or curl without the Mac's presigner: `method`
    /// on `key` (empty: the bucket itself) with `query` (in order) signed in,
    /// `headers` (lowercase names) and `x-amz-expected-bucket-owner:
    /// LAB_OWNER`, as every request of ours signs, expiring `expires` later.
    #[must_use]
    pub fn presign(&self, method: &str, key: &str, query: &[(&str, &str)], headers: &[(&str, &str)], expires: Duration) -> String {
        let path = if key.is_empty() { format!("/{LAB_BUCKET}") } else { format!("/{LAB_BUCKET}/{}", key.split('/').map(encode).collect::<Vec<_>>().join("/")) };
        let mut url = format!("http://{}{path}", self.addr);
        let pairs: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", encode(k), encode(v))).collect();
        if !pairs.is_empty() {
            url.push('?');
            url.push_str(&pairs.join("&"));
        }
        let mut signed: Vec<(&str, &str)> = headers.to_vec();
        signed.push(("x-amz-expected-bucket-owner", LAB_OWNER));
        let params = sign(method, &url, &signed, SystemTime::now(), expires).unwrap_or_else(|e| panic!("sign {method} {url}: {e}"));
        let extra: Vec<String> = params.iter().map(|(k, v)| format!("{}={}", encode(k), encode(v))).collect();
        format!("{url}{}{}", if pairs.is_empty() { '?' } else { '&' }, extra.join("&"))
    }
}

/// `text` percent-encoded but S3's unreserved characters (`A-Za-z0-9-_.~`).
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `text` with each `%XX` decoded (a malformed escape kept as it is).
fn decode(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], text.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The query-string SigV4 parameters `aws-sigv4` makes for `method` on
/// `url` with `headers` signed (besides `host`), at `time`, for `expires`:
/// the lab's key, `eu-central-1`, `s3`, S3's settings, an unsigned payload.
fn sign(method: &str, url: &str, headers: &[(&str, &str)], time: SystemTime, expires: Duration) -> Result<Vec<(String, String)>, String> {
    use aws_sigv4::http_request::{PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation, SigningSettings, UriPathNormalizationMode};
    let credentials = aws_sdk_lambdamicrovms::config::Credentials::new(LAB_KEY_ID, LAB_SECRET, None, None, "fake-s3");
    let identity = credentials.into();
    let mut settings = SigningSettings::default();
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in = Some(expires);
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    let params = aws_sigv4::sign::v4::SigningParams::builder().identity(&identity).region(REGION).name("s3").time(time).settings(settings).build().map_err(|e| e.to_string())?.into();
    let signable = SignableRequest::new(method, url, headers.iter().copied(), SignableBody::UnsignedPayload).map_err(|e| e.to_string())?;
    let (instructions, _) = aws_sigv4::http_request::sign(signable, &params).map_err(|e| e.to_string())?.into_parts();
    Ok(instructions.params().iter().map(|(k, v)| ((*k).to_string(), v.to_string())).collect())
}

/// `YYYYMMDDTHHMMSSZ` as a time.
fn amz_date(text: &str) -> Option<SystemTime> {
    if text.len() != 16 || !text.is_ascii() {
        return None;
    }
    let rfc = format!("{}-{}-{}T{}:{}:{}Z", &text[0..4], &text[4..6], &text[6..8], &text[9..11], &text[11..13], &text[13..15]);
    let secs = ai_env_cli::wire::time::parse_rfc3339_utc(&rfc)?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

/// One parsed request.
struct Req {
    method: String,
    /// The path as it came.
    raw_path: String,
    /// The query as it came (without its `?`).
    raw_query: String,
    /// Lowercased names, in order.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The query's parameters, decoded, in order.
    fn params(&self) -> Vec<(String, String)> {
        if self.raw_query.is_empty() {
            return Vec::new();
        }
        self.raw_query.split('&').map(|pair| pair.split_once('=').map_or((decode(pair), String::new()), |(k, v)| (decode(k), decode(v)))).collect()
    }

    fn param(&self, name: &str) -> Option<String> {
        self.params().into_iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }
}

/// An answer: its status, headers and body.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    code: Option<String>,
}

impl Answer {
    fn ok(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Answer {
        Answer { status, headers, body, code: None }
    }

    fn error(status: u16, code: &str) -> Answer {
        let body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code><Message>{code} (the tests' fake S3)</Message></Error>").into_bytes();
        Answer { status, headers: vec![("content-type".into(), "application/xml".into())], body, code: Some(code.to_string()) }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// The head of an answer of `len` body bytes.
fn head_of(a: &Answer, len: usize) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {} {}\r\nContent-Length: {len}\r\nConnection: close\r\n", a.status, reason(a.status));
    for (k, v) in &a.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    head.into_bytes()
}

/// Read the request head (at most [`HEAD_MAX`]); `None` for a connection
/// that closed or sent no head.
async fn read_head(stream: &mut TcpStream) -> Option<(Req, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        if buf.len() > HEAD_MAX {
            return None;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let rest = buf[end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let (raw_path, raw_query) = target.split_once('?').map_or((target.clone(), String::new()), |(p, q)| (p.to_string(), q.to_string()));
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    Some((Req { method, raw_path, raw_query, headers, body: Vec::new() }, rest))
}

/// Read the body after `first` until `len` bytes (a scripted cut passes its
/// own, smaller `len`); `false` when the connection ended first.
async fn read_body(stream: &mut TcpStream, req: &mut Req, first: Vec<u8>, len: u64) -> bool {
    read_body_at(stream, req, first, len, None).await
}

/// [`read_body`], each read followed by the wait that keeps it to `per_s`
/// bytes a second when one is given (S10 F5: [`S3Action::Throttle`]).
async fn read_body_at(stream: &mut TcpStream, req: &mut Req, first: Vec<u8>, len: u64, per_s: Option<u64>) -> bool {
    req.body = first;
    let mut chunk = vec![0u8; 64 * 1024];
    while (req.body.len() as u64) < len {
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => n,
        };
        req.body.extend_from_slice(&chunk[..n]);
        if let Some(rate) = per_s.filter(|r| *r > 0) {
            tokio::time::sleep(Duration::from_micros(n as u64 * 1_000_000 / rate)).await;
        }
    }
    req.body.truncate(usize::try_from(len).unwrap_or(usize::MAX));
    true
}

async fn serve(mut stream: TcpStream, shared: Shared) {
    let Some((mut req, first)) = read_head(&mut stream).await else { return };
    let part = if req.method == "PUT" { req.param("partNumber").and_then(|n| n.parse::<u32>().ok()) } else { None };
    let (is_put, is_complete, is_delete) = {
        let object = req.raw_path.strip_prefix('/').is_some_and(|p| p.contains('/'));
        // S12 (P): a DeleteObjects is a POST of the bucket itself with `delete`.
        (req.method == "PUT" && object && req.param("uploadId").is_none(), req.method == "POST" && req.param("uploadId").is_some(), req.method == "POST" && !object && req.param("delete").is_some())
    };
    let action = {
        let mut st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let own = match part {
            Some(n) => st.part_script.get_mut(&n).and_then(VecDeque::pop_front),
            None if is_put => st.put_script.pop_front(),
            None if is_complete => st.complete_script.pop_front(),
            None if is_delete => st.delete_script.pop_front(),
            None => None,
        };
        // S11: NoContentEncoding waits in the queue for the next GET.
        own.or_else(|| if req.method != "GET" && st.script.front() == Some(&S3Action::NoContentEncoding) { None } else { st.script.pop_front() })
    };
    let params = req.params();
    let in_bucket = req.raw_path.strip_prefix('/').unwrap_or_default();
    let (bucket, key) = in_bucket.split_once('/').map_or((in_bucket.to_string(), String::new()), |(b, k)| (decode(b), decode(k)));
    // S11 (C4): a PUT is in flight from here (its scripted delay included) until its answer goes (or its
    // connection ends unanswered): ended before the answer is written, so the client never sees one more in flight.
    let flight = (req.method == "PUT" && !key.is_empty()).then(|| InFlight::start(&shared, &key));
    // S12 (P): a DeleteObject (not an abort, which names its upload) the same way, counted apart.
    let deleting = (req.method == "DELETE" && !key.is_empty() && req.param("uploadId").is_none()).then(|| DeleteInFlight::start(&shared));
    if let Some(S3Action::Delay(d)) = &action {
        tokio::time::sleep(*d).await;
    }
    let chunked = req.header("transfer-encoding").is_some_and(|t| t.to_ascii_lowercase().contains("chunked"));
    let content_length = req.header("content-length").and_then(|v| v.parse::<u64>().ok());
    let mut record = S3Request {
        method: req.method.clone(),
        key: key.clone(),
        query_names: params.iter().map(|(k, _)| k.clone()).collect(),
        part,
        signed_headers: params.iter().find(|(k, _)| k == "X-Amz-SignedHeaders").map(|(_, v)| v.split(';').map(str::to_string).collect()).unwrap_or_default(),
        content_length,
        chunked,
        status: 0,
        code: None,
        delete_keys: Vec::new(),
    };
    let writes = matches!(req.method.as_str(), "PUT" | "POST");
    let answer = if writes && chunked {
        Some(Answer::error(501, "NotImplemented"))
    } else if req.method == "PUT" && content_length.is_none() {
        Some(Answer::error(411, "MissingContentLength"))
    } else {
        None
    };
    if answer.is_none() {
        let len = content_length.unwrap_or(0);
        if let Some(S3Action::CutAfter { bytes }) = &action {
            if writes {
                let _ = read_body(&mut stream, &mut req, first, len.min(*bytes)).await;
                shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).requests.push(record);
                return;
            }
        }
        if let Some(S3Action::Stall { after }) = &action {
            // Some of the body, then no read and no answer: the connection's budget (or the fake's drop) ends it.
            let _ = read_body(&mut stream, &mut req, first, len.min(*after)).await;
            shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).requests.push(record);
            tokio::time::sleep(CONNECTION_LIMIT).await;
            return;
        }
        let per_s = match &action {
            Some(S3Action::Throttle { per_s }) => Some(*per_s),
            _ => None,
        };
        if !read_body_at(&mut stream, &mut req, first, len, per_s).await {
            shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).requests.push(record);
            return;
        }
        // S12 (P): the body came whole: a DeleteObjects' keys, whatever its answer will be.
        if is_delete {
            record.delete_keys = named_keys(&req.body);
        }
        if action == Some(S3Action::Silent) {
            shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).requests.push(record);
            tokio::time::sleep(CONNECTION_LIMIT).await;
            return;
        }
    }
    let mut answer = match (answer, &action) {
        (Some(a), _) => a,
        (None, Some(S3Action::Status { status, code })) => Answer::error(*status, code),
        (None, _) => respond(&req, &bucket, &key, &params, &shared),
    };
    if action == Some(S3Action::NoContentEncoding) {
        answer.headers.retain(|(k, _)| k != "content-encoding");
    }
    if action == Some(S3Action::Drop) {
        // Done (its effect stands), the answer lost: the connection closes with none.
        record.code = answer.code.clone();
        shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).requests.push(record);
        let _ = stream.shutdown().await;
        return;
    }
    let cut = match &action {
        Some(S3Action::CutAfter { bytes }) if !writes => Some(usize::try_from(*bytes).unwrap_or(usize::MAX).min(answer.body.len())),
        _ => None,
    };
    record.status = if cut.is_some() { 0 } else { answer.status };
    record.code = answer.code.clone();
    shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).requests.push(record);
    drop(flight);
    drop(deleting);
    let mut out = head_of(&answer, answer.body.len());
    out.extend_from_slice(&answer.body[..cut.unwrap_or(answer.body.len())]);
    let _ = stream.write_all(&out).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

/// The answer to an authenticated request of the lab bucket.
fn respond(req: &Req, bucket: &str, key: &str, params: &[(String, String)], shared: &Shared) -> Answer {
    if bucket != LAB_BUCKET {
        return Answer::error(404, "NoSuchBucket");
    }
    if let Err(code) = authenticate(req, params) {
        return Answer::error(403, code);
    }
    let mut st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let has = |name: &str| params.iter().any(|(k, _)| k == name);
    match (req.method.as_str(), key.is_empty()) {
        ("GET", true) if req.param("list-type").as_deref() == Some("2") => list_objects(&st, req),
        ("PUT", false) if has("uploadId") => upload_part(&mut st, req),
        ("PUT", false) => put_object(&mut st, req, key),
        ("GET", false) if has("uploadId") => list_parts(&st, req, key),
        ("GET", false) => get_object(&st, req, key),
        ("POST", false) if has("uploads") => {
            st.upload_ids += 1;
            let id = format!("fu{}", st.upload_ids);
            let content_encoding = req.header("content-encoding").map(str::to_string);
            st.uploads.insert(id.clone(), Upload { key: key.to_string(), parts: BTreeMap::new(), content_encoding });
            Answer::ok(200, xml(), format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<InitiateMultipartUploadResult><Bucket>{LAB_BUCKET}</Bucket><Key>{}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>", escape(key)).into_bytes())
        }
        ("POST", false) if has("uploadId") => complete_upload(&mut st, req, key),
        ("DELETE", false) if has("uploadId") => match st.uploads.remove(&req.param("uploadId").unwrap_or_default()) {
            Some(_) => Answer::ok(204, Vec::new(), Vec::new()),
            None => Answer::error(404, "NoSuchUpload"),
        },
        ("DELETE", false) => {
            let id = st.add(key, Vec::new(), true);
            Answer::ok(204, vec![("x-amz-delete-marker".into(), "true".into()), ("x-amz-version-id".into(), id)], Vec::new())
        }
        ("POST", true) if has("delete") => delete_objects(&mut st, req),
        _ => Answer::error(405, "MethodNotAllowed"),
    }
}

/// Query-string SigV4 (the module doc): the request signed again must give its own signature.
fn authenticate(req: &Req, params: &[(String, String)]) -> Result<(), &'static str> {
    let get = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let (Some(_), Some(_), Some(date), Some(expires), Some(signed), Some(signature)) =
        (get("X-Amz-Algorithm"), get("X-Amz-Credential"), get("X-Amz-Date"), get("X-Amz-Expires"), get("X-Amz-SignedHeaders"), get("X-Amz-Signature"))
    else {
        return Err("AccessDenied");
    };
    let signed: Vec<&str> = signed.split(';').collect();
    if !signed.contains(&"x-amz-expected-bucket-owner") || !signed.contains(&"host") {
        return Err("AccessDenied");
    }
    let unsigned_amz = req.headers.iter().any(|(k, _)| k.starts_with("x-amz-") && !signed.contains(&k.as_str()));
    if unsigned_amz || req.header("x-amz-expected-bucket-owner") != Some(LAB_OWNER) {
        return Err("AccessDenied");
    }
    let (Some(time), Ok(expires)) = (amz_date(&date), expires.parse::<u64>()) else { return Err("AccessDenied") };
    if SystemTime::now() > time + Duration::from_secs(expires) {
        return Err("AccessDenied");
    }
    let host = req.header("host").unwrap_or_default();
    let others: Vec<&str> = req.raw_query.split('&').filter(|pair| !pair.is_empty() && !pair.starts_with("X-Amz-")).collect();
    let url = if others.is_empty() { format!("http://{host}{}", req.raw_path) } else { format!("http://{host}{}?{}", req.raw_path, others.join("&")) };
    let headers: Vec<(&str, &str)> = signed.iter().filter(|h| **h != "host").filter_map(|h| req.header(h).map(|v| (*h, v))).collect();
    let again = sign(&req.method, &url, &headers, time, Duration::from_secs(expires)).map_err(|_| "SignatureDoesNotMatch")?;
    let mine = |name: &str| again.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    if mine("X-Amz-Signature").as_deref() != Some(signature.as_str()) || mine("X-Amz-SignedHeaders").as_deref() != Some(signed.join(";").as_str()) {
        return Err("SignatureDoesNotMatch");
    }
    Ok(())
}

fn xml() -> Vec<(String, String)> {
    vec![("content-type".into(), "application/xml".into())]
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The ETag of `sha256` (hex): its first 32 digits, quoted.
fn etag(sha256: &str) -> String {
    format!("\"{}\"", &sha256[..32])
}

fn b64_of_hex(sha256: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(hex::decode(sha256).unwrap_or_default())
}

/// A body's sha256, and whether its `x-amz-checksum-sha256` (when given) is it.
fn checked(req: &Req) -> (String, bool) {
    let sha = hex::encode(Sha256::digest(&req.body));
    let ok = req.header("x-amz-checksum-sha256").is_none_or(|c| c == b64_of_hex(&sha));
    (sha, ok)
}

fn put_object(st: &mut State, req: &Req, key: &str) -> Answer {
    let (sha, ok) = checked(req);
    if !ok {
        return Answer::error(400, "BadDigest");
    }
    if req.header("if-none-match") == Some("*") && st.current(key).is_some() {
        return Answer::error(412, "PreconditionFailed");
    }
    let id = st.add_encoded(key, req.body.clone(), false, req.header("content-encoding").map(str::to_string));
    Answer::ok(200, vec![("x-amz-version-id".into(), id), ("etag".into(), etag(&sha)), ("x-amz-checksum-sha256".into(), b64_of_hex(&sha))], Vec::new())
}

fn get_object(st: &State, req: &Req, key: &str) -> Answer {
    let version = match req.param("versionId") {
        Some(id) => match st.objects.get(key).and_then(|vs| vs.iter().find(|v| v.id == id)) {
            Some(v) if v.delete_marker => return Answer::error(405, "MethodNotAllowed"),
            Some(v) => v,
            None => return Answer::error(404, "NoSuchVersion"),
        },
        None => match st.current(key) {
            Some(v) => v,
            None => return Answer::error(404, "NoSuchKey"),
        },
    };
    let mut headers = vec![("x-amz-version-id".into(), version.id.clone()), ("etag".into(), etag(&version.sha256))];
    if req.header("x-amz-checksum-mode").is_some_and(|m| m.eq_ignore_ascii_case("ENABLED")) {
        headers.push(("x-amz-checksum-sha256".into(), b64_of_hex(&version.sha256)));
    }
    if let Some(encoding) = &version.content_encoding {
        headers.push(("content-encoding".into(), encoding.clone()));
    }
    Answer::ok(200, headers, version.bytes.clone())
}

fn upload_part(st: &mut State, req: &Req) -> Answer {
    let (Some(id), Some(number)) = (req.param("uploadId"), req.param("partNumber").and_then(|n| n.parse::<u32>().ok())) else {
        return Answer::error(400, "InvalidRequest");
    };
    let (sha, ok) = checked(req);
    if !ok {
        return Answer::error(400, "BadDigest");
    }
    let Some(upload) = st.uploads.get_mut(&id) else { return Answer::error(404, "NoSuchUpload") };
    let tag = etag(&sha);
    upload.parts.insert(number, (req.body.clone(), tag.clone()));
    Answer::ok(200, vec![("etag".into(), tag), ("x-amz-checksum-sha256".into(), b64_of_hex(&sha))], Vec::new())
}

fn list_parts(st: &State, req: &Req, key: &str) -> Answer {
    let id = req.param("uploadId").unwrap_or_default();
    let Some(upload) = st.uploads.get(&id).filter(|u| u.key == key) else { return Answer::error(404, "NoSuchUpload") };
    let mut body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListPartsResult><Bucket>{LAB_BUCKET}</Bucket><Key>{}</Key><UploadId>{id}</UploadId>", escape(key));
    for (n, (bytes, tag)) in &upload.parts {
        let sha = hex::encode(Sha256::digest(bytes));
        body.push_str(&format!("<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag><Size>{}</Size><ChecksumSHA256>{}</ChecksumSHA256></Part>", escape(tag), bytes.len(), b64_of_hex(&sha)));
    }
    body.push_str("<IsTruncated>false</IsTruncated></ListPartsResult>");
    Answer::ok(200, xml(), body.into_bytes())
}

/// The `(PartNumber, ETag)` pairs of a CompleteMultipartUpload body, in order.
fn completed_parts(body: &str) -> Vec<(u32, String)> {
    let between = |text: &str, open: &str, close: &str| text.split_once(open).and_then(|(_, rest)| rest.split_once(close)).map(|(v, _)| v.trim().to_string());
    body.split("<Part>").skip(1).filter_map(|part| Some((between(part, "<PartNumber>", "</PartNumber>")?.parse().ok()?, between(part, "<ETag>", "</ETag>")?.replace("&quot;", "\"")))).collect()
}

fn complete_upload(st: &mut State, req: &Req, key: &str) -> Answer {
    let id = req.param("uploadId").unwrap_or_default();
    let Some(upload) = st.uploads.get(&id).filter(|u| u.key == key).cloned() else { return Answer::error(404, "NoSuchUpload") };
    let wanted = completed_parts(&String::from_utf8_lossy(&req.body));
    if wanted.is_empty() || !wanted.windows(2).all(|w| w[0].0 < w[1].0) {
        return Answer::error(400, "InvalidPartOrder");
    }
    let mut bytes = Vec::new();
    for (n, tag) in &wanted {
        match upload.parts.get(n) {
            Some((b, t)) if t.trim_matches('"') == tag.trim_matches('"') => bytes.extend_from_slice(b),
            _ => return Answer::error(400, "InvalidPart"),
        }
    }
    if req.header("if-none-match") == Some("*") && st.current(key).is_some() {
        return Answer::error(412, "PreconditionFailed");
    }
    st.uploads.remove(&id);
    let sha = hex::encode(Sha256::digest(&bytes));
    let version = st.add_encoded(key, bytes, false, upload.content_encoding.clone());
    let tag = format!("\"{}-{}\"", &sha[..32], wanted.len());
    let body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUploadResult><Bucket>{LAB_BUCKET}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>", escape(key), escape(&tag));
    Answer::ok(200, vec![("content-type".into(), "application/xml".into()), ("x-amz-version-id".into(), version)], body.into_bytes())
}

fn list_objects(st: &State, req: &Req) -> Answer {
    let prefix = req.param("prefix").unwrap_or_default();
    let max = req.param("max-keys").and_then(|m| m.parse::<usize>().ok()).unwrap_or(1000);
    let after = req.param("continuation-token");
    let keys: Vec<(&String, &Version)> = st.objects.keys().filter_map(|k| st.current(k).map(|v| (k, v))).filter(|(k, _)| k.starts_with(&prefix) && after.as_ref().is_none_or(|a| k.as_str() > a.as_str())).collect();
    let page: Vec<&(&String, &Version)> = keys.iter().take(max).collect();
    let truncated = keys.len() > page.len();
    let mut body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult><Name>{LAB_BUCKET}</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><MaxKeys>{max}</MaxKeys><IsTruncated>{truncated}</IsTruncated>", escape(&prefix), page.len());
    if let (true, Some((last, _))) = (truncated, page.last()) {
        body.push_str(&format!("<NextContinuationToken>{}</NextContinuationToken>", escape(last)));
    }
    for (k, v) in &page {
        body.push_str(&format!("<Contents><Key>{}</Key><Size>{}</Size><ETag>{}</ETag><ChecksumAlgorithm>SHA256</ChecksumAlgorithm></Contents>", escape(k), v.bytes.len(), escape(&etag(&v.sha256))));
    }
    body.push_str("</ListBucketResult>");
    Answer::ok(200, xml(), body.into_bytes())
}

/// S12 (P): S3's most keys one DeleteObjects names.
const DELETE_MAX: usize = 1000;
/// XML's whitespace.
const XML_SPACE: [char; 4] = [' ', '\t', '\r', '\n'];

/// `text` with XML's five named entities decoded (`&amp;` last).
fn unescape(text: &str) -> String {
    text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// The inner texts of `xml`'s `<name>…</name>` elements, in order (no attributes, not nested in themselves), and
/// whether every `<name>` that opens closes: this fake's own reader, never the client's.
fn elements<'x>(xml: &'x str, name: &str) -> (Vec<&'x str>, bool) {
    let (open, close) = (format!("<{name}>"), format!("</{name}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find(&open) {
        let inner = &rest[at + open.len()..];
        let Some(end) = inner.find(&close) else { return (out, false) };
        out.push(&inner[..end]);
        rest = &inner[end + close.len()..];
    }
    (out, true)
}

/// S12 (P): the keys a DeleteObjects body names, each `<Object>`'s first `<Key>` unescaped, in order, whatever else
/// the body holds (what [`S3Request::delete_keys`] records, a malformed body's too).
fn named_keys(body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    elements(&text, "Object").0.into_iter().filter_map(|o| elements(o, "Key").0.first().map(|k| unescape(k))).collect()
}

/// S12 (P): a DeleteObjects body's keys (unescaped, in order) and whether it is quiet, `None` where S3 answers
/// `MalformedXML`: UTF-8 whose root, past whitespace and an optional `<?xml …?>`, is a `Delete` element (its
/// attributes free) closing at the body's end; 1 to 1000 `<Object>`s, each with exactly one non-empty `<Key>` and no
/// `<VersionId>`; a `<Quiet>` of `true` or `false` when there is one (none: verbose).
fn delete_body(body: &[u8]) -> Option<(Vec<String>, bool)> {
    let text = std::str::from_utf8(body).ok()?.trim_matches(XML_SPACE);
    let text = match text.strip_prefix("<?xml") {
        Some(rest) => rest[rest.find("?>")? + 2..].trim_start_matches(XML_SPACE),
        None => text,
    };
    let head = text.strip_prefix("<Delete").filter(|h| h.starts_with('>') || h.starts_with(XML_SPACE))?;
    let inner = head[head.find('>')? + 1..].strip_suffix("</Delete>")?;
    let (objects, closed) = elements(inner, "Object");
    if !closed || objects.is_empty() || objects.len() > DELETE_MAX || inner.matches("<Object>").count() != objects.len() {
        return None;
    }
    let mut keys = Vec::with_capacity(objects.len());
    for object in objects {
        let (key, closed) = elements(object, "Key");
        if !closed || key.len() != 1 || key[0].is_empty() || object.matches("<Key>").count() != 1 || object.contains("<VersionId") {
            return None;
        }
        keys.push(unescape(key[0]));
    }
    let quiet = match elements(inner, "Quiet") {
        (q, true) if q.is_empty() => false,
        (q, true) if q == ["true"] => true,
        (q, true) if q == ["false"] => false,
        _ => return None,
    };
    Some((keys, quiet))
}

/// S12 (P): DeleteObjects of the lab bucket (the module doc), once authenticated: the checksum rules, then the body,
/// then each key a delete marker or its scripted `<Error>`, in a 200 `DeleteResult`; then the next object planted
/// after a DeleteObjects is written.
fn delete_objects(st: &mut State, req: &Req) -> Answer {
    // S3 asks a DeleteObjects for a checksum of its body: this fake takes the SHA-256 one alone (no content-md5).
    if req.header("x-amz-checksum-sha256").is_none() || req.header("x-amz-sdk-checksum-algorithm").is_some_and(|a| a != "SHA256") {
        return Answer::error(400, "InvalidRequest");
    }
    if !checked(req).1 {
        return Answer::error(400, "BadDigest");
    }
    let Some((keys, quiet)) = delete_body(&req.body) else { return Answer::error(400, "MalformedXML") };
    let mut entries = String::new();
    for key in &keys {
        if let Some(code) = st.key_errors.get_mut(key).and_then(VecDeque::pop_front) {
            entries.push_str(&format!("<Error><Key>{}</Key><Code>{code}</Code><Message>{code} (the tests' fake S3)</Message></Error>", escape(key)));
            continue;
        }
        let id = st.add(key, Vec::new(), true);
        if !quiet {
            entries.push_str(&format!("<Deleted><Key>{}</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>{id}</DeleteMarkerVersionId></Deleted>", escape(key)));
        }
    }
    if let Some((key, bytes)) = st.after_delete.pop_front() {
        st.add(&key, bytes, false);
    }
    Answer::ok(200, xml(), format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{entries}</DeleteResult>").into_bytes())
}
