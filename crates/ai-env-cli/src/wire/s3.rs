//! S9's transcript store in S3 (plan §5, M2 to M4; every feature set: the
//! shim deserialises the presigned URLs the Mac sends it): the bucket's name
//! and host, the key scheme ([`S3Key`], whose `render` and `parse` are
//! inverse), the sizes a transfer keeps to, and [`PresignedUrl`], the only
//! form a presigned URL is ever held in: checked ([`check_url`]), registered
//! with the scrubber while held, shown by its host and key only. Frozen in S9
//! phase 0; G4 presigns on the Mac (`bridge::s3`), G5 moves the bytes in the
//! VM (`shim::s3xfer`).
//!
//! Custody (the review lens checks it): [`PresignedUrl::expose`] is called in
//! three places only (the Mac's own S3 request, the shim's curl config on fd
//! 3, the egress check's script); everywhere else a URL is
//! [`PresignedUrl::shown`]: never in an argv, an environment, a file, a log
//! line, an audit row, a census part, a registry row, a manifest, an error
//! or a refusal message.
use crate::wire::redact::{forget_secret, register_secret, Secret};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::time::Duration;

/// The one region (the MicroVM bridge is pinned to it).
pub const REGION: &str = "eu-central-1";
/// `ai-env-transcripts-<acct>`.
pub const BUCKET_PREFIX: &str = "ai-env-transcripts-";

/// The transcripts bucket of `account_id` (12 digits), else `None`.
#[must_use]
pub fn bucket_name(account_id: &str) -> Option<String> {
    is_account_id(account_id).then(|| format!("{BUCKET_PREFIX}{account_id}"))
}

/// Is `name` a transcripts bucket: [`BUCKET_PREFIX`] and 12 digits.
#[must_use]
pub fn is_bucket_name(name: &str) -> bool {
    name.strip_prefix(BUCKET_PREFIX).is_some_and(is_account_id)
}

/// The bucket's virtual-hosted name: `<bucket>.s3.eu-central-1.amazonaws.com`.
#[must_use]
pub fn bucket_host(bucket: &str) -> String {
    format!("{bucket}.s3.{REGION}.amazonaws.com")
}

/// Is `s` an AWS account id: 12 ASCII digits.
#[must_use]
pub fn is_account_id(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())
}

/// squid as curl in the VM names it: `http://`, an RFC 1918 IPv4 address,
/// `:`, a port from 1 to 65535, nothing else (each in its canonical form).
pub fn proxy_check(p: &str) -> Result<(), String> {
    let bad = || Err("is not http://<an RFC 1918 IPv4 address>:<port>".to_string());
    let Some(rest) = p.strip_prefix("http://") else { return bad() };
    let Some((ip, port)) = rest.rsplit_once(':') else { return bad() };
    let (Ok(ip), Ok(port)) = (ip.parse::<std::net::Ipv4Addr>(), port.parse::<u16>()) else { return bad() };
    if !ip.is_private() || port == 0 || format!("http://{ip}:{port}") != p {
        return bad();
    }
    Ok(())
}

// ---- keys ----------------------------------------------------------------------------------

/// Every key of the store is under it (IAM's runtime statements cover `v1/*` only).
pub const KEY_PREFIX: &str = "v1/";
/// The egress check's own objects (expired after a day by the bucket's lifecycle).
pub const EGRESS_CHECK_PREFIX: &str = "v1/_egress-check/";
/// The egress check's key outside [`KEY_PREFIX`] (`s3-own-outside-prefix`):
/// never written, IAM refuses it.
pub const OUTSIDE_PROBE_PREFIX: &str = "x/_egress-check/";

/// One object of the store. [`S3Key::render`] and [`S3Key::parse`] are
/// inverse: a key `parse` refuses names nothing of ours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3Key {
    /// `v1/<sid>/mac/<sha256>`: a chat that began on the Mac, as it went up.
    Mac { session: String, sha256: String },
    /// `v1/<sid>/vm/g<gen>/base`: a generation's full copy of the VM's transcript.
    Base { session: String, gen: u32 },
    /// `v1/<sid>/vm/g<gen>/s/<offset:016x>`: the bytes appended from `offset`.
    Segment { session: String, gen: u32, offset: u64 },
    /// `v1/<sid>/vm/g<gen>/t/<offset:016x>`: what `/suspend` or `/terminate` pushed past the committed length.
    Tail { session: String, gen: u32, offset: u64 },
    /// `v1/<sid>/vm/f/<sha256>`: a file of the session's subtree, by its bytes' sha256.
    File { session: String, sha256: String },
    /// `v1/_egress-check/<nonce>`, `nonce` `[a-z0-9]{8,32}`.
    EgressCheck { nonce: String },
    /// `x/_egress-check/<nonce>`, the same nonce: no session, not the VM's.
    OutsideProbe { nonce: String },
}

/// 64 lowercase hex digits (a sha256).
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `[a-z0-9]{8,32}`.
fn is_nonce(s: &str) -> bool {
    (8..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A generation in its canonical decimal form (`g1`, never `g01`).
fn parse_gen(s: &str) -> Option<u32> {
    let digits = s.strip_prefix('g')?;
    let gen: u32 = digits.parse().ok()?;
    (gen.to_string() == digits).then_some(gen)
}

/// An offset as exactly 16 lowercase hex digits.
fn parse_offset(s: &str) -> Option<u64> {
    (s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then(|| u64::from_str_radix(s, 16).ok()).flatten()
}

impl S3Key {
    /// The key's text.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            S3Key::Mac { session, sha256 } => format!("{KEY_PREFIX}{session}/mac/{sha256}"),
            S3Key::Base { session, gen } => format!("{KEY_PREFIX}{session}/vm/g{gen}/base"),
            S3Key::Segment { session, gen, offset } => format!("{KEY_PREFIX}{session}/vm/g{gen}/s/{offset:016x}"),
            S3Key::Tail { session, gen, offset } => format!("{KEY_PREFIX}{session}/vm/g{gen}/t/{offset:016x}"),
            S3Key::File { session, sha256 } => format!("{KEY_PREFIX}{session}/vm/f/{sha256}"),
            S3Key::EgressCheck { nonce } => format!("{EGRESS_CHECK_PREFIX}{nonce}"),
            S3Key::OutsideProbe { nonce } => format!("{OUTSIDE_PROBE_PREFIX}{nonce}"),
        }
    }

    /// The object `key` names, `None` for any other text: a session id
    /// (`wire::workspace::is_uuid`), sha256s of 64 lowercase hex, a
    /// generation in canonical decimal, an offset of 16 lowercase hex digits.
    #[must_use]
    pub fn parse(key: &str) -> Option<S3Key> {
        if let Some(nonce) = key.strip_prefix(EGRESS_CHECK_PREFIX) {
            return is_nonce(nonce).then(|| S3Key::EgressCheck { nonce: nonce.to_string() });
        }
        if let Some(nonce) = key.strip_prefix(OUTSIDE_PROBE_PREFIX) {
            return is_nonce(nonce).then(|| S3Key::OutsideProbe { nonce: nonce.to_string() });
        }
        let rest = key.strip_prefix(KEY_PREFIX)?;
        let segs: Vec<&str> = rest.split('/').collect();
        let session = segs.first().filter(|s| crate::wire::workspace::is_uuid(s))?.to_string();
        match segs[1..] {
            ["mac", sha] if is_sha256_hex(sha) => Some(S3Key::Mac { session, sha256: sha.to_string() }),
            ["vm", "f", sha] if is_sha256_hex(sha) => Some(S3Key::File { session, sha256: sha.to_string() }),
            ["vm", gen, "base"] => Some(S3Key::Base { session, gen: parse_gen(gen)? }),
            ["vm", gen, "s", offset] => Some(S3Key::Segment { session, gen: parse_gen(gen)?, offset: parse_offset(offset)? }),
            ["vm", gen, "t", offset] => Some(S3Key::Tail { session, gen: parse_gen(gen)?, offset: parse_offset(offset)? }),
            _ => None,
        }
    }

    /// The session it belongs to (none for the egress check's keys).
    #[must_use]
    pub fn session(&self) -> Option<&str> {
        match self {
            S3Key::Mac { session, .. } | S3Key::Base { session, .. } | S3Key::Segment { session, .. } | S3Key::Tail { session, .. } | S3Key::File { session, .. } => Some(session),
            S3Key::EgressCheck { .. } | S3Key::OutsideProbe { .. } => None,
        }
    }

    /// Is it one of the VM's (`v1/<sid>/vm/…`: the bucket policy refuses its writes outside the endpoint)?
    #[must_use]
    pub fn is_vm(&self) -> bool {
        matches!(self, S3Key::Base { .. } | S3Key::Segment { .. } | S3Key::Tail { .. } | S3Key::File { .. })
    }
}

// ---- sizes and times -----------------------------------------------------------------------

/// How long a presigned URL lives (but a tail's and a pull's parts).
pub const PRESIGN_EXPIRY: Duration = Duration::from_secs(300);
/// A tail URL's life: it waits in the shim for `/suspend` or `/terminate`.
pub const TAIL_EXPIRY: Duration = Duration::from_secs(3600);
/// A pull's parts are presigned at once and used one after another: they expire after the pull's budget
/// (`budget::TRANSCRIPT_PULL` plus the parts' sum at 1 MB/s, as the shim counts it), at least `PRESIGN_EXPIRY`, at most this.
pub const PULL_EXPIRY_MAX: Duration = Duration::from_secs(3600);
/// One PUT from the VM (S3's single PUT stops at 5 GB): a larger transcript cannot be pushed (plan risk 8).
pub const PUSH_MAX: u64 = 4 << 30;
/// A Mac-begun chat's multipart upload: its part size, and how many go at once.
pub const MULTIPART_PART: u64 = 64 << 20;
pub const MULTIPART_PARALLEL: usize = 8;
/// A chat begun on the Mac goes up inline at its reopen up to this; and a reopen pulls at most this from S3
/// within Cursor's window (R5-AWS-1). Larger ones need `ai-env session stage UUID --warm`.
pub const INLINE_MAX: u64 = 64 << 20;
/// A new generation (a full copy) once the segments number this many,
pub const COMPACT_SEGMENTS: usize = 64;
/// or their bytes pass max(this, base / 2).
pub const COMPACT_BYTES_MIN: u64 = 64 << 20;
/// The bytes a fingerprint covers: the sha256 of the `FP_SPAN` bytes before an offset.
pub const FP_SPAN: u64 = 64 << 10;
/// The most parts one pull carries.
pub const PULL_PARTS_MAX: usize = 128;
/// The longest presigned URL, in bytes.
pub const PRESIGNED_URL_MAX: usize = 4096;
/// X-Amz-SignedHeaders, as SigV4 lists them (sorted, lowercase): a push's,
pub const SIGNED_HEADERS_PUT: &str = "content-length;host;if-none-match;x-amz-checksum-sha256;x-amz-expected-bucket-owner";
/// a pull part's,
pub const SIGNED_HEADERS_GET: &str = "host;x-amz-expected-bucket-owner";
/// a tail's (no length or checksum: the tail's bytes are unknown when it is signed).
pub const SIGNED_HEADERS_TAIL: &str = "host;if-none-match;x-amz-expected-bucket-owner";

/// The `x-amz-checksum-sha256` value (base64 of the 32 bytes) of a lowercase-hex digest; `None` for any other text.
#[must_use]
pub fn sha256_b64(hex: &str) -> Option<String> {
    use base64::Engine as _;
    if !is_sha256_hex(hex) {
        return None;
    }
    let bytes = hex::decode(hex).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(bytes))
}

// ---- presigned URLs ------------------------------------------------------------------------

/// The query parameters a presigned URL must carry.
const REQUIRED_PARAMS: [&str; 6] = ["X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature"];
/// The other parameters it may carry: S3's own and a temporary credential's token.
const OPTIONAL_PARAMS: [&str; 9] = ["versionId", "uploadId", "partNumber", "uploads", "list-type", "prefix", "continuation-token", "max-keys", "X-Amz-Security-Token"];

/// `value` with each `%XX` decoded (`None` for a malformed escape or a result that is not UTF-8).
fn percent_decode(value: &str) -> Option<String> {
    let b = value.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = value.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The checks of [`check_url`]; the query's parameters once they pass, in order.
fn checked_params(url: &str) -> Result<Vec<(&str, &str)>, String> {
    if url.len() > PRESIGNED_URL_MAX {
        return Err(format!("is {} bytes long (at most {PRESIGNED_URL_MAX})", url.len()));
    }
    if !url.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\') {
        return Err("holds a byte that is not printable ASCII, a space, a quote or a backslash".into());
    }
    let Some(q) = url.find('?') else { return Err("has no query: it is not presigned".into()) };
    let (base, query) = (&url[..q], &url[q + 1..]);
    let (lab, rest) = match (base.strip_prefix("https://"), base.strip_prefix("http://")) {
        (Some(rest), _) => (false, rest),
        (None, Some(rest)) if cfg!(debug_assertions) => (true, rest),
        _ => return Err("is not https://".into()),
    };
    let Some(slash) = rest.find('/') else { return Err("has no path".into()) };
    let (host, path) = (&rest[..slash], &rest[slash..]);
    let key = if lab {
        let port = host.strip_prefix("127.0.0.1:").filter(|p| p.parse::<u16>().is_ok_and(|n| n != 0 && n.to_string() == *p));
        if port.is_none() {
            return Err("is a lab URL whose host is not 127.0.0.1:<port>".into());
        }
        let in_bucket = path.strip_prefix('/').unwrap_or_default();
        let (bucket, key) = in_bucket.split_once('/').unwrap_or((in_bucket, ""));
        if !is_bucket_name(bucket) || (in_bucket.contains('/') && key.is_empty()) {
            return Err("is a lab URL whose path does not start with a transcripts bucket".into());
        }
        key
    } else {
        let bucket = host.strip_suffix(&format!(".s3.{REGION}.amazonaws.com")).unwrap_or_default();
        if !is_bucket_name(bucket) {
            return Err(format!("names a host other than a transcripts bucket's ({BUCKET_PREFIX}<account>.s3.{REGION}.amazonaws.com, no port, no user)"));
        }
        &path[1..]
    };
    if !key.is_empty() && S3Key::parse(key).is_none() {
        return Err("names a key that is none of the store's".into());
    }
    let mut params: Vec<(&str, &str)> = Vec::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if !REQUIRED_PARAMS.contains(&name) && !OPTIONAL_PARAMS.contains(&name) {
            return Err(format!("carries the query parameter {name:?}, which no request of ours signs"));
        }
        if params.iter().any(|(n, _)| *n == name) {
            return Err(format!("carries the query parameter {name} twice"));
        }
        params.push((name, value));
    }
    let get = |name: &str| params.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
    if let Some(missing) = REQUIRED_PARAMS.iter().find(|n| get(n).is_none_or(str::is_empty)) {
        return Err(format!("lacks {missing}: it is not presigned"));
    }
    if get("X-Amz-Algorithm") != Some("AWS4-HMAC-SHA256") {
        return Err("is not signed with AWS4-HMAC-SHA256".into());
    }
    let expires = get("X-Amz-Expires").and_then(|e| e.parse::<u64>().ok().filter(|n| n.to_string() == e));
    if !expires.is_some_and(|e| (1..=TAIL_EXPIRY.as_secs()).contains(&e)) {
        return Err(format!("expires after other than 1 to {} s", TAIL_EXPIRY.as_secs()));
    }
    if !get("X-Amz-Signature").is_some_and(is_sha256_hex) {
        return Err("carries a signature that is not 64 lowercase hex digits".into());
    }
    if get("X-Amz-SignedHeaders").and_then(percent_decode).is_none() {
        return Err("carries signed headers that do not decode".into());
    }
    Ok(params)
}

/// A presigned URL of the store: at most [`PRESIGNED_URL_MAX`] bytes of
/// printable ASCII without a space, `"` or a backslash (it is written into a
/// quoted curl config string); `https://` then exactly a transcripts
/// bucket's host ([`bucket_host`]: no port, no user); a path that is `/`
/// (the bucket itself: the Mac's ListObjectsV2) or `/` and a key
/// [`S3Key::parse`] takes (an `OutsideProbe` key included: only the egress
/// check builds one); a query holding `X-Amz-Algorithm=AWS4-HMAC-SHA256`,
/// `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires` (1 to 3600),
/// `X-Amz-SignedHeaders` and `X-Amz-Signature` (64 lowercase hex), besides
/// them only `versionId`, `uploadId`, `partNumber`, `uploads`, `list-type`,
/// `prefix`, `continuation-token`, `max-keys` and `X-Amz-Security-Token`,
/// each once. In debug builds only, a lab URL also passes:
/// `http://127.0.0.1:<port>/<bucket>[/<key>]?…` (path-style, loopback, the
/// same query rules). The request types' `check`s narrow it for the VM.
pub fn check_url(url: &str) -> Result<(), String> {
    checked_params(url).map(|_| ())
}

/// A presigned URL: the only form one is held in, anywhere. Checked
/// ([`check_url`]) when it is made or read, and registered with the
/// scrubber (the whole URL and its `X-Amz-Signature` value) while it is
/// held: every clone registers again, every drop forgets once. Its `Debug`
/// is `[presigned-url <shown>]`; it serialises as its text, and reading one
/// back runs [`PresignedUrl::new`].
pub struct PresignedUrl(Secret<String>, String);

impl PresignedUrl {
    /// `url` checked ([`check_url`]), then registered with the scrubber: the whole URL and its `X-Amz-Signature` value.
    pub fn new(url: String) -> Result<PresignedUrl, String> {
        let signed = {
            let params = checked_params(&url).map_err(|e| format!("the presigned URL {e}"))?;
            let raw = params.iter().find(|(n, _)| *n == "X-Amz-SignedHeaders").map_or("", |(_, v)| *v);
            percent_decode(raw).unwrap_or_default()
        };
        let held = PresignedUrl(Secret::new(url), signed);
        held.register();
        Ok(held)
    }

    fn register(&self) {
        register_secret(self.0.expose());
        register_secret(self.signature());
    }

    fn param(&self, name: &str) -> &str {
        let url = self.0.expose().as_str();
        let query = url.split_once('?').map_or("", |(_, q)| q);
        query.split('&').find_map(|pair| pair.strip_prefix(name).and_then(|r| r.strip_prefix('='))).unwrap_or_default()
    }

    fn signature(&self) -> &str {
        self.param("X-Amz-Signature")
    }

    /// The only read (grep-able): the Mac's own S3 request, the shim's curl config on fd 3, the egress check's script.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// `https://<host>/<key>` without the query: for errors and logs.
    #[must_use]
    pub fn shown(&self) -> String {
        let url = self.0.expose().as_str();
        url.split_once('?').map_or(url, |(shown, _)| shown).to_string()
    }

    /// The URL's host: the bucket's virtual-hosted name (`127.0.0.1:<port>` for a lab URL).
    #[must_use]
    pub fn host(&self) -> &str {
        let url = self.0.expose().as_str();
        let rest = url.split_once("://").map_or("", |(_, r)| r);
        rest.split('/').next().unwrap_or_default()
    }

    /// The object's key (empty for the bucket itself).
    #[must_use]
    pub fn key(&self) -> &str {
        let url = self.0.expose().as_str();
        let path = url.split_once("://").map_or("", |(_, r)| r).split_once('?').map_or("", |(p, _)| p);
        let path = path.split_once('/').map_or("", |(_, p)| p);
        if self.is_lab() {
            path.split_once('/').map_or("", |(_, key)| key)
        } else {
            path
        }
    }

    /// X-Amz-SignedHeaders, percent-decoded.
    #[must_use]
    pub fn signed_headers(&self) -> &str {
        &self.1
    }

    /// X-Amz-Expires, in seconds.
    #[must_use]
    pub fn expires_s(&self) -> u64 {
        self.param("X-Amz-Expires").parse().unwrap_or_default()
    }

    /// Is it a lab URL (debug builds: the tests' loopback S3)?
    #[must_use]
    pub fn is_lab(&self) -> bool {
        self.0.expose().starts_with("http://")
    }

    /// The names of its query parameters, in order (values never).
    #[must_use]
    pub fn param_names(&self) -> Vec<&str> {
        let url = self.0.expose().as_str();
        let query = url.split_once('?').map_or("", |(_, q)| q);
        query.split('&').map(|pair| pair.split_once('=').map_or(pair, |(n, _)| n)).collect()
    }
}

impl Clone for PresignedUrl {
    /// One holder more: registered again.
    fn clone(&self) -> PresignedUrl {
        let copy = PresignedUrl(self.0.clone(), self.1.clone());
        copy.register();
        copy
    }
}

impl Drop for PresignedUrl {
    /// One holder fewer: both values forgotten once (the last holder's drop stops the masking).
    fn drop(&mut self) {
        forget_secret(self.0.expose());
        let signature = self.signature().to_string();
        forget_secret(&signature);
    }
}

impl fmt::Debug for PresignedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[presigned-url {}]", self.shown())
    }
}

impl PartialEq for PresignedUrl {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose() == other.0.expose()
    }
}
impl Eq for PresignedUrl {}

impl Serialize for PresignedUrl {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.expose())
    }
}

impl<'de> Deserialize<'de> for PresignedUrl {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        PresignedUrl::new(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::redact::scrub;

    const S: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const SHA: &str = "841075eede78b44b2d2862f4c38a643daf938671983e4ca0563a98a82ceddcd1";

    /// A URL of the bucket `ai-env-transcripts-123456789012` for `key`, its
    /// query the fake S3's credential, `extra` first, then the signature
    /// parameters (built at run time: no signature-shaped literal).
    fn url(key: &str, extra: &str, signed: &str, expires: u64, sig: char) -> String {
        let host = bucket_host(&bucket_name("123456789012").unwrap());
        let credential = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261017%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261017T101530Z";
        let signature = sig.to_string().repeat(64);
        format!("https://{host}/{key}?{extra}{credential}&X-Amz-Expires={expires}&X-Amz-SignedHeaders={}&X-Amz-Signature={signature}", signed.replace(';', "%3B"))
    }

    #[test]
    fn keys_render_and_parse_back() {
        let keys = [
            (S3Key::Mac { session: S.into(), sha256: SHA.into() }, format!("v1/{S}/mac/{SHA}")),
            (S3Key::Base { session: S.into(), gen: 1 }, format!("v1/{S}/vm/g1/base")),
            (S3Key::Segment { session: S.into(), gen: 12, offset: 48213 }, format!("v1/{S}/vm/g12/s/000000000000bc55")),
            (S3Key::Tail { session: S.into(), gen: 1, offset: 52000 }, format!("v1/{S}/vm/g1/t/000000000000cb20")),
            (S3Key::File { session: S.into(), sha256: SHA.into() }, format!("v1/{S}/vm/f/{SHA}")),
            (S3Key::EgressCheck { nonce: "abc12345".into() }, "v1/_egress-check/abc12345".to_string()),
            (S3Key::OutsideProbe { nonce: "abc12345".into() }, "x/_egress-check/abc12345".to_string()),
        ];
        for (key, text) in &keys {
            assert_eq!(&key.render(), text);
            assert_eq!(S3Key::parse(text).as_ref(), Some(key), "{text}");
        }
        let sessions: Vec<Option<&str>> = keys.iter().map(|(k, _)| k.session()).collect();
        assert_eq!(sessions, [Some(S), Some(S), Some(S), Some(S), Some(S), None, None]);
        let vm: Vec<bool> = keys.iter().map(|(k, _)| k.is_vm()).collect();
        assert_eq!(vm, [false, true, true, true, true, false, false]);
        for bad in [
            String::new(),
            "v1/".to_string(),
            format!("v1/{S}"),
            format!("v1/{S}/"),
            format!("v2/{S}/vm/g1/base"),
            "v1/not-a-session/vm/g1/base".to_string(),
            format!("v1/{S}/mac/{}", SHA.to_uppercase()),
            format!("v1/{S}/mac/{}", &SHA[..63]),
            format!("v1/{S}/vm/g01/base"),
            format!("v1/{S}/vm/g/base"),
            format!("v1/{S}/vm/g1/base/"),
            format!("v1/{S}/vm/g1/s/bc55"),
            format!("v1/{S}/vm/g1/s/000000000000BC55"),
            format!("v1/{S}/vm/g1/x/000000000000bc55"),
            format!("v1/{S}/vm/f/{SHA}/x"),
            format!("v1/{S}/../{S}/vm/g1/base"),
            "v1/_egress-check/short".to_string(),
            format!("v1/_egress-check/{}", "a".repeat(33)),
            "v1/_egress-check/ABCDEFGH".to_string(),
            "x/_egress-check/abc-1234".to_string(),
            format!("x/{S}/vm/g1/base"),
        ] {
            assert_eq!(S3Key::parse(&bad), None, "{bad}");
        }
        assert_eq!(bucket_name("123456789012").as_deref(), Some("ai-env-transcripts-123456789012"));
        assert_eq!((bucket_name("12345678901"), is_bucket_name("ai-env-transcripts-12345678901x")), (None, false));
        assert_eq!(bucket_host("ai-env-transcripts-123456789012"), "ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com");
        assert_eq!(sha256_b64(SHA).map(|b| b.len()), Some(44));
        assert_eq!(sha256_b64("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").as_deref(), Some("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="));
        assert_eq!(sha256_b64(&SHA.to_uppercase()), None);
        for good in ["http://10.42.0.10:3128", "http://172.16.0.1:1", "http://192.168.1.2:65535"] {
            assert_eq!(proxy_check(good), Ok(()), "{good}");
        }
        for bad in ["https://10.42.0.10:3128", "http://8.8.8.8:3128", "http://10.42.0.10", "http://10.42.0.10:0", "http://10.42.0.10:03128", "http://010.42.0.10:3128", "http://10.42.0.10:3128/", "http://user@10.42.0.10:3128", "http://10.42.0.10:+3128"] {
            assert!(proxy_check(bad).is_err(), "{bad}");
        }
    }

    /// The URL's rules, and its custody: registered with the scrubber while
    /// held (a clone holds it too), forgotten with its last holder; its
    /// `Debug`, `shown()` and every error name the host and key, never the
    /// query; it round-trips through serde as its text.
    #[test]
    fn presigned_urls_are_checked_registered_and_never_printed() {
        let key = format!("v1/{S}/vm/g1/s/000000000000bc55");
        let good = url(&key, "", SIGNED_HEADERS_PUT, 300, '7');
        let held = PresignedUrl::new(good.clone()).unwrap();
        assert_eq!((held.host(), held.key(), held.signed_headers(), held.expires_s(), held.is_lab()), ("ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com", key.as_str(), SIGNED_HEADERS_PUT, 300, false));
        assert_eq!(held.shown(), format!("https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/{key}"));
        assert_eq!(format!("{held:?}"), format!("[presigned-url {}]", held.shown()));
        assert_eq!(held.expose(), good);
        let signature = "7".repeat(64);
        let line = format!("curl failed on {good}; signature {signature}");
        assert!(!scrub(&line).contains(&signature) && !scrub(&line).contains("X-Amz-Credential"), "{}", scrub(&line));
        let copy = held.clone();
        drop(held);
        assert!(!scrub(&line).contains(&signature), "the clone still holds it");
        let json = serde_json::to_string(&copy).unwrap();
        assert_eq!(json, serde_json::to_string(&good).unwrap());
        let back: PresignedUrl = serde_json::from_str(&json).unwrap();
        assert_eq!(back, copy);
        drop((copy, back));
        assert!(scrub(&line).contains(&signature), "forgotten once the last holder went");
        // The bucket itself, a part of a multipart upload, a version.
        assert_eq!(check_url(&url("", "list-type=2&prefix=v1%2F&", SIGNED_HEADERS_GET, 300, 'a')), Ok(()));
        assert_eq!(check_url(&url(&key, "partNumber=1&uploadId=fu1&", SIGNED_HEADERS_PUT, 300, 'b')), Ok(()));
        assert_eq!(check_url(&url(&key, "versionId=fv2&", SIGNED_HEADERS_GET, 3600, 'c')), Ok(()));
        let host = "ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com";
        let cases: Vec<(String, &str)> = vec![
            (good.replace("https://", "ftp://"), "is not https://"),
            (good.replace(host, "ai-env-transcripts-123456789012.s3.eu-west-3.amazonaws.com"), "names a host other"),
            (good.replace(host, "other-bucket.s3.eu-central-1.amazonaws.com"), "names a host other"),
            (good.replace(host, &format!("{host}:443")), "names a host other"),
            (good.replace(host, &format!("user@{host}")), "names a host other"),
            (good.replace(&key, "v1/x/y"), "names a key"),
            (good.replace("X-Amz-Expires=300", "X-Amz-Expires=3601"), "expires after"),
            (good.replace("X-Amz-Expires=300", "X-Amz-Expires=0"), "expires after"),
            (good.replace("X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Algorithm=AWS4-HMAC-SHA1"), "AWS4-HMAC-SHA256"),
            (good.replace(&signature, &"7".repeat(63)), "64 lowercase hex"),
            (good.replace("X-Amz-Date=20261017T101530Z&", ""), "lacks X-Amz-Date"),
            (format!("{good}&response-content-type=x"), "\"response-content-type\""),
            (format!("{good}&X-Amz-Expires=300"), "twice"),
            (good.replace("ai-env-fake-s3", "ai env"), "printable ASCII"),
            (good.replace("ai-env-fake-s3", "ai\"env"), "printable ASCII"),
            (format!("{good}&prefix={}", "p".repeat(PRESIGNED_URL_MAX)), "bytes long"),
            (good.split('?').next().unwrap().to_string(), "no query"),
        ];
        for (bad, why) in cases {
            let e = PresignedUrl::new(bad.clone()).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
            assert!(!e.contains(&signature) && !e.contains("X-Amz-Credential="), "never the query: {e}");
        }
        assert!(serde_json::from_str::<PresignedUrl>("\"https://example.com/v1?x=1\"").is_err());
        // The lab's path-style loopback URL: debug builds only.
        let lab = format!("http://127.0.0.1:41234/ai-env-transcripts-123456789012/{key}?{}", good.split_once('?').unwrap().1);
        assert_eq!(check_url(&lab).is_ok(), cfg!(debug_assertions));
        if cfg!(debug_assertions) {
            let l = PresignedUrl::new(lab).unwrap();
            assert_eq!((l.is_lab(), l.host(), l.key()), (true, "127.0.0.1:41234", key.as_str()));
        }
        assert!(check_url(&format!("http://10.0.0.1:41234/ai-env-transcripts-123456789012/{key}?{}", good.split_once('?').unwrap().1)).is_err());
    }
}
