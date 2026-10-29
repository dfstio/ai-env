//! Presigning (S9 plan §5, G4): a query-string SigV4 URL for one request of
//! the transcript store, signed with the runtime key (`SdkMicrovmApi`'s
//! credentials provider, as `get_connector` signs by hand) or the lab key
//! (the fakes: `LAB_KEY_ID`, `LAB_SECRET`): service `s3`, region
//! `eu-central-1`, the signature in the query, S3's own settings (the path
//! encoded once and never normalised), an unsigned payload; the exact key,
//! `PRESIGN_EXPIRY` (a tail's `TAIL_EXPIRY`, a pull's parts the pull's
//! budget), and `x-amz-expected-bucket-owner` signed in every request. The
//! URL comes back only as a `wire::s3::PresignedUrl`.
use super::{PresignReq, S3Endpoint, S3Method, S3Target};
use crate::bridge::errors::BridgeError;
use crate::wire::s3::{bucket_host, is_account_id, is_bucket_name, PresignedUrl, S3Key, REGION, TAIL_EXPIRY};
use std::time::{Duration, SystemTime};

/// The header every request signs, its value the bucket's owner (a bucket of
/// our name in another account answers 403, never takes a transcript).
pub const OWNER_HEADER: &str = "x-amz-expected-bucket-owner";
/// The headers a request may sign besides `host`, lowercase (plans/s9-contracts.md §2.2); S11 (L5, C.3.4):
/// `content-encoding`, which an encoded object's PUT or CreateMultipartUpload signs; S12 (P):
/// `x-amz-sdk-checksum-algorithm`, which a multi-object delete signs beside its `x-amz-checksum-sha256`.
pub const SIGNABLE_HEADERS: [&str; 7] = ["content-length", "content-encoding", "x-amz-checksum-sha256", "x-amz-checksum-algorithm", "x-amz-sdk-checksum-algorithm", "if-none-match", OWNER_HEADER];
/// The query parameters a request may sign besides the X-Amz ones, in the
/// order they must come; S12 (P): `delete` last (`reorder`'s positions of the
/// others unchanged).
pub const SIGNABLE_QUERY: [&str; 9] = ["versionId", "uploadId", "partNumber", "uploads", "list-type", "prefix", "continuation-token", "max-keys", "delete"];
/// The signing name of S3.
pub const SIGNING_NAME: &str = "s3";

impl S3Method {
    /// The HTTP method.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            S3Method::Get => "GET",
            S3Method::Put => "PUT",
            S3Method::Post => "POST",
            S3Method::Delete => "DELETE",
        }
    }
}

/// The request's rules, before anything is signed (`Config`, exit 1, naming
/// the first broken one): the bucket a transcripts bucket and its owner 12
/// digits; the key one of the store's ([`S3Key::parse`]); the query names of
/// [`SIGNABLE_QUERY`], each once, in its order; the headers of
/// [`SIGNABLE_HEADERS`], lowercase, each once; S12 (P, LD-P9): `delete` only
/// in a POST of the bucket itself (no key), with no value, alone in the query
/// (a multi-object delete), and `x-amz-sdk-checksum-algorithm` only
/// `SHA256`, beside `x-amz-checksum-sha256`, in such a delete (which may sign
/// neither: the live probe presigns the forms S3 should refuse); then
/// [`OWNER_HEADER`] among the headers, its value the target's owner; the
/// expiry whole seconds from 1 to `TAIL_EXPIRY` (3600 s).
pub fn check(req: &PresignReq) -> Result<(), BridgeError> {
    let bad = |why: String| Err(BridgeError::Config(format!("presign: {why}")));
    let t = &req.target;
    if !is_bucket_name(&t.bucket) {
        return bad(format!("{:?} is not a transcripts bucket", t.bucket));
    }
    if !is_account_id(&t.owner) {
        return bad("the bucket's owner is not 12 digits".into());
    }
    if let Some(key) = &req.key {
        if S3Key::parse(key).is_none() {
            return bad(format!("{key:?} is no key of the store"));
        }
    }
    let mut at = 0;
    for (name, _) in &req.query {
        match SIGNABLE_QUERY.iter().position(|q| q == name) {
            Some(i) if i >= at => at = i + 1,
            Some(_) => return bad(format!("the query parameter {name} is out of order, or twice")),
            None => return bad(format!("{name:?} is no query parameter a request of the store signs")),
        }
    }
    let mut seen: Vec<&str> = Vec::new();
    for (name, value) in &req.headers {
        if !SIGNABLE_HEADERS.contains(&name.as_str()) {
            return bad(format!("{name:?} is no header a request of the store signs"));
        }
        if seen.contains(&name.as_str()) {
            return bad(format!("the header {name} twice"));
        }
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
            return bad(format!("the header {name} has an empty or unprintable value"));
        }
        seen.push(name);
    }
    // S12 (P, P-R18): a multi-object delete (`POST /?delete`) and its SDK checksum header, signed only so.
    let delete = req.query.iter().find(|(n, _)| n == "delete");
    if let Some((_, value)) = delete {
        if req.method != S3Method::Post {
            return bad("the query parameter delete is a POST's (a multi-object delete)".into());
        }
        if req.key.is_some() {
            return bad("the query parameter delete names the bucket itself, not a key".into());
        }
        if !value.is_empty() {
            return bad("the query parameter delete has no value".into());
        }
        if req.query.len() > 1 {
            return bad("the query parameter delete stands alone".into());
        }
    }
    if let Some((_, algorithm)) = req.headers.iter().find(|(n, _)| n == "x-amz-sdk-checksum-algorithm") {
        if algorithm != "SHA256" {
            return bad("x-amz-sdk-checksum-algorithm is SHA256".into());
        }
        if !req.headers.iter().any(|(n, _)| n == "x-amz-checksum-sha256") {
            return bad("x-amz-sdk-checksum-algorithm without x-amz-checksum-sha256".into());
        }
        if delete.is_none() {
            return bad("x-amz-sdk-checksum-algorithm is a multi-object delete's only".into());
        }
    }
    match req.headers.iter().find(|(n, _)| n == OWNER_HEADER) {
        None => return bad(format!("the request does not sign {OWNER_HEADER}")),
        Some((_, v)) if *v != t.owner => return bad(format!("{OWNER_HEADER} is not the bucket's owner")),
        Some(_) => {}
    }
    let secs = req.expires.as_secs();
    if req.expires.subsec_nanos() != 0 || !(1..=TAIL_EXPIRY.as_secs()).contains(&secs) {
        return bad(format!("an expiry of {} s (whole seconds, 1 to {})", req.expires.as_secs_f64(), TAIL_EXPIRY.as_secs()));
    }
    Ok(())
}

/// `text` percent-encoded but S3's unreserved characters (`A-Za-z0-9-_.~`):
/// a key's segment, a query name or value (a `+` is never read as a space).
#[must_use]
pub fn encode(text: &str) -> String {
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

/// The URL of `key` (none: the bucket itself) of `target` without a query:
/// `https://<bucket>.s3.eu-central-1.amazonaws.com/<key>` (virtual-hosted;
/// the bucket itself is `/`), or in debug builds `http://<addr>/<bucket>/<key>`
/// (path-style, the lab's loopback S3; the bucket itself is `/<bucket>`).
pub fn object_url(target: &S3Target, key: Option<&str>) -> Result<String, BridgeError> {
    let path: String = key.map(|k| k.split('/').map(encode).collect::<Vec<_>>().join("/")).unwrap_or_default();
    match target.endpoint {
        S3Endpoint::Aws => Ok(format!("https://{}/{path}", bucket_host(&target.bucket))),
        S3Endpoint::Lab(addr) if cfg!(debug_assertions) => {
            if !addr.ip().is_loopback() {
                return Err(BridgeError::Config(format!("presign: the lab S3 is a loopback address, not {addr}")));
            }
            Ok(if path.is_empty() { format!("http://{addr}/{}", target.bucket) } else { format!("http://{addr}/{}/{path}", target.bucket) })
        }
        S3Endpoint::Lab(_) => Err(BridgeError::Config("presign: the lab S3 exists in debug builds only".into())),
    }
}

/// The lab's credentials (`LAB_KEY_ID`, `LAB_SECRET`: the two fakes sign
/// with them, the tests' S3 checks them; not credential-shaped).
#[must_use]
pub fn lab_credentials() -> aws_sdk_lambdamicrovms::config::Credentials {
    aws_sdk_lambdamicrovms::config::Credentials::new(super::LAB_KEY_ID, super::LAB_SECRET, None, None, "ai-env-lab-s3")
}

/// `req` ([`check`]ed) signed with `creds` at `time`: the URL of its key with
/// its query in order, then the SigV4 query parameters aws-sigv4 made
/// (S3's settings: the path taken as encoded once and never normalised, the
/// payload unsigned, a temporary credential's token signed in), as a
/// [`PresignedUrl`] (checked, and registered with the scrubber while held).
pub fn sign(creds: aws_sdk_lambdamicrovms::config::Credentials, req: &PresignReq, time: SystemTime) -> Result<PresignedUrl, BridgeError> {
    use aws_sigv4::http_request::{PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation, SigningSettings, UriPathNormalizationMode};
    const OP: &str = "presign";
    check(req)?;
    let mut url = object_url(&req.target, req.key.as_deref())?;
    let pairs: Vec<String> = req.query.iter().map(|(k, v)| format!("{}={}", encode(k), encode(v))).collect();
    if !pairs.is_empty() {
        url.push('?');
        url.push_str(&pairs.join("&"));
    }
    let identity = creds.into();
    let mut settings = SigningSettings::default();
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in = Some(Duration::from_secs(req.expires.as_secs()));
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    let params = aws_sigv4::sign::v4::SigningParams::builder()
        .identity(&identity)
        .region(REGION)
        .name(SIGNING_NAME)
        .time(time)
        .settings(settings)
        .build()
        .map_err(|e| BridgeError::Sdk { op: OP, message: format!("signing parameters: {e}") })?
        .into();
    let headers = req.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    let signable = SignableRequest::new(req.method.as_str(), url.as_str(), headers, SignableBody::UnsignedPayload).map_err(|e| BridgeError::Sdk { op: OP, message: format!("signable request: {e}") })?;
    let (instructions, _) = aws_sigv4::http_request::sign(signable, &params).map_err(|e| BridgeError::Sdk { op: OP, message: format!("signing: {e}") })?.into_parts();
    let signed: Vec<String> = instructions.params().iter().map(|(k, v)| format!("{}={}", encode(k), encode(v))).collect();
    url.push(if pairs.is_empty() { '?' } else { '&' });
    url.push_str(&signed.join("&"));
    PresignedUrl::new(url).map_err(|e| BridgeError::Config(format!("{OP}: {e}")))
}

/// A request for `key` (none: the bucket itself) of `target` by `method`,
/// `x-amz-expected-bucket-owner` first among its headers, then `headers`,
/// expiring after `expires`.
#[must_use]
pub fn request(method: S3Method, target: &S3Target, key: Option<String>, query: Vec<(String, String)>, headers: Vec<(String, String)>, expires: Duration) -> PresignReq {
    let mut all = vec![(OWNER_HEADER.to_string(), target.owner.clone())];
    all.extend(headers);
    PresignReq { method, target: target.clone(), key, query, headers: all, expires }
}

/// The headers of a write of `len` bytes whose sha256 is `sha256` (lowercase
/// hex): `content-length`, `x-amz-checksum-sha256` (base64 of the digest),
/// and `if-none-match: *` when `new_only` (the store's objects are immutable).
pub fn write_headers(len: u64, sha256: &str, new_only: bool) -> Result<Vec<(String, String)>, BridgeError> {
    let checksum = crate::wire::s3::sha256_b64(sha256).ok_or_else(|| BridgeError::Config("presign: a write's sha256 is not 64 lowercase hex digits".into()))?;
    let mut h = vec![("content-length".to_string(), len.to_string()), ("x-amz-checksum-sha256".to_string(), checksum)];
    if new_only {
        h.push(("if-none-match".to_string(), "*".to_string()));
    }
    Ok(h)
}

/// How long the parts of one pull of `bytes` in all stay valid: the pull's
/// budget, as the shim and the Mac count it (S10:
/// `wire::workspace::budget::pull_budget`, `share` the pulls that run at
/// once, 1 for one alone), at least `PRESIGN_EXPIRY`, at most `PULL_EXPIRY_MAX`.
#[must_use]
pub fn pull_expiry(bytes: u64, share: u32) -> Duration {
    let budget = crate::wire::workspace::budget::pull_budget(bytes, share);
    budget.clamp(crate::wire::s3::PRESIGN_EXPIRY, crate::wire::s3::PULL_EXPIRY_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::s3::{LAB_BUCKET, LAB_OWNER};
    use crate::wire::s3::{PRESIGN_EXPIRY, SIGNED_HEADERS_GET, SIGNED_HEADERS_PUT};

    const S: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const SHA: &str = "b094ab054161cac4f8714d6855dc32bf0488f8eed1c4790aec8f054577f7c5c2";

    fn aws() -> S3Target {
        S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Aws }
    }

    /// 2026-10-17T10:15:30Z, the goldens' signing time.
    fn at() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(crate::wire::time::parse_rfc3339_utc("2026-10-17T10:15:30Z").unwrap())
    }

    /// A segment's PUT signs exactly `SIGNED_HEADERS_PUT` (its length, its
    /// checksum, `If-None-Match` and the owner), for its key, for 300 s, as
    /// the golden `transcript_push` carries it: the very same URL up to its
    /// signature (the golden's signature is a placeholder of SigV4's shape),
    /// then the signature of the lab key at the goldens' time as a known
    /// answer (computed independently of aws-sigv4: the canonical request of
    /// that PUT, `UNSIGNED-PAYLOAD`, the key `fake-s3-secret`); the request
    /// checks the VM would make (`TranscriptPush::check`) pass.
    #[test]
    fn presign_put_signs_length_checksum_if_none_match_owner() {
        let key = format!("v1/{S}/vm/g1/s/000000000000bc55");
        let req = request(S3Method::Put, &aws(), Some(key.clone()), Vec::new(), write_headers(3787, SHA, true).unwrap(), PRESIGN_EXPIRY);
        let url = sign(lab_credentials(), &req, at()).unwrap();
        assert_eq!((url.host(), url.key(), url.signed_headers(), url.expires_s()), ("ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com", key.as_str(), SIGNED_HEADERS_PUT, 300));
        let golden = "https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/v1/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/vm/g1/s/000000000000bc55?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261017%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261017T101530Z&X-Amz-Expires=300&X-Amz-SignedHeaders=content-length%3Bhost%3Bif-none-match%3Bx-amz-checksum-sha256%3Bx-amz-expected-bucket-owner&X-Amz-Signature=";
        assert_eq!(url.expose(), format!("{golden}c345b4eeaec8841f514d1fb382462a2c6c349e541e229ce59ec102299fad6625"), "the lab key's signature, a known answer");
        let push = crate::wire::workspace::TranscriptPush {
            rel: format!("-Users-mike-Documents-DeFi-ai-env/{S}.jsonl"),
            from: 48213,
            len: 3787,
            sha256: SHA.into(),
            url: url.clone(),
            owner: LAB_OWNER.into(),
            proxy: Some("http://10.42.0.10:3128".into()),
        };
        assert_eq!(push.check(), Ok(()));
        // The same request signed twice at the same time is the same URL; a different length signs differently.
        assert_eq!(sign(lab_credentials(), &req, at()).unwrap(), url);
        let other = request(S3Method::Put, &aws(), Some(key), Vec::new(), write_headers(3788, SHA, true).unwrap(), PRESIGN_EXPIRY);
        assert_ne!(sign(lab_credentials(), &other, at()).unwrap(), url);
        // A GET of a version signs only the host and the owner, the versionId in the query first.
        let get = request(S3Method::Get, &aws(), Some(format!("v1/{S}/vm/g1/base")), vec![("versionId".into(), "fv1".into())], Vec::new(), PRESIGN_EXPIRY);
        let g = sign(lab_credentials(), &get, at()).unwrap();
        assert_eq!((g.signed_headers(), g.param_names()[0]), (SIGNED_HEADERS_GET, "versionId"));
        assert!(!format!("{url:?}{g:?}").contains("X-Amz-Signature"), "Debug shows the host and key only");
    }

    /// S11 (C.3.4): an encoded object's PUT signs `content-encoding: gzip`; an unsigned extra header is still refused.
    /// S12 (P): the list holds the SDK checksum header a multi-object delete signs.
    #[test]
    fn content_encoding_is_a_signable_header() {
        assert_eq!(SIGNABLE_HEADERS, ["content-length", "content-encoding", "x-amz-checksum-sha256", "x-amz-checksum-algorithm", "x-amz-sdk-checksum-algorithm", "if-none-match", OWNER_HEADER]);
        let key = Some(format!("v1/{S}/mac/{SHA}"));
        let mut headers = write_headers(3787, SHA, true).unwrap();
        headers.push(("content-encoding".into(), "gzip".into()));
        let req = request(S3Method::Put, &aws(), key.clone(), Vec::new(), headers, PRESIGN_EXPIRY);
        assert!(check(&req).is_ok(), "{:?}", check(&req));
        let url = sign(lab_credentials(), &req, at()).unwrap();
        assert!(url.signed_headers().split(';').any(|h| h == "content-encoding"), "{}", url.signed_headers());
        let mut other = req.clone();
        other.headers.push(("x-amz-meta-what".into(), "x".into()));
        assert!(matches!(check(&other), Err(BridgeError::Config(m)) if m.contains("x-amz-meta-what")));
    }

    /// S12 (P, P-R1, P-R18): a multi-object delete, a POST of the bucket
    /// itself with `delete` (empty, alone: `SIGNABLE_QUERY`'s last, S11's
    /// eight before it in their order), signs exactly its SDK checksum pair
    /// beside the owner, `host;x-amz-checksum-sha256;x-amz-expected-bucket-owner;x-amz-sdk-checksum-algorithm`,
    /// its URL naming no key and `delete` first; with no checksum, or the
    /// checksum alone, it signs too (the live probe's forms). Refused before
    /// anything is signed (`Config`, exit 1), each naming its rule: `delete`
    /// on a GET, a PUT or a DELETE, with a key, with a value, beside another
    /// parameter; the SDK header other than `SHA256`, without the checksum,
    /// or in a request without `delete` (a PUT of a key).
    #[test]
    fn a_multi_object_delete_signs_its_checksum_pair() {
        assert_eq!(SIGNABLE_QUERY[..8], ["versionId", "uploadId", "partNumber", "uploads", "list-type", "prefix", "continuation-token", "max-keys"]);
        assert_eq!(SIGNABLE_QUERY[8], "delete");
        let checksum = crate::wire::s3::sha256_b64(SHA).unwrap();
        let sdk = |algorithm: &str| ("x-amz-sdk-checksum-algorithm".to_string(), algorithm.to_string());
        let sum = || ("x-amz-checksum-sha256".to_string(), checksum.clone());
        let delete = || vec![("delete".to_string(), String::new())];
        let req = request(S3Method::Post, &aws(), None, delete(), vec![sdk("SHA256"), sum()], PRESIGN_EXPIRY);
        let url = sign(lab_credentials(), &req, at()).unwrap();
        assert_eq!((url.signed_headers(), url.key(), url.param_names()[0]), ("host;x-amz-checksum-sha256;x-amz-expected-bucket-owner;x-amz-sdk-checksum-algorithm", "", "delete"));
        assert!(url.expose().starts_with("https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/?delete=&X-Amz-Algorithm=AWS4-HMAC-SHA256&"), "{url:?}");
        // The live probe's forms: no checksum header at all, and the checksum alone.
        for (headers, signed) in [(Vec::new(), "host;x-amz-expected-bucket-owner"), (vec![sum()], "host;x-amz-checksum-sha256;x-amz-expected-bucket-owner")] {
            let url = sign(lab_credentials(), &request(S3Method::Post, &aws(), None, delete(), headers, PRESIGN_EXPIRY), at()).unwrap();
            assert_eq!((url.signed_headers(), url.key()), (signed, ""));
        }
        let key = Some(format!("v1/{S}/mac/{SHA}"));
        let mut put = write_headers(3787, SHA, true).unwrap();
        put.push(sdk("SHA256"));
        let pair = || vec![sdk("SHA256"), sum()];
        let refused: Vec<(PresignReq, &str)> = vec![
            (request(S3Method::Get, &aws(), None, delete(), pair(), PRESIGN_EXPIRY), "the query parameter delete is a POST's (a multi-object delete)"),
            (request(S3Method::Put, &aws(), None, delete(), pair(), PRESIGN_EXPIRY), "the query parameter delete is a POST's (a multi-object delete)"),
            (request(S3Method::Delete, &aws(), None, delete(), pair(), PRESIGN_EXPIRY), "the query parameter delete is a POST's (a multi-object delete)"),
            (request(S3Method::Post, &aws(), key.clone(), delete(), pair(), PRESIGN_EXPIRY), "the query parameter delete names the bucket itself, not a key"),
            (request(S3Method::Post, &aws(), None, vec![("delete".into(), "x".into())], pair(), PRESIGN_EXPIRY), "the query parameter delete has no value"),
            (request(S3Method::Post, &aws(), None, vec![("prefix".into(), format!("v1/{S}/")), ("delete".into(), String::new())], pair(), PRESIGN_EXPIRY), "the query parameter delete stands alone"),
            (request(S3Method::Post, &aws(), None, delete(), vec![sdk("CRC32"), sum()], PRESIGN_EXPIRY), "x-amz-sdk-checksum-algorithm is SHA256"),
            (request(S3Method::Post, &aws(), None, delete(), vec![sdk("SHA256")], PRESIGN_EXPIRY), "x-amz-sdk-checksum-algorithm without x-amz-checksum-sha256"),
            (request(S3Method::Put, &aws(), key, Vec::new(), put, PRESIGN_EXPIRY), "x-amz-sdk-checksum-algorithm is a multi-object delete's only"),
        ];
        for (req, why) in refused {
            match sign(lab_credentials(), &req, at()) {
                Err(BridgeError::Config(m)) => assert_eq!(m, format!("presign: {why}")),
                other => panic!("{why}: expected Config, got {other:?}"),
            }
        }
    }

    /// Every method and the bucket itself sign `x-amz-expected-bucket-owner`
    /// with the target's owner; a request without the header, or with
    /// another owner, is refused before anything is signed (exit 1); so are
    /// a header or a query parameter no request of ours signs, a key that is
    /// none of the store's, and an expiry outside 1 to 3600 s.
    #[test]
    fn presign_always_signs_the_expected_owner() {
        let key = Some(format!("v1/{S}/mac/{SHA}"));
        for method in [S3Method::Get, S3Method::Put, S3Method::Post, S3Method::Delete] {
            for k in [key.clone(), None] {
                let query = if k.is_none() { vec![("list-type".to_string(), "2".to_string()), ("prefix".to_string(), format!("v1/{S}/"))] } else { Vec::new() };
                let url = sign(lab_credentials(), &request(method, &aws(), k.clone(), query, Vec::new(), PRESIGN_EXPIRY), at()).unwrap();
                assert!(url.signed_headers().split(';').any(|h| h == OWNER_HEADER), "{method:?} {k:?}: {}", url.signed_headers());
                assert_eq!(url.key(), k.as_deref().unwrap_or(""));
            }
        }
        let config = |r: Result<PresignedUrl, BridgeError>| match r {
            Err(BridgeError::Config(m)) => m,
            other => panic!("expected Config, got {other:?}"),
        };
        let mut no_owner = request(S3Method::Get, &aws(), key.clone(), Vec::new(), Vec::new(), PRESIGN_EXPIRY);
        no_owner.headers.clear();
        assert!(config(sign(lab_credentials(), &no_owner, at())).contains("does not sign x-amz-expected-bucket-owner"));
        let mut other_owner = request(S3Method::Put, &aws(), key.clone(), Vec::new(), Vec::new(), PRESIGN_EXPIRY);
        other_owner.headers[0].1 = "999999999999".into();
        assert!(config(sign(lab_credentials(), &other_owner, at())).contains("is not the bucket's owner"));
        let refused: Vec<(PresignReq, &str)> = vec![
            (request(S3Method::Get, &aws(), key.clone(), Vec::new(), vec![("x-amz-checksum-mode".into(), "ENABLED".into())], PRESIGN_EXPIRY), "no header"),
            (request(S3Method::Get, &aws(), key.clone(), vec![("response-content-type".into(), "x".into())], Vec::new(), PRESIGN_EXPIRY), "no query parameter"),
            (request(S3Method::Get, &aws(), key.clone(), vec![("prefix".into(), "a".into()), ("list-type".into(), "2".into())], Vec::new(), PRESIGN_EXPIRY), "out of order"),
            (request(S3Method::Get, &aws(), Some("v1/not/ours".into()), Vec::new(), Vec::new(), PRESIGN_EXPIRY), "no key of the store"),
            (request(S3Method::Get, &aws(), key.clone(), Vec::new(), Vec::new(), Duration::from_secs(3601)), "an expiry"),
            (request(S3Method::Get, &aws(), key.clone(), Vec::new(), Vec::new(), Duration::ZERO), "an expiry"),
            (request(S3Method::Get, &aws(), key.clone(), Vec::new(), vec![(OWNER_HEADER.into(), LAB_OWNER.into())], PRESIGN_EXPIRY), "twice"),
            (request(S3Method::Get, &S3Target { bucket: "other-bucket".into(), ..aws() }, key.clone(), Vec::new(), Vec::new(), PRESIGN_EXPIRY), "not a transcripts bucket"),
        ];
        for (req, why) in refused {
            let e = config(sign(lab_credentials(), &req, at()));
            assert!(e.contains(why), "{why}: {e}");
        }
        // The lab's path-style URL in debug builds.
        let lab = S3Target { endpoint: S3Endpoint::Lab("127.0.0.1:41234".parse().unwrap()), ..aws() };
        let url = sign(lab_credentials(), &request(S3Method::Get, &lab, key.clone(), Vec::new(), Vec::new(), PRESIGN_EXPIRY), at());
        if cfg!(debug_assertions) {
            let url = url.unwrap();
            assert_eq!((url.is_lab(), url.host(), url.key()), (true, "127.0.0.1:41234", key.as_deref().unwrap()));
        } else {
            assert!(url.is_err());
        }
        assert_eq!((pull_expiry(0, 1), pull_expiry(10_000_000_000, 1)), (PRESIGN_EXPIRY, crate::wire::s3::PULL_EXPIRY_MAX));
        // S10: the pull's budget as both ends count it (`pull_budget`: 60 s, 30 s, the bytes at 1 MB/s times the share).
        assert_eq!(pull_expiry(300_000_000, 1), Duration::from_secs(390), "60 s plus 30 s plus 300 MB at 1 MB/s");
        assert_eq!(pull_expiry(300_000_000, 4), Duration::from_secs(1290), "four pulls at once share the rate");
        assert_eq!(pull_expiry(300_000_000, 0), pull_expiry(300_000_000, 1), "a share of 0 counts as 1");
        assert_eq!(pull_expiry(300_000_000, 1), crate::wire::workspace::budget::pull_budget(300_000_000, 1), "the budget itself when inside the bounds");
    }
}
