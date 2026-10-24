//! Every request's checks ([`judge`], pure, in B §B5.5's order) and every
//! response's headers ([`harden`]: [`HEADERS`], never a cookie, a CORS header
//! or `WWW-Authenticate`); the form bodies' parser ([`form_fields`]: word
//! values only, so no `form` feature and no decoding).
use super::{BEARER_LEN, BODY_MAX, FORM_TYPE, HEADERS};
use crate::wire::redact::Secret;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, StatusCode};
use std::collections::BTreeMap;

/// What `judge` sees of a request.
pub struct Parts<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub host: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub sec_fetch_site: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The path after `/<bearer>`, starting with `/` (empty for `/<bearer>` alone, which no route takes).
    Pass { rest: String },
    Refuse(StatusCode),
}

/// The checks, in order; pure:
/// 1. `Host` is exactly `127.0.0.1:<port>` (missing included): else 403;
/// 2. the first path segment is the bearer, its length first, then in constant time: else 401;
/// 3. the method is GET, HEAD or POST: else 405;
/// 4. a GET or HEAD whose `Sec-Fetch-Site` is present and neither `same-origin` nor `none`: 403;
/// 5. a POST whose `Origin` is missing or not `http://127.0.0.1:<port>`: 403;
/// 6. a POST whose `Sec-Fetch-Site` is present and not `same-origin`: 403;
/// 7. a POST whose content type is not [`FORM_TYPE`] (parameters ignored): 415;
/// 8. a POST whose `Content-Length` is over [`BODY_MAX`]: 413 (a body without one is cut at it when read).
#[must_use]
pub fn judge(parts: &Parts<'_>, port: u16, bearer: &Secret<String>) -> Verdict {
    let local = format!("127.0.0.1:{port}");
    if parts.host != Some(local.as_str()) {
        return Verdict::Refuse(StatusCode::FORBIDDEN);
    }
    let Some(after) = parts.path.strip_prefix('/') else {
        return Verdict::Refuse(StatusCode::UNAUTHORIZED);
    };
    let (first, rest) = after.split_at(after.find('/').unwrap_or(after.len()));
    if first.len() != BEARER_LEN || !bearer.ct_eq(first.as_bytes()) {
        return Verdict::Refuse(StatusCode::UNAUTHORIZED);
    }
    let get = *parts.method == Method::GET || *parts.method == Method::HEAD;
    let post = *parts.method == Method::POST;
    if !get && !post {
        return Verdict::Refuse(StatusCode::METHOD_NOT_ALLOWED);
    }
    if get && parts.sec_fetch_site.is_some_and(|s| s != "same-origin" && s != "none") {
        return Verdict::Refuse(StatusCode::FORBIDDEN);
    }
    if post {
        if parts.origin != Some(format!("http://{local}").as_str()) {
            return Verdict::Refuse(StatusCode::FORBIDDEN);
        }
        if parts.sec_fetch_site.is_some_and(|s| s != "same-origin") {
            return Verdict::Refuse(StatusCode::FORBIDDEN);
        }
        let media = parts.content_type.map(|t| t.split(';').next().unwrap_or_default().trim());
        if !media.is_some_and(|m| m.eq_ignore_ascii_case(FORM_TYPE)) {
            return Verdict::Refuse(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        if parts.content_length.is_some_and(|n| n > BODY_MAX as u64) {
            return Verdict::Refuse(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
    Verdict::Pass { rest: rest.to_string() }
}

/// Every response's headers ([`HEADERS`]); never a `Set-Cookie`, never a CORS header, never `WWW-Authenticate`.
pub fn harden(headers: &mut HeaderMap) {
    headers.remove(http::header::SET_COOKIE);
    headers.remove(http::header::WWW_AUTHENTICATE);
    let cors: Vec<HeaderName> = headers.keys().filter(|k| k.as_str().starts_with("access-control-")).cloned().collect();
    for name in cors {
        headers.remove(name);
    }
    for (name, value) in HEADERS {
        headers.insert(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
}

/// A byte of a form key or value: `[A-Za-z0-9_-]`.
fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// A form body's fields: `k=v` pairs split on `&`, each key and value `[A-Za-z0-9_-]` only (a key not empty),
/// each key once; anything else `None` (400). An empty body is no field.
#[must_use]
pub fn form_fields(body: &[u8]) -> Option<BTreeMap<String, String>> {
    let text = std::str::from_utf8(body).ok()?;
    let mut fields = BTreeMap::new();
    if text.is_empty() {
        return Some(fields);
    }
    for pair in text.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k.is_empty() || !k.bytes().all(word_byte) || !v.bytes().all(word_byte) {
            return None;
        }
        if fields.insert(k.to_string(), v.to_string()).is_some() {
            return None;
        }
    }
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 7391;

    fn bearer() -> Secret<String> {
        Secret::new("A".repeat(BEARER_LEN - 1) + "z")
    }

    fn parts<'a>(method: &'a Method, path: &'a str) -> Parts<'a> {
        Parts { method, path, host: Some("127.0.0.1:7391"), origin: None, sec_fetch_site: None, content_type: None, content_length: None }
    }

    /// A POST that passes every check.
    fn post<'a>(path: &'a str) -> Parts<'a> {
        Parts { origin: Some("http://127.0.0.1:7391"), sec_fetch_site: Some("same-origin"), content_type: Some("application/x-www-form-urlencoded; charset=UTF-8"), content_length: Some(60), ..parts(&Method::POST, path) }
    }

    /// Every row of B §B5.5's table, a pass of each method, and the order (an earlier check wins).
    #[test]
    fn judge_table() {
        let b = bearer();
        let good = format!("/{}/", b.expose());
        let actions = format!("/{}/actions", b.expose());
        let pass = |rest: &str| Verdict::Pass { rest: rest.to_string() };
        let refuse = Verdict::Refuse;
        let (get, head, put) = (Method::GET, Method::HEAD, Method::PUT);
        // Passes.
        assert_eq!(judge(&parts(&get, &good), PORT, &b), pass("/"));
        assert_eq!(judge(&parts(&head, &format!("/{}/vms", b.expose())), PORT, &b), pass("/vms"));
        assert_eq!(judge(&parts(&get, &format!("/{}", b.expose())), PORT, &b), pass(""), "no route takes it: 404");
        assert_eq!(judge(&Parts { sec_fetch_site: Some("same-origin"), ..parts(&get, &good) }, PORT, &b), pass("/"));
        assert_eq!(judge(&Parts { sec_fetch_site: Some("none"), ..parts(&get, &good) }, PORT, &b), pass("/"));
        assert_eq!(judge(&post(&actions), PORT, &b), pass("/actions"));
        assert_eq!(judge(&Parts { sec_fetch_site: None, content_length: None, content_type: Some(FORM_TYPE), ..post(&actions) }, PORT, &b), pass("/actions"));
        // 1. Host.
        for host in [None, Some("localhost:7391"), Some("127.0.0.1"), Some("127.0.0.1:7392"), Some("127.0.0.1:7391 "), Some("evil.example")] {
            assert_eq!(judge(&Parts { host, ..parts(&get, &good) }, PORT, &b), refuse(StatusCode::FORBIDDEN), "{host:?}");
        }
        assert_eq!(judge(&Parts { host: None, ..parts(&get, "/nope/") }, PORT, &b), refuse(StatusCode::FORBIDDEN), "the host first");
        // 2. The bearer.
        let mut same_length = b.expose().clone();
        same_length.replace_range(0..1, "B");
        for path in ["/".to_string(), "/x/".to_string(), format!("/{same_length}/"), format!("/{}x/", b.expose()), format!("/{}/", &b.expose()[1..]), format!("//{}/", b.expose()), "".to_string()] {
            assert_eq!(judge(&parts(&get, &path), PORT, &b), refuse(StatusCode::UNAUTHORIZED), "{path}");
        }
        assert_eq!(judge(&parts(&put, "/x/"), PORT, &b), refuse(StatusCode::UNAUTHORIZED), "the bearer before the method");
        // 3. The method.
        for m in [Method::PUT, Method::DELETE, Method::OPTIONS, Method::PATCH, Method::TRACE] {
            assert_eq!(judge(&parts(&m, &good), PORT, &b), refuse(StatusCode::METHOD_NOT_ALLOWED), "{m}");
        }
        // 4. A GET or HEAD from another site.
        for site in ["cross-site", "same-site", "Same-Origin"] {
            assert_eq!(judge(&Parts { sec_fetch_site: Some(site), ..parts(&get, &good) }, PORT, &b), refuse(StatusCode::FORBIDDEN), "{site}");
            assert_eq!(judge(&Parts { sec_fetch_site: Some(site), ..parts(&head, &good) }, PORT, &b), refuse(StatusCode::FORBIDDEN), "{site}");
        }
        // 5. A POST's Origin.
        for origin in [None, Some("null"), Some("http://localhost:7391"), Some("http://127.0.0.1:7392"), Some("https://127.0.0.1:7391"), Some("http://127.0.0.1:7391/")] {
            assert_eq!(judge(&Parts { origin, ..post(&actions) }, PORT, &b), refuse(StatusCode::FORBIDDEN), "{origin:?}");
        }
        // 6. A POST's Sec-Fetch-Site.
        for site in ["none", "same-site", "cross-site"] {
            assert_eq!(judge(&Parts { sec_fetch_site: Some(site), ..post(&actions) }, PORT, &b), refuse(StatusCode::FORBIDDEN), "{site}");
        }
        // 7. A POST's content type.
        for ct in [None, Some("text/plain"), Some("multipart/form-data; boundary=x"), Some("application/json"), Some("application/x-www-form-urlencodedx")] {
            assert_eq!(judge(&Parts { content_type: ct, ..post(&actions) }, PORT, &b), refuse(StatusCode::UNSUPPORTED_MEDIA_TYPE), "{ct:?}");
        }
        assert_eq!(judge(&Parts { content_type: Some("Application/X-WWW-Form-Urlencoded"), ..post(&actions) }, PORT, &b), pass("/actions"));
        // 8. A POST's size.
        assert_eq!(judge(&Parts { content_length: Some(BODY_MAX as u64 + 1), ..post(&actions) }, PORT, &b), refuse(StatusCode::PAYLOAD_TOO_LARGE));
        assert_eq!(judge(&Parts { content_length: Some(BODY_MAX as u64), ..post(&actions) }, PORT, &b), pass("/actions"));
        assert_eq!(judge(&Parts { content_type: None, content_length: Some(1 << 20), ..post(&actions) }, PORT, &b), refuse(StatusCode::UNSUPPORTED_MEDIA_TYPE), "in order");
    }

    #[test]
    fn form_fields_take_word_values_only() {
        let f = form_fields(b"nonce=0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b&action=vm-suspend&target=microvm-x_1").unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!((f["nonce"].as_str(), f["action"].as_str(), f["target"].as_str()), ("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", "vm-suspend", "microvm-x_1"));
        assert_eq!(form_fields(b"").unwrap().len(), 0);
        assert_eq!(form_fields(b"target=").unwrap()["target"], "", "an empty value has no other byte");
        for bad in [
            &b"a=b&a=c"[..],
            b"a",
            b"=b",
            b"a=b&",
            b"a=b=c",
            b"a=b%20c",
            b"a=b+c",
            b"a=<b>",
            b"a=\xff",
            b"a=b;c",
            b"a b=c",
            b"a=b\n",
            b"a=../x",
            b"a=b.c",
        ] {
            assert_eq!(form_fields(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn harden_sets_the_six_and_drops_cookies_and_cors() {
        let mut h = HeaderMap::new();
        h.insert(http::header::SET_COOKIE, HeaderValue::from_static("a=b"));
        h.insert(http::header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        h.insert(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        h.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        harden(&mut h);
        for (name, value) in HEADERS {
            assert_eq!(h.get_all(name).iter().collect::<Vec<_>>(), [value], "{name}");
        }
        assert!(h.get(http::header::SET_COOKIE).is_none() && h.get(http::header::WWW_AUTHENTICATE).is_none() && h.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
        assert_eq!(h.len(), HEADERS.len());
    }
}
