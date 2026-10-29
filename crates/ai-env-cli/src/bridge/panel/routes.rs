//! The router and the handlers (B §B5.6). One handler takes every request:
//! [`guard::judge`] first (the bearer is the path's first segment), then the
//! route of the path after it, by hand; every response passes
//! [`guard::harden`]. Pages answer `?json=1` with their model's document;
//! HEAD answers as GET without a body (and issues no nonce). Error bodies are
//! one `text/plain` line that never echoes the request's path, a header or a
//! form value; a model's error is a 500 page with its line.
use super::actions::{self, Action};
use super::guard::{self, Parts, Verdict};
use super::html::{self, BELOW, TOP};
use super::model::{self, PageErr};
use super::{sse, Shared, BODY_MAX};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use axum::Router;
use http::{header, HeaderValue, Method, StatusCode};
use std::collections::BTreeMap;
use std::sync::Arc;

/// `assets/app.js`.
const APP_JS: &str = include_str!("assets/app.js");
/// `assets/app.css`.
const APP_CSS: &str = include_str!("assets/app.css");

/// The panel's router: one handler for every method and path.
pub(crate) fn router(shared: Arc<Shared>) -> Router {
    Router::new().fallback(entry).layer(axum::extract::DefaultBodyLimit::max(BODY_MAX)).with_state(shared)
}

/// Every request: its answer, hardened.
async fn entry(State(shared): State<Arc<Shared>>, req: Request) -> Response {
    let mut resp = answer(&shared, req).await;
    guard::harden(resp.headers_mut());
    resp
}

/// One `text/plain; charset=utf-8` line.
pub(crate) fn plain(status: StatusCode, line: &str) -> Response {
    let mut r = Response::new(Body::from(format!("{line}\n")));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    r
}

/// A refusal's fixed line: never the request's path, a header or a value.
fn refusal(status: StatusCode) -> Response {
    let line = match status {
        StatusCode::BAD_REQUEST => "bad request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not found",
        StatusCode::METHOD_NOT_ALLOWED => "method not allowed",
        StatusCode::PAYLOAD_TOO_LARGE => "payload too large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported media type",
        _ => "refused",
    };
    plain(status, line)
}

/// A body of `content_type`.
fn typed(status: StatusCode, content_type: &'static str, body: String) -> Response {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    r
}

/// An HTML page (200).
fn html_page(body: String) -> Response {
    typed(StatusCode::OK, "text/html; charset=utf-8", body)
}

/// A page's error: 400 and 404 their fixed line (as text for `?json=1`), 500 a page with the model's line.
pub(crate) fn page_error(root: &str, e: &PageErr, json: bool) -> Response {
    match e {
        PageErr::Bad(line) => plain(StatusCode::BAD_REQUEST, line),
        PageErr::NotFound(line) => plain(StatusCode::NOT_FOUND, line),
        PageErr::Failed(line) if json => plain(StatusCode::INTERNAL_SERVER_ERROR, line),
        PageErr::Failed(line) => typed(StatusCode::INTERNAL_SERVER_ERROR, "text/html; charset=utf-8", html::error(root, 500, line)),
    }
}

/// A request's query: each key once, its value percent-decoded (`+` a space) and valid UTF-8.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Query(BTreeMap<String, String>);

/// One hex digit's value.
fn hex(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// `%XX` and `+` decoded; `None` for a bad escape or bytes that are no UTF-8.
fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let (hi, lo) = (hex(*b.get(i + 1)?)?, hex(*b.get(i + 2)?)?);
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

impl Query {
    /// `None` (400) for a bad escape or a key given twice.
    pub(crate) fn parse(q: &str) -> Option<Query> {
        let mut map = BTreeMap::new();
        for pair in q.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if map.insert(decode(k)?, decode(v)?).is_some() {
                return None;
            }
        }
        Some(Query(map))
    }

    /// Every key is one of `allowed`.
    fn only(&self, allowed: &[&str]) -> bool {
        self.0.keys().all(|k| allowed.contains(&k.as_str()))
    }

    /// A key's value, an empty one as none.
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str).filter(|v| !v.is_empty())
    }

    /// `json=1`: the document; absent: the page; another value: `None` (400).
    fn json(&self) -> Option<bool> {
        match self.get("json") {
            None => Some(false),
            Some("1") => Some(true),
            Some(_) => None,
        }
    }
}

/// `f` on a blocking thread (the models read files): its result, or a 500 when it panicked.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, PageErr> + Send + 'static) -> Result<T, PageErr> {
    tokio::task::spawn_blocking(f).await.unwrap_or_else(|_| Err(PageErr::Failed("the page's model failed (logs/ai-env.log)".into())))
}

/// A document: pretty JSON as the CLI prints it.
fn json_doc<T: serde::Serialize>(value: &T) -> Response {
    match model::pretty(value) {
        Ok(text) => typed(StatusCode::OK, "application/json", text),
        Err(e) => page_error(TOP, &e, true),
    }
}

/// The request's answer: the guard, then the route.
async fn answer(shared: &Arc<Shared>, req: Request) -> Response {
    let (head, body) = req.into_parts();
    let header_of = |name: header::HeaderName| head.headers.get(name).and_then(|v| v.to_str().ok());
    let content_length = match head.headers.get(header::CONTENT_LENGTH) {
        None => None,
        Some(v) => match v.to_str().ok().and_then(|s| s.parse::<u64>().ok()) {
            Some(n) => Some(n),
            None => return refusal(StatusCode::BAD_REQUEST),
        },
    };
    let parts = Parts {
        method: &head.method,
        path: head.uri.path(),
        host: header_of(header::HOST),
        origin: header_of(header::ORIGIN),
        sec_fetch_site: header_of(header::HeaderName::from_static("sec-fetch-site")),
        content_type: header_of(header::CONTENT_TYPE),
        content_length,
    };
    let rest = match guard::judge(&parts, shared.port, &shared.bearer) {
        Verdict::Pass { rest } => rest,
        Verdict::Refuse(status) => return refusal(status),
    };
    let query = head.uri.query().unwrap_or_default();
    if head.method == Method::POST {
        if rest != "/actions" || !query.is_empty() {
            return refusal(StatusCode::NOT_FOUND);
        }
        let Ok(bytes) = axum::body::to_bytes(body, BODY_MAX).await else {
            return refusal(StatusCode::PAYLOAD_TOO_LARGE);
        };
        return post_actions(shared, &bytes);
    }
    let is_head = head.method == Method::HEAD;
    let resp = match Query::parse(query) {
        Some(q) => get(shared, &rest, &q, is_head).await,
        None => refusal(StatusCode::BAD_REQUEST),
    };
    if is_head {
        let (parts, _) = resp.into_parts();
        return Response::from_parts(parts, Body::empty());
    }
    resp
}

/// `POST actions` (form: `nonce`, `action`, `target`): 303 to `actions/<nonce>`; 400 a bad form; 403 the nonce;
/// 409 an action is running.
fn post_actions(shared: &Shared, body: &[u8]) -> Response {
    let Some(fields) = guard::form_fields(body) else {
        return refusal(StatusCode::BAD_REQUEST);
    };
    let field = |k: &str| fields.get(k).map(String::as_str).filter(|v| !v.is_empty());
    let (Some(nonce), Some(action), Some(target)) = (field("nonce"), field("action").and_then(Action::from_word), field("target")) else {
        return refusal(StatusCode::BAD_REQUEST);
    };
    if fields.len() != 3 {
        return refusal(StatusCode::BAD_REQUEST);
    }
    match actions::submit(shared, nonce, action, target) {
        Ok(()) => {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::SEE_OTHER;
            match HeaderValue::from_str(&format!("actions/{nonce}")) {
                Ok(v) => {
                    r.headers_mut().insert(header::LOCATION, v);
                    r
                }
                Err(_) => refusal(StatusCode::BAD_REQUEST),
            }
        }
        Err((status, line)) => plain(status, &line),
    }
}

/// The GET (and HEAD) routes.
async fn get(shared: &Arc<Shared>, rest: &str, q: &Query, head: bool) -> Response {
    let Some(json) = q.json() else {
        return refusal(StatusCode::BAD_REQUEST);
    };
    let paths = shared.paths.clone();
    let now = crate::bridge::lab::now();
    let below = |prefix: &str| rest.strip_prefix(prefix).filter(|id| !id.is_empty() && !id.contains('/')).map(str::to_string);
    match rest {
        "/" if q.only(&["json", "q"]) => {
            // S12 (T, §T3 U5): the search over names and ids; an empty `q` reads as none.
            let search = q.get("q").map(str::to_string);
            match blocking(move || model::sessions(&paths, now, search.as_deref())).await {
                Ok(m) if json => json_doc(&m.rows),
                Ok(m) => html_page(html::sessions(&m)),
                Err(e) => page_error(TOP, &e, json),
            }
        }
        "/vms" if q.only(&["json"]) => match blocking(move || model::vms(&paths, now)).await {
            Ok(s) if json => json_doc(&crate::bridge::vm::ops::survey_json(&s)),
            Ok(s) => html_page(html::vms(&s)),
            Err(e) => page_error(TOP, &e, json),
        },
        "/audit" if q.only(&["json", "event", "session", "vm"]) => {
            let args = model::audit_args(q.get("event"), q.get("session"), q.get("vm"));
            match blocking(move || model::audit(&paths, args, now)).await {
                Ok(m) if json => typed(StatusCode::OK, "application/x-ndjson", model::audit_ndjson(&m)),
                Ok(m) => html_page(html::audit(&m)),
                Err(e) => page_error(TOP, &e, json),
            }
        }
        "/cost" if q.only(&["json", "since"]) => {
            let since = q.get("since").map(str::to_string);
            match blocking(move || model::cost(&paths, since.as_deref(), now)).await {
                Ok(m) if json => json_doc(&m.estimate),
                Ok(m) => html_page(html::cost(&m)),
                Err(e) => page_error(TOP, &e, json),
            }
        }
        "/confirm" if q.only(&["json", "action", "target"]) => {
            let (Some(action), Some(target)) = (q.get("action").and_then(Action::from_word), q.get("target").map(str::to_string)) else {
                return refusal(StatusCode::BAD_REQUEST);
            };
            let checked = target.clone();
            match blocking(move || model::confirm(&paths, action, &checked)).await {
                Ok(mut c) => {
                    if !head {
                        c.nonce = Some(shared.nonces().issue(action, &target, crate::wire::time::unix_now()));
                    }
                    if json {
                        json_doc(&c)
                    } else {
                        html_page(html::confirm(&c))
                    }
                }
                Err(e) => page_error(TOP, &e, json),
            }
        }
        "/events" if q.only(&["event", "session", "vm"]) => {
            let args = model::audit_args(q.get("event"), q.get("session"), q.get("vm"));
            match blocking(move || model::filter_of(&paths, &args, now)).await {
                Ok(filter) => sse::open(shared, filter).unwrap_or_else(sse::busy),
                Err(e) => sse::refused(&e),
            }
        }
        "/assets/app.js" if q.only(&[]) => typed(StatusCode::OK, "text/javascript; charset=utf-8", APP_JS.to_string()),
        "/assets/app.css" if q.only(&[]) => typed(StatusCode::OK, "text/css; charset=utf-8", APP_CSS.to_string()),
        "/" | "/vms" | "/audit" | "/cost" | "/confirm" | "/events" | "/assets/app.js" | "/assets/app.css" => refusal(StatusCode::BAD_REQUEST),
        _ => {
            if !q.only(&["json"]) {
                return refusal(StatusCode::BAD_REQUEST);
            }
            if let Some(sid) = below("/session/") {
                return match blocking(move || model::session(&paths, &sid, now)).await {
                    Ok(v) if json => json_doc(&v),
                    Ok(v) => html_page(html::session(&v)),
                    Err(e) => page_error(BELOW, &e, json),
                };
            }
            if let Some(sid) = below("/settings/") {
                return match blocking(move || model::settings(&paths, &sid)).await {
                    Ok(m) if json => json_doc(&m.diff),
                    Ok(m) => html_page(html::settings(&m)),
                    Err(e) => page_error(BELOW, &e, json),
                };
            }
            if let Some(id) = below("/actions/") {
                let found = shared.board().get(&id).cloned();
                return match found {
                    Some(a) if json => json_doc(&a),
                    Some(a) => html_page(html::action(&a)),
                    None => plain(StatusCode::NOT_FOUND, "not found: no such action in this run"),
                };
            }
            refusal(StatusCode::NOT_FOUND)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_decode_and_refuse_twice_given_keys() {
        let q = Query::parse("event=vm_suspend%2Cvm_resume&session=&vm=microvm-a&json=1").unwrap();
        assert_eq!((q.get("event"), q.get("session"), q.get("vm"), q.json()), (Some("vm_suspend,vm_resume"), None, Some("microvm-a"), Some(true)));
        assert!(q.only(&["event", "session", "vm", "json"]) && !q.only(&["event"]));
        assert_eq!(Query::parse("").unwrap(), Query::default());
        assert_eq!(Query::parse("since=1+h").unwrap().get("since"), Some("1 h"));
        assert_eq!(Query::parse("json=2").unwrap().json(), None);
        for bad in ["a=1&a=2", "a=%zz", "a=%2", "a=%ff"] {
            assert_eq!(Query::parse(bad), None, "{bad}");
        }
    }
}
