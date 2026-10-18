//! Git smart-HTTP on the code port (S9 plan §1, L3, L4): `git http-backend`
//! as the agent, through the helper op `shim-io git-cgi`, upload-pack only.
//! Only literal routes exist (`wire::workspace::GIT_INFO_REFS_ROUTE` with the
//! query exactly `service=git-upload-pack`, and `GIT_UPLOAD_PACK_ROUTE`
//! without one); receive-pack in either form is 403 before any other check
//! and before any helper starts, and anything else under the repository is
//! 404 (`NO_SUCH_ROUTE`: a path the router does not know meets the ports'
//! fallback, a git route's other query this module's answer). Behind those,
//! in order (plans/s9-contracts.md §1.3): another method 405, a draining
//! shim 503, an unseeded VM 409 `not_seeded`, a `Git-Protocol` header outside
//! `GIT_PROTOCOLS` 400; a `POST` without its `Content-Length` (or chunked)
//! 411, over `GIT_REQUEST_MAX` 413, of another `Content-Type` or
//! `Content-Encoding` 400; past `GIT_CGI_MAX` runs 409 `busy` at once. The
//! helper's refusal is its own answer; a CGI head over `GIT_CGI_HEAD_MAX`,
//! unparseable, or whose `Status` is not 200 is 500 `git_failed` (a CGI 403
//! never reaches the Mac, which would re-mint on it). Otherwise the answer is
//! 200 with the CGI's `GIT_CGI_HEADERS` only, its body streamed chunked under
//! the route's deadline from the request's start (`budget::GIT_ADVERTISE`,
//! `budget::GIT_UPLOAD_PACK`) and `GIT_RESPONSE_MAX`; a helper that fails
//! after its head ends the stream with an error, so a cut pack never looks
//! complete (`asagent::AgentProc::into_stream`). No workspace lock: the CGI
//! only reads. Every argument the helper gets is non-secret (uid 1000 can
//! read them), and its CGI environment is an allowlist (`GIT_CGI_ENV`,
//! `wshelper::cgi_env`): never a bearer, a cookie or an `x-aws-*` header.
//!
//! The routes are mounted (`code::router`) and `CAP_GIT_HTTP_V1` named
//! (`ShimState::caps`) exactly when [`SERVED`] is true.
use crate::shim::asagent::{self, flag, AgentCmd, AgentProc, AgentProcError};
use crate::shim::code::{refuse_after_body, refuse_draining};
use crate::shim::health::ShimState;
use crate::shim::peer::Peer;
use crate::wire::workspace::{
    budget, refusal, GitCgiReply, WsRefusal, GIT_CGI_MAX, GIT_CONTENT_ENCODINGS, GIT_PATH_INFO_REFS, GIT_PATH_INFO_UPLOAD_PACK, GIT_PROTOCOLS, GIT_RECEIVE_PACK_QUERY, GIT_RECEIVE_PACK_REFUSAL, GIT_REQUEST_MAX, GIT_RESPONSE_MAX,
    GIT_UPLOAD_PACK_QUERY, GIT_UPLOAD_PACK_REQUEST_TYPE,
};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Whether this build serves the git routes (and names `git_http_v1`).
pub const SERVED: bool = true;

/// The helper op every git route starts (`wshelper::OPS`), and its log lines' name.
const OP: &str = "git-cgi";

/// The header of the protocol version a client asks (the CGI's `HTTP_GIT_PROTOCOL`).
const GIT_PROTOCOL: &str = "git-protocol";

/// The two requests that start the CGI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cgi {
    /// `GET …/info/refs?service=git-upload-pack`.
    Advertise,
    /// `POST …/git-upload-pack`.
    UploadPack,
}

impl Cgi {
    /// The whole stream's deadline, from the request's start.
    fn budget(self) -> Duration {
        match self {
            Cgi::Advertise => budget::GIT_ADVERTISE,
            Cgi::UploadPack => budget::GIT_UPLOAD_PACK,
        }
    }
}

/// `GET /workspace.git/info/refs?service=git-upload-pack`: the advertisement.
/// The same path with `GET ?service=git-receive-pack` is 403, with any other
/// query (or none) 404, and another method 405.
pub async fn info_refs(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let started = Instant::now();
    let get = req.method() == Method::GET;
    let query = req.uri().query();
    let (receive, literal) = (get && query == Some(GIT_RECEIVE_PACK_QUERY), query == Some(GIT_UPLOAD_PACK_QUERY));
    if receive {
        return receive_pack_refused(started, req).await;
    }
    if !literal {
        return no_such_route(started, req).await;
    }
    if !get {
        return not_allowed(started, req, "GET").await;
    }
    serve(&state, started, req, Cgi::Advertise).await
}

/// `POST /workspace.git/git-upload-pack`: one upload-pack request, its result
/// streamed. Any query (an empty `?` too: no request text but the literal
/// query reaches the helper's argv) is 404, another method 405.
pub async fn upload_pack(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let started = Instant::now();
    if req.uri().query().is_some() {
        return no_such_route(started, req).await;
    }
    if req.method() != Method::POST {
        return not_allowed(started, req, "POST").await;
    }
    serve(&state, started, req, Cgi::UploadPack).await
}

/// `/workspace.git/git-receive-pack`, any method (and `GET
/// …/info/refs?service=git-receive-pack`): 403 before any other check and
/// before any helper: the VM's repository is never written through the code port.
pub async fn receive_pack(State(_state): State<Arc<ShimState>>, req: Request) -> Response {
    receive_pack_refused(Instant::now(), req).await
}

/// §1.3's rows 6 to 15 for a request its route took (module doc).
async fn serve(state: &ShimState, started: Instant, req: Request, cgi: Cgi) -> Response {
    if state.is_draining() {
        return refuse_draining(OP, started, req, &AgentProcError::Draining.refusal(OP)).await;
    }
    let Some(record) = state.workspace.record() else {
        return refuse_draining(OP, started, req, &WsRefusal::new(refusal::NOT_SEEDED, "the VM was never seeded: it has no repository to fetch from")).await;
    };
    let Ok(protocol) = one_of(req.headers(), GIT_PROTOCOL, &GIT_PROTOCOLS) else {
        return refuse_draining(OP, started, req, &WsRefusal::new(refusal::BAD_REQUEST, "the Git-Protocol header is not one of version=0, version=1, version=2")).await;
    };
    let mut args = vec![flag("path", &record.path)];
    let mut len = 0;
    match cgi {
        Cgi::Advertise => args.extend([flag("method", "GET"), flag("path-info", GIT_PATH_INFO_REFS), flag("query", GIT_UPLOAD_PACK_QUERY)]),
        Cgi::UploadPack => {
            len = match crate::shim::code::content_length(&req, GIT_REQUEST_MAX) {
                Ok(len) => len,
                Err(stop) => {
                    crate::shim::peer::drain(req).await;
                    return stop.respond(OP, started);
                }
            };
            if !matches!(one_of(req.headers(), header::CONTENT_TYPE, &[GIT_UPLOAD_PACK_REQUEST_TYPE]), Ok(Some(_))) {
                let r = WsRefusal::new(refusal::BAD_REQUEST, &format!("the request's Content-Type is not exactly {GIT_UPLOAD_PACK_REQUEST_TYPE}"));
                return refuse_after_body(OP, started, req, len, &r).await;
            }
            let Ok(encoding) = one_of(req.headers(), header::CONTENT_ENCODING, &GIT_CONTENT_ENCODINGS) else {
                return refuse_after_body(OP, started, req, len, &WsRefusal::new(refusal::BAD_REQUEST, "the request's Content-Encoding is neither gzip nor x-gzip")).await;
            };
            args.extend([flag("method", "POST"), flag("path-info", GIT_PATH_INFO_UPLOAD_PACK), flag("content-type", GIT_UPLOAD_PACK_REQUEST_TYPE), flag("content-length", len.to_string())]);
            args.extend(encoding.map(|e| flag("content-encoding", e)));
        }
    }
    args.extend(protocol.map(|p| flag("git-protocol", p)));
    args.push(flag("remote-addr", remote_addr(&req).to_string()));
    let Some(slot) = state.workspace.try_cgi() else {
        let r = WsRefusal::new(refusal::BUSY, &format!("{GIT_CGI_MAX} git requests run already (at most {GIT_CGI_MAX} at once)"));
        return match cgi {
            Cgi::Advertise => refuse_draining(OP, started, req, &r).await,
            Cgi::UploadPack => refuse_after_body(OP, started, req, len, &r).await,
        };
    };
    let cmd = AgentCmd { op: OP, args, budget: cgi.budget().saturating_sub(started.elapsed()), stdin: cgi == Cgi::UploadPack, during_stop: false };
    let body = req.into_body();
    let mut proc = match AgentProc::start(state, cmd).await {
        Ok(p) => p,
        Err(e) => {
            // The body is read first (within its transfer time): the client reads the answer, not a reset.
            let _ = tokio::time::timeout(asagent::transfer(len), asagent::feed(body, None)).await;
            return asagent::refuse(OP, started, &e.refusal(OP));
        }
    };
    if let Some(stdin) = proc.take_stdin() {
        // A task of its own: the helper reads the body while its head and the CGI's are read here.
        // The body has its transfer time (as S8's routes give one): a stalled one closes the
        // helper's stdin, whose refusal of a short body (400) frees the slot.
        let until = proc.deadline().min(tokio::time::Instant::now() + asagent::transfer(len));
        tokio::spawn(async move {
            let _ = tokio::time::timeout_at(until, asagent::feed(body, Some(stdin))).await;
        });
    }
    let reply = match proc.head::<GitCgiReply>().await {
        Ok(head) => head.outcome(),
        Err(e) => {
            proc.stop().await;
            return asagent::refuse(OP, started, &e.refusal(OP));
        }
    };
    match reply {
        Some(Ok(_)) => {}
        Some(Err(r)) => {
            if let Err(e) = proc.finish().await {
                errln!("ai-env: workspace {OP} helper ended badly after its refusal: {}", e.refusal(OP).message);
            }
            return asagent::refuse(OP, started, &r);
        }
        None => {
            proc.stop().await;
            return asagent::refuse(OP, started, &AgentProcError::BadHead("neither a reply nor a refusal".into()).refusal(OP));
        }
    }
    let head = match proc.read_cgi_head().await {
        Ok(head) => head,
        Err(e) => {
            proc.stop().await;
            let r = match e {
                AgentProcError::BadHead(why) => WsRefusal::new(refusal::GIT_FAILED, &why),
                other => other.refusal(OP),
            };
            return asagent::refuse(OP, started, &r);
        }
    };
    asagent::log(OP, 200, None, started);
    let mut res = Response::new(proc.into_stream(GIT_RESPONSE_MAX, Some(slot)));
    for (name, value) in head.headers {
        res.headers_mut().insert(name, value);
    }
    res
}

/// 403 `GIT_RECEIVE_PACK_REFUSAL` (text), the body read first (bounded): the client reads the answer, not a reset.
async fn receive_pack_refused(started: Instant, req: Request) -> Response {
    crate::shim::peer::drain(req).await;
    asagent::log(OP, 403, None, started);
    (StatusCode::FORBIDDEN, GIT_RECEIVE_PACK_REFUSAL).into_response()
}

/// 404 `NO_SUCH_ROUTE`, the ports' fallback's answer (`auth::not_implemented`).
async fn no_such_route(started: Instant, req: Request) -> Response {
    let res = crate::shim::auth::not_implemented(req).await;
    asagent::log(OP, 404, None, started);
    res
}

/// 405 (`health::method_not_allowed`'s), naming the one method the route serves.
async fn not_allowed(started: Instant, req: Request, allow: &'static str) -> Response {
    let status = crate::shim::health::method_not_allowed(req).await;
    asagent::log(OP, status.as_u16(), None, started);
    let mut res = status.into_response();
    res.headers_mut().insert(header::ALLOW, HeaderValue::from_static(allow));
    res
}

/// The client's address, the CGI's `REMOTE_ADDR` (IPv4 when it is a mapped
/// one); the unspecified address on a router served without the
/// connection's facts.
fn remote_addr(req: &Request) -> IpAddr {
    req.extensions().get::<ConnectInfo<Peer>>().map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| crate::shim::peer::canonical(c.0.peer.ip()))
}

/// The value of the header `name`, which must be exactly one of `allowed`:
/// `Ok(None)` when it is absent, `Err` when it is another value or given twice.
fn one_of(headers: &HeaderMap, name: impl header::AsHeaderName, allowed: &[&'static str]) -> Result<Option<&'static str>, ()> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => allowed.iter().find(|a| v.as_bytes() == a.as_bytes()).map(|a| Some(*a)).ok_or(()),
        (Some(_), Some(_)) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shim::health::{ProbeSpec, ShimOpts};
    use crate::shim::state::RunRecord;
    use crate::shim::sys::RealSys;
    use crate::shim::wshelper::{cgi_env, git_cgi_here, GitCgiArgs};
    use crate::wire::frame::RunHookPayload;
    use crate::wire::redact::Secret;
    use crate::wire::workspace::{parse_head, HelperHead, ObjectFormat, SeedMode, SeedRecord, GIT_CGI_ENV, GIT_RECEIVE_PACK_ROUTE, GIT_UPLOAD_PACK_ROUTE, NO_SUCH_ROUTE};
    use std::net::SocketAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TOKEN: &str = "gitcgi-test-token";
    /// The helper's own head, as `git-cgi` writes it before the CGI's output.
    const HEAD: &str = r#"{"ok":true,"reply":{"object_format":"sha1","git_version":"2.50.1"}}"#;
    /// What http-backend answers for a v2 advertisement (an empty repository's, cut short).
    const ADVERTISEMENT: &[u8] = b"Expires: Fri, 01 Jan 1980 00:00:00 GMT\r\nPragma: no-cache\r\nCache-Control: no-cache, max-age=0, must-revalidate\r\nContent-Type: application/x-git-upload-pack-advertisement\r\n\r\n000eversion 2\n0000";
    const ADVERTISE: &str = "/workspace.git/info/refs?service=git-upload-pack";
    const POST_TYPE: &str = "Content-Type: application/x-git-upload-pack-request";
    /// One request of a table: its method, its target, its extra headers, its body (sent with its length).
    type Req<'a> = (&'a str, &'a str, &'a [&'a str], Option<&'a [u8]>);

    /// A code port on 127.0.0.1, `/run` committed to [`TOKEN`], whose helper
    /// is a script: each start appends its argv to `<dir>/starts`, waits for
    /// `<dir>/go` while `<dir>/hold` exists, prints [`HEAD`], then the bytes
    /// of `<dir>/cgi` (when there), and exits with the number in `<dir>/exit`
    /// (else 0). Seeded (a record at `/w`) unless `seeded` is false.
    struct Port {
        state: Arc<ShimState>,
        addr: SocketAddr,
        dir: PathBuf,
        _tmp: tempfile::TempDir,
    }

    async fn port(seeded: bool) -> Port {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        let d = dir.display();
        let script = dir.join("helper");
        let body = format!(
            "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\nprintf '%s\\n' \"$*\" >> '{d}/starts'\nif [ -e '{d}/hold' ]; then\n  while [ ! -e '{d}/go' ]; do sleep 0.05; done\nfi\nprintf '%s\\n' '{HEAD}'\n[ -e '{d}/cgi' ] && cat '{d}/cgi'\nexit \"$(cat '{d}/exit' 2>/dev/null || echo 0)\"\n"
        );
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        // macOS assesses a new executable at its first exec: once, outside every test's timing.
        let warmed = {
            let _fork = crate::test_locks::forking();
            std::process::Command::new(&script).arg("warm").status().unwrap()
        };
        assert!(warmed.success());
        let opts = ShimOpts { helper: Some(script), home: dir.clone(), ..ShimOpts::default() };
        let state = Arc::new(ShimState::with(PathBuf::from("/nonexistent/claude"), opts, ProbeSpec::default(), Arc::new(RealSys)));
        let payload = RunHookPayload::new(&Secret::new(TOKEN.to_string()), "mike@mbp", "2026-10-03T08:00:00Z");
        state.run.claim(&[1; 32], || RunRecord { microvm_id: None, payload: Some(payload), body_sha256: [1; 32], at: Instant::now(), boot_nonce: "0".repeat(32) });
        if seeded {
            let record = SeedRecord { path: "/w".into(), mode: SeedMode::Clone, branch: Some("main".into()), head: "a".repeat(40), wip: None, wip_tree: None, index_tree: None, object_format: ObjectFormat::Sha1, at: "2026-10-12T08:00:00Z".into() };
            state.workspace.set_record(record);
        }
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::shim::code::router(state.clone()).into_make_service_with_connect_info::<Peer>();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Port { state, addr, dir, _tmp: tmp }
    }

    impl Port {
        /// Each helper start's argv, in order.
        fn starts(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.join("starts")).unwrap_or_default().lines().map(str::to_string).collect()
        }

        /// What the helper prints after its head, and its exit.
        fn cgi(&self, out: &[u8], exit: u8) {
            std::fs::write(self.dir.join("cgi"), out).unwrap();
            std::fs::write(self.dir.join("exit"), exit.to_string()).unwrap();
        }

        async fn request(&self, method: &str, target: &str, headers: &[&str], body: Option<&[u8]>) -> (u16, String, Vec<u8>) {
            request(self.addr, TOKEN, method, target, headers, body).await
        }
    }

    /// One request (`Connection: close`; `body` with its `Content-Length`):
    /// the status, the head (lowercase) and the body's raw bytes.
    async fn request(addr: SocketAddr, token: &str, method: &str, target: &str, headers: &[&str], body: Option<&[u8]>) -> (u16, String, Vec<u8>) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut head = format!("{method} {target} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n");
        for h in headers {
            head.push_str(&format!("{h}\r\n"));
        }
        if let Some(b) = body {
            head.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        head.push_str("Connection: close\r\n\r\n");
        s.write_all(head.as_bytes()).await.unwrap();
        if let Some(b) = body {
            // A refusal may come before the whole body was read; what came back is still read.
            let _ = s.write_all(b).await;
        }
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut got)).await.expect("an answer within 30 s").unwrap();
        let end = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| panic!("no head in {:?}", String::from_utf8_lossy(&got))) + 4;
        let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
        let status = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap();
        (status, head, got[end..].to_vec())
    }

    /// A chunked body's bytes, and whether it ended with its last chunk.
    fn chunked(raw: &[u8]) -> (Vec<u8>, bool) {
        let (mut rest, mut body) = (raw, Vec::new());
        loop {
            let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") else { return (body, false) };
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..nl]).unwrap().trim(), 16).unwrap();
            rest = &rest[nl + 2..];
            if size == 0 {
                return (body, rest == b"\r\n");
            }
            if rest.len() < size + 2 {
                return (body, false);
            }
            body.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
    }

    fn refusal_of(body: &[u8]) -> WsRefusal {
        serde_json::from_slice(body).unwrap_or_else(|e| panic!("not a refusal ({e}): {}", String::from_utf8_lossy(body)))
    }

    /// Only the three literal routes exist: a trailing `/`, a `//`, a
    /// percent-encoded or `.`/`..` segment, a dumb path, another repository,
    /// a git route's query that is not its literal one (the POST's any query,
    /// an empty `?` included) are each 404 `NO_SUCH_ROUTE` (text), and no
    /// helper starts; another method on a git route is 405 naming its one
    /// method. The literal routes start the helper with exactly their flags.
    #[tokio::test]
    async fn routes_are_literal_traversal_404() {
        let p = port(true).await;
        p.cgi(ADVERTISEMENT, 0);
        let post: &[&str] = &[POST_TYPE];
        let cases: [Req<'_>; 31] = [
            ("GET", "/workspace.git/info/refs/?service=git-upload-pack", &[], None),
            ("GET", "/workspace.git/info/refs/", &[], None),
            ("GET", "//workspace.git/info/refs?service=git-upload-pack", &[], None),
            ("GET", "/workspace.git//info/refs?service=git-upload-pack", &[], None),
            ("GET", "/workspace.git/info/%72efs?service=git-upload-pack", &[], None),
            ("GET", "/workspace.git/info%2Frefs?service=git-upload-pack", &[], None),
            ("GET", "/workspace.git/./info/refs?service=git-upload-pack", &[], None),
            ("GET", "/workspace.git/x/../info/refs?service=git-upload-pack", &[], None),
            ("GET", "/workspace.git/%2e%2e/workspace.git/info/refs?service=git-upload-pack", &[], None),
            ("GET", "/x/../workspace.git/info/refs?service=git-upload-pack", &[], None),
            ("GET", "/workspace.git/HEAD", &[], None),
            ("GET", "/workspace.git/objects/info/packs", &[], None),
            ("GET", "/workspace.git/objects/info/alternates", &[], None),
            ("GET", "/workspace.git/objects/12/34567890abcdef1234567890abcdef12345678", &[], None),
            ("GET", "/workspace.git/config", &[], None),
            ("GET", "/workspace.git", &[], None),
            ("GET", "/workspace.git/", &[], None),
            ("GET", "/other.git/info/refs?service=git-upload-pack", &[], None),
            ("GET", "/Workspace.git/info/refs?service=git-upload-pack", &[], None),
            ("GET", "/workspace.git/info/refs", &[], None),
            ("GET", "/workspace.git/info/refs?", &[], None),
            ("GET", "/workspace.git/info/refs?service=git-upload-pack&x=1", &[], None),
            ("GET", "/workspace.git/info/refs?x=1&service=git-upload-pack", &[], None),
            ("GET", "/workspace.git/info/refs?service=GIT-UPLOAD-PACK", &[], None),
            ("GET", "/workspace.git/info/refs?service=git%2Dupload-pack", &[], None),
            ("PUT", "/workspace.git/info/refs?service=git-receive-pack", &[], Some(b"x")),
            ("POST", "/workspace.git/git-upload-pack?service=git-upload-pack", post, Some(b"0000")),
            ("POST", "/workspace.git/git-upload-pack?", post, Some(b"0000")),
            ("POST", "/workspace.git/git-upload-pack/", post, Some(b"0000")),
            ("POST", "/workspace.git/git-upload-pack/../git-upload-pack", post, Some(b"0000")),
            ("GET", "/workspace.git/git-upload-pack?x", &[], None),
        ];
        for (method, target, headers, body) in cases {
            let (st, head, got) = p.request(method, target, headers, body).await;
            assert_eq!((st, got.as_slice()), (404, NO_SUCH_ROUTE.as_bytes()), "{method} {target}: {head}");
            assert!(head.contains("content-type: text/plain"), "{method} {target}: {head}");
        }
        assert!(p.starts().is_empty(), "no helper started: {:?}", p.starts());
        for (method, target, allow) in [("PUT", ADVERTISE, "GET"), ("POST", ADVERTISE, "GET"), ("HEAD", ADVERTISE, "GET"), ("GET", GIT_UPLOAD_PACK_ROUTE, "POST"), ("DELETE", GIT_UPLOAD_PACK_ROUTE, "POST")] {
            let (st, head, _) = p.request(method, target, &[], Some(b"")).await;
            assert!(st == 405 && head.contains(&format!("\r\nallow: {}", allow.to_ascii_lowercase())), "{method} {target}: {head}");
        }
        assert!(p.starts().is_empty(), "no helper started: {:?}", p.starts());
        let (st, head, raw) = p.request("GET", ADVERTISE, &["Git-Protocol: version=2"], None).await;
        assert_eq!(st, 200, "{head}");
        assert_eq!(chunked(&raw), (b"000eversion 2\n0000".to_vec(), true));
        let (st, head, _) = p.request("POST", GIT_UPLOAD_PACK_ROUTE, &[POST_TYPE, "Content-Encoding: gzip"], Some(b"0000")).await;
        assert_eq!(st, 200, "{head}");
        let starts = p.starts();
        assert_eq!(starts.len(), 2, "{starts:?}");
        let flags = |start: &str| start.split(' ').skip_while(|w| *w != OP).skip(1).filter(|w| !w.starts_with("--budget-ms=")).map(str::to_string).collect::<Vec<_>>();
        assert_eq!(flags(&starts[0]), ["--path=/w", "--method=GET", "--path-info=/info/refs", "--query=service=git-upload-pack", "--git-protocol=version=2", "--remote-addr=127.0.0.1"]);
        assert_eq!(
            flags(&starts[1]),
            ["--path=/w", "--method=POST", "--path-info=/git-upload-pack", "--content-type=application/x-git-upload-pack-request", "--content-length=4", "--content-encoding=gzip", "--remote-addr=127.0.0.1"]
        );
    }

    /// receive-pack in either form is 403 (text) before any other check and
    /// before any helper starts: a push's body read first, on a VM never
    /// seeded and on a stopping shim alike; the bearer still comes first.
    #[tokio::test]
    async fn receive_pack_403_before_any_helper() {
        let p = port(false).await;
        let pack = vec![b'p'; 48 * 1024];
        let receive: &[&str] = &["Content-Type: application/x-git-receive-pack-request"];
        let cases: [(&str, &str, Option<&[u8]>); 6] = [
            ("POST", GIT_RECEIVE_PACK_ROUTE, Some(&pack)),
            ("GET", GIT_RECEIVE_PACK_ROUTE, None),
            ("PUT", GIT_RECEIVE_PACK_ROUTE, Some(b"x")),
            ("DELETE", GIT_RECEIVE_PACK_ROUTE, None),
            ("POST", "/workspace.git/git-receive-pack?service=git-receive-pack", Some(&pack)),
            ("GET", "/workspace.git/info/refs?service=git-receive-pack", None),
        ];
        for round in ["unseeded", "draining"] {
            for (method, target, body) in cases {
                let (st, head, got) = p.request(method, target, receive, body).await;
                assert_eq!((st, got.as_slice()), (403, GIT_RECEIVE_PACK_REFUSAL.as_bytes()), "{round}: {method} {target}: {head}");
                assert!(head.contains("content-type: text/plain"), "{head}");
            }
            p.state.set_draining();
        }
        let (st, _, got) = p.request("GET", ADVERTISE, &[], None).await;
        assert_eq!((st, refusal_of(&got).code.as_str()), (503, refusal::DRAINING), "upload-pack meets the stop");
        let (st, _, _) = request(p.addr, "not-the-token", "POST", GIT_RECEIVE_PACK_ROUTE, receive, Some(b"x")).await;
        assert_eq!(st, 401, "the bearer first");
        assert!(p.starts().is_empty(), "no helper started: {:?}", p.starts());
    }

    /// The real git, the first in an absolute `PATH` entry, else `/usr/bin/git`.
    fn real_git() -> PathBuf {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .filter(|d| d.is_absolute())
            .map(|d| d.join("git"))
            .chain(std::iter::once(PathBuf::from("/usr/bin/git")))
            .find(|g| std::fs::metadata(g).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
            .expect("a git")
    }

    /// `git <args>` in `dir`, no user or system config, one author at one date.
    fn git(dir: &Path, args: &[&str]) {
        let out = {
            let _fork = crate::test_locks::forking();
            std::process::Command::new(real_git())
                .args(args)
                .current_dir(dir)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", dir)
                .env("LC_ALL", "C")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
                .env("GIT_AUTHOR_DATE", "2026-10-12T08:00:00Z")
                .env("GIT_COMMITTER_DATE", "2026-10-12T08:00:00Z")
                .output()
                .unwrap()
        };
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// One call of the fake git (`FAKE_GIT_ENV_ALL=1`): its uid, every name it started with, its arguments.
    struct Call {
        uid: u32,
        names: Vec<String>,
        args: Vec<String>,
    }

    fn calls(log: &Path) -> Vec<Call> {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        text.lines()
            .map(|l| {
                let mut f = l.split('\t');
                let uid = f.next().and_then(|u| u.strip_prefix("uid=")).and_then(|u| u.parse().ok()).unwrap_or_else(|| panic!("no uid in {l}"));
                let env = f.next().and_then(|e| e.strip_prefix("env=")).unwrap_or_else(|| panic!("no env in {l}"));
                let _fds = f.next();
                Call { uid, names: env.split(',').filter(|n| *n != "-").map(str::to_string).collect(), args: f.map(str::to_string).collect() }
            })
            .collect()
    }

    /// The environment http-backend starts with is `GitRun::vm`'s five names
    /// and exactly the `GIT_CGI_ENV` names the request sets (a `GET` has no
    /// `CONTENT_TYPE` or `CONTENT_LENGTH`, a `POST` both, its `QUERY_STRING`
    /// empty): never a bearer, a cookie, a remote user, an `x-aws-*` header
    /// or a config carrier; it runs as the helper's uid (the agent's: here
    /// this test's), after gitrun's overrides and the CGI's own. The helper's
    /// side (`git-cgi`) is driven in this process with the fake git, which
    /// logs every name each call started with; the real git answers.
    #[test]
    fn the_cgi_env_is_an_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let (home, log, fake) = (root.join("home"), root.join("git.log"), root.join("vm-git"));
        let ws = home.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        git(&ws, &["init", "-q", "-b", "main"]);
        std::fs::write(ws.join("a.txt"), "one\n").unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "c1"]);
        std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/git.sh"), &fake).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Its first exec (macOS assesses a new executable), before its knobs: it logs nothing then.
        {
            let _fork = crate::test_locks::forking();
            let _ = std::process::Command::new(&fake).arg("--version").env_clear().output().unwrap();
        }
        std::fs::write(root.join("vm-git.knobs"), format!("export GIT_REAL='{}'\nexport GIT_ARGV_LOG='{}'\nexport FAKE_GIT_ENV_ALL='1'\n", real_git().display(), log.display())).unwrap();
        let path = ws.to_str().unwrap().to_string();
        let get = GitCgiArgs {
            path: path.clone(),
            method: "GET".into(),
            path_info: GIT_PATH_INFO_REFS.into(),
            query: Some(GIT_UPLOAD_PACK_QUERY.into()),
            content_type: None,
            content_length: None,
            content_encoding: None,
            git_protocol: Some("version=2".into()),
            remote_addr: "10.0.0.1".into(),
        };
        let ls_refs = b"0014command=ls-refs\n00010000";
        let post = GitCgiArgs {
            method: "POST".into(),
            path_info: GIT_PATH_INFO_UPLOAD_PACK.into(),
            query: None,
            content_type: Some(GIT_UPLOAD_PACK_REQUEST_TYPE.into()),
            content_length: Some(ls_refs.len() as u64),
            ..get.clone()
        };
        for (a, body, want) in [(&get, &b""[..], "version 2"), (&post, &ls_refs[..], "refs/heads/main")] {
            let (out, done) = git_cgi_here(&home, &fake, a, body);
            done.unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out)));
            let nl = out.iter().position(|b| *b == b'\n').unwrap();
            let head: HelperHead<GitCgiReply> = parse_head(&out[..nl]).unwrap();
            let reply = head.reply.expect("a reply");
            assert!(reply.object_format == ObjectFormat::Sha1 && !reply.git_version.is_empty(), "{reply:?}");
            let cgi = String::from_utf8_lossy(&out[nl + 1..]);
            assert!(cgi.contains("Content-Type: application/x-git-upload-pack-") && cgi.contains(want) && !cgi.contains("Status:"), "{cgi}");
        }
        let all = calls(&log);
        let backend: Vec<&Call> = all.iter().filter(|c| c.args.last().map(String::as_str) == Some("http-backend")).collect();
        assert_eq!(backend.len(), 2, "{:?}", all.iter().map(|c| &c.args).collect::<Vec<_>>());
        let vm = ["GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "HOME", "LC_ALL", "PATH"];
        let sorted = |extra: &[&str]| {
            let mut names: Vec<String> = vm.iter().chain(extra).map(|n| (*n).to_string()).collect();
            names.sort();
            names
        };
        let get_names = ["GIT_PROJECT_ROOT", "GIT_HTTP_EXPORT_ALL", "PATH_INFO", "REQUEST_METHOD", "QUERY_STRING", "HTTP_GIT_PROTOCOL", "REMOTE_ADDR"];
        assert_eq!(backend[0].names, sorted(&get_names), "a GET's");
        let post_names: Vec<&str> = get_names.iter().copied().chain(["CONTENT_TYPE", "CONTENT_LENGTH"]).collect();
        assert_eq!(backend[1].names, sorted(&post_names), "a POST's");
        // SAFETY: a plain getter.
        let uid = unsafe { libc::geteuid() };
        let overrides = ["-c", "http.receivepack=false", "-c", "http.getanyfile=false", "-c", "http.uploadpack=true", "http-backend"];
        for c in &backend {
            assert_eq!(c.uid, uid, "the helper's uid");
            assert!(c.names.iter().filter(|n| !vm.contains(&n.as_str())).all(|n| GIT_CGI_ENV.contains(&n.as_str())), "{:?}", c.names);
            assert_eq!(c.args[c.args.len() - overrides.len()..], overrides, "{:?}", c.args);
            assert_eq!(c.args[..2], ["-c", crate::gitrun::OVERRIDES[0]], "gitrun's overrides first: {:?}", c.args);
        }
        for c in &all {
            let carrier = |n: &String| ["HTTP_AUTHORIZATION", "REMOTE_USER", "HTTP_COOKIE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"].contains(&n.as_str()) || n.starts_with("GIT_CONFIG_KEY_") || n.starts_with("GIT_CONFIG_VALUE_") || n.starts_with("HTTP_X_AWS");
            assert!(!c.names.iter().any(carrier) && !c.args.iter().any(|a| a.contains("://")), "{:?} {:?}", c.names, c.args);
        }
        // The builder alone: what each request sets, all `GIT_CGI_ENV`'s.
        let names = |a: &GitCgiArgs| cgi_env(a, Path::new("/w/.git")).into_iter().map(|(n, _)| n).collect::<Vec<_>>();
        let gzip = GitCgiArgs { content_encoding: Some("gzip".into()), git_protocol: None, ..post.clone() };
        assert_eq!(names(&gzip), ["GIT_PROJECT_ROOT", "GIT_HTTP_EXPORT_ALL", "PATH_INFO", "REQUEST_METHOD", "QUERY_STRING", "CONTENT_TYPE", "CONTENT_LENGTH", "HTTP_CONTENT_ENCODING", "REMOTE_ADDR"]);
        for a in [&get, &post, &gzip] {
            assert!(names(a).iter().all(|n| GIT_CGI_ENV.contains(n)), "{:?}", names(a));
        }
        let query = cgi_env(&post, Path::new("/w/.git")).into_iter().find(|(n, _)| *n == "QUERY_STRING").map(|(_, v)| v);
        assert_eq!(query.as_deref(), Some(std::ffi::OsStr::new("")), "a POST's query is empty: no request text reaches it");
    }

    /// The CGI's head passes `Content-Type`, `Cache-Control`, `Expires` and
    /// `Pragma` only, its body chunked; a head whose `Status` is not 200 (a
    /// CGI 403 never reaches the Mac), one over `GIT_CGI_HEAD_MAX`, one that
    /// does not parse, and a helper that ends before its head are each 500
    /// `git_failed`.
    #[tokio::test]
    async fn cgi_heads_pass_allowed_headers_only() {
        let p = port(true).await;
        p.cgi(b"Expires: Fri, 01 Jan 1980 00:00:00 GMT\r\nPragma: no-cache\r\nCache-Control: no-cache, max-age=0, must-revalidate\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nSet-Cookie: session=x\r\nLocation: http://example.invalid/\r\nContent-Length: 3\r\nTransfer-Encoding: identity\r\nConnection: keep-alive\r\nX-Aws-Proxy-Auth: no\r\nStatus: 200 OK\r\n\r\n000eversion 2\n0000", 0);
        let (st, head, raw) = p.request("GET", ADVERTISE, &[], None).await;
        assert_eq!(st, 200, "{head}");
        for kept in ["\r\nexpires: fri, 01 jan 1980 00:00:00 gmt\r\n", "\r\npragma: no-cache\r\n", "\r\ncache-control: no-cache, max-age=0, must-revalidate\r\n", "\r\ncontent-type: application/x-git-upload-pack-advertisement\r\n", "\r\ntransfer-encoding: chunked\r\n"] {
            assert!(head.contains(kept), "{kept:?} in {head}");
        }
        for dropped in ["set-cookie", "location", "content-length", "x-aws-proxy-auth", "identity", "keep-alive", "status"] {
            assert!(!head.contains(dropped), "{dropped} in {head}");
        }
        assert_eq!(chunked(&raw), (b"000eversion 2\n0000".to_vec(), true));
        let pad = format!("X-Pad: {}\r\n", "p".repeat(1000)).repeat(17);
        let refused: [(&[u8], u8); 9] = [
            (b"Status: 403 Forbidden\r\nContent-Type: text/plain\r\n\r\ndenied", 0),
            (b"Status: 404 Not Found\r\n\r\n", 0),
            (b"Status: 500 Internal Server Error\r\nExpires: Fri, 01 Jan 1980 00:00:00 GMT\r\n\r\n", 0),
            (b"Content-Type: application/x-git-upload-pack-advertisement\r\nnot a header\r\n\r\n", 0),
            (b"Content-Type: a\x01b\r\n\r\n", 0),
            (pad.as_bytes(), 0),
            (b"Content-Type: application/x-git-upload-pack-advertisement\r\n", 0),
            (b"", 1),
            (b"Content-Type: application/x-git-upload-pack-advertisement\r\n", 128),
        ];
        for (cgi, exit) in refused {
            p.cgi(cgi, exit);
            let (st, _, got) = p.request("GET", ADVERTISE, &[], None).await;
            let r = refusal_of(&got);
            assert_eq!((st, r.code.as_str()), (500, refusal::GIT_FAILED), "{}: {r:?}", String::from_utf8_lossy(&cgi[..cgi.len().min(60)]));
        }
    }

    /// At most `GIT_CGI_MAX` CGI runs at once: with two under way a third is
    /// 409 `busy` at once (a `Retry-After`, no wait, no helper), a POST's body
    /// read first; once they end, the slots are free again.
    #[tokio::test]
    async fn a_third_cgi_run_is_409_busy_at_once() {
        let p = port(true).await;
        p.cgi(ADVERTISEMENT, 0);
        std::fs::write(p.dir.join("hold"), "").unwrap();
        let addr = p.addr;
        let held: Vec<_> = (0..GIT_CGI_MAX).map(|_| tokio::spawn(async move { request(addr, TOKEN, "GET", ADVERTISE, &[], None).await })).collect();
        let until = Instant::now() + Duration::from_secs(10);
        while p.starts().len() < GIT_CGI_MAX {
            assert!(Instant::now() < until, "the two runs never started: {:?}", p.starts());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        for (method, target, headers, body) in [("GET", ADVERTISE, &[][..], None), ("POST", GIT_UPLOAD_PACK_ROUTE, &[POST_TYPE][..], Some(&[b'0'; 4000][..]))] {
            let t = Instant::now();
            let (st, head, got) = p.request(method, target, headers, body).await;
            assert_eq!((st, refusal_of(&got).code.as_str()), (409, refusal::BUSY), "{method}: {head}");
            assert!(head.contains("\r\nretry-after: 5\r\n"), "{head}");
            assert!(t.elapsed() < Duration::from_secs(2), "at once: {:?}", t.elapsed());
        }
        assert_eq!(p.starts().len(), GIT_CGI_MAX, "the third started no helper");
        std::fs::write(p.dir.join("go"), "").unwrap();
        for h in held {
            let (st, head, raw) = h.await.unwrap();
            assert_eq!(st, 200, "{head}");
            assert_eq!(chunked(&raw), (b"000eversion 2\n0000".to_vec(), true));
        }
        let (st, head, _) = p.request("GET", ADVERTISE, &[], None).await;
        assert_eq!(st, 200, "the slots are free again: {head}");
    }

    /// The request's own checks, in §1.3's order, each before any helper: an
    /// unseeded VM 409; a `Git-Protocol` outside the three versions 400; a
    /// POST without its length 411, over `GIT_REQUEST_MAX` 413 with the size,
    /// of another type or encoding 400; a helper that cannot start 500.
    #[tokio::test]
    async fn the_requests_checks_come_before_any_helper() {
        let unseeded = port(false).await;
        for (method, target, headers, body) in [("GET", ADVERTISE, &[][..], None), ("POST", GIT_UPLOAD_PACK_ROUTE, &[POST_TYPE][..], Some(&b"0000"[..]))] {
            let (st, _, got) = unseeded.request(method, target, headers, body).await;
            assert_eq!((st, refusal_of(&got).code.as_str()), (409, refusal::NOT_SEEDED), "{method}");
        }
        assert!(unseeded.starts().is_empty());
        let p = port(true).await;
        let cases: [(Req<'_>, u16); 8] = [
            (("GET", ADVERTISE, &["Git-Protocol: version=3"], None), 400),
            (("GET", ADVERTISE, &["Git-Protocol: version=2", "Git-Protocol: version=2"], None), 400),
            (("POST", GIT_UPLOAD_PACK_ROUTE, &[POST_TYPE, "Git-Protocol: version=2:object-format=sha1"], Some(b"0000")), 400),
            (("POST", GIT_UPLOAD_PACK_ROUTE, &[POST_TYPE], None), 411),
            (("POST", GIT_UPLOAD_PACK_ROUTE, &["Content-Type: application/x-git-upload-pack-request; charset=utf-8"], Some(b"0000")), 400),
            (("POST", GIT_UPLOAD_PACK_ROUTE, &["Content-Type: application/x-git-receive-pack-request"], Some(b"0000")), 400),
            (("POST", GIT_UPLOAD_PACK_ROUTE, &[POST_TYPE, "Content-Encoding: br"], Some(b"0000")), 400),
            (("POST", GIT_UPLOAD_PACK_ROUTE, &[POST_TYPE, "Content-Encoding: gzip", "Content-Encoding: gzip"], Some(b"0000")), 400),
        ];
        for ((method, target, headers, body), want) in cases {
            let (st, _, got) = p.request(method, target, headers, body).await;
            let r = refusal_of(&got);
            assert_eq!((st, r.code.as_str()), (want, refusal::BAD_REQUEST), "{headers:?}: {r:?}");
        }
        // Over the cap: refused on its length, the client's write side shut (the drain reads no more than it sends).
        let mut s = tokio::net::TcpStream::connect(p.addr).await.unwrap();
        let head = format!("POST {GIT_UPLOAD_PACK_ROUTE} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\n{POST_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n0000", GIT_REQUEST_MAX + 1);
        s.write_all(head.as_bytes()).await.unwrap();
        s.shutdown().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut got)).await.expect("an answer within 30 s");
        let end = got.windows(4).position(|w| w == b"\r\n\r\n").expect("a head") + 4;
        let r = refusal_of(&got[end..]);
        assert!(got.starts_with(b"HTTP/1.1 413") && r.code == refusal::TOO_LARGE && r.size == Some(GIT_REQUEST_MAX + 1), "{r:?}");
        assert!(p.starts().is_empty(), "no helper started: {:?}", p.starts());
        std::fs::remove_file(p.state.opts.helper.as_ref().unwrap()).unwrap();
        let (st, _, got) = p.request("POST", GIT_UPLOAD_PACK_ROUTE, &[POST_TYPE], Some(&[b'0'; 4000])).await;
        assert_eq!((st, refusal_of(&got).code.as_str()), (500, refusal::GIT_FAILED), "a helper that cannot start: the body read, then refused");
    }
}
