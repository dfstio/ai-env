//! tests/workspace.rs area: the data plane's HTTP client (`dataplane::
//! HttpsEndpoint`, plan §10) against an in-test server through the lab's
//! plain-http client (the agent-address knob with the fake API): the
//! endpoint's headers and Host, the query form-encoded, a body streamed with
//! its `Content-Length`, each status as the reply its verdict reads, a
//! code-out's manifest line split from its pack (never past the cap), a
//! redirect refused.
use super::fixture::{framed, target};
use ai_env_cli::bridge::api::{AuthToken, TOKEN_HEADER};
use ai_env_cli::bridge::dataplane::{verdict, DataPlane, HttpsEndpoint, Verdict};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::lab::VmKnobs;
use ai_env_cli::bridge::workspace::KeptReason;
use ai_env_cli::errors::CliError;
use ai_env_cli::wire::redact::Secret;
use ai_env_cli::wire::workspace::{refusal, CodeoutManifest, CodeoutRequest, ObjectFormat, SeedApplied, SeedManifest, SeedMode, SeedQuery, SeedReply, SeedState, WsRefusal};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One request as the server read it.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// One scripted answer.
struct Answer {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

fn answer(status: u16, body: impl Into<Vec<u8>>) -> Answer {
    Answer { status, headers: Vec::new(), body: body.into() }
}

/// A loopback server answering its script in order, one request per connection.
struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    async fn start(script: Vec<Answer>) -> Server {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Mutex::new(VecDeque::from(script)));
        let s = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let (seen, script) = (s.clone(), script.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 65536];
                    let end = loop {
                        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break end;
                        }
                        let n = conn.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    let mut lines = head.split("\r\n");
                    let mut first = lines.next().unwrap().split(' ');
                    let (method, target) = (first.next().unwrap().to_string(), first.next().unwrap().to_string());
                    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
                    let len: usize = headers.iter().find(|(k, _)| k == "content-length").map_or(0, |(_, v)| v.parse().unwrap());
                    let mut body = buf[end + 4..].to_vec();
                    while body.len() < len {
                        let n = conn.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&chunk[..n]);
                    }
                    seen.lock().unwrap().push(Seen { method, target, headers, body });
                    let a = script.lock().unwrap().pop_front().unwrap_or_else(|| answer(500, "no script left"));
                    let mut out = format!("HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: close\r\n", a.status, a.body.len());
                    for (k, v) in &a.headers {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                    out.push_str("\r\n");
                    let _ = conn.write_all(out.as_bytes()).await;
                    let _ = conn.write_all(&a.body).await;
                    let _ = conn.shutdown().await;
                });
            }
        });
        Server { addr, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// The data plane in the lab: plain http to this server, the endpoint's host resolved to it.
    fn dp(&self) -> HttpsEndpoint {
        HttpsEndpoint::new(&VmKnobs { fake_api: Some("/nonexistent/fake.json".into()), agent_addr: Some(self.addr.to_string()), ..VmKnobs::default() }).unwrap()
    }
}

fn token(port: u16) -> AuthToken {
    AuthToken { headers: BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new("proxy-token-value".into()))]), port, expires_at_unix: u64::MAX }
}

const H: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";

#[tokio::test]
async fn requests_carry_the_endpoints_headers_and_the_query_form_encoded() {
    let state = SeedState { tip: Some(H.into()), clean: true, ..SeedState::default() };
    let server = Server::start(vec![answer(200, serde_json::to_vec(&state).unwrap())]).await;
    let target = target();
    let path = "/Users/mike/\u{0419}\u{043e}\u{0433}\u{0430} x&y=z";
    let reply = server.dp().seed_state(&target, &token(9418), path).await.unwrap();
    assert_eq!((reply.status, reply.body), (200, Some(state)));
    let seen = &server.seen()[0];
    assert_eq!((seen.method.as_str(), seen.target.as_str()), ("GET", "/seed?path=%2FUsers%2Fmike%2F%D0%99%D0%BE%D0%B3%D0%B0+x%26y%3Dz"));
    assert_eq!(seen.header("host"), Some(target.endpoint.as_str()), "the endpoint's Host, through the lab's address");
    assert_eq!(seen.header("x-aws-proxy-auth"), Some("proxy-token-value"));
    assert_eq!(seen.header("x-aws-proxy-port"), Some("9418"));
    assert_eq!(seen.header("authorization").map(str::to_string), Some(format!("Bearer {}", "s".repeat(64))));
}

/// A seed's body goes up streamed from its file, with its `Content-Length`
/// (never chunked), and the 201 comes back parsed.
#[tokio::test]
async fn a_seed_body_streams_with_its_content_length() {
    let reply = SeedReply { outcome: SeedApplied::Cloned, head: H.into(), branch: Some("main".into()), wip: None, index: None, ms: 7 };
    let server = Server::start(vec![answer(201, serde_json::to_vec(&reply).unwrap())]).await;
    let dir = tempfile::tempdir().unwrap();
    let manifest = SeedManifest { v: 1, object_format: ObjectFormat::Sha1, branch: Some("main".into()), detached: false, head: H.into(), wip: None, index: None, shallow: vec![H.into()], refs: BTreeMap::new() };
    let pack: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let body = framed(&manifest, &pack);
    let file = dir.path().join("seed.body");
    std::fs::write(&file, &body).unwrap();
    let q = SeedQuery { path: "/Users/mike/w".into(), mode: SeedMode::Clone, branch: Some("main".into()), detached: false, expect: None };
    let got = server.dp().put_seed(&target(), &token(9418), &q, &file, body.len() as u64).await.unwrap();
    assert_eq!((got.status, got.body), (201, Some(reply)));
    let seen = &server.seen()[0];
    assert_eq!((seen.method.as_str(), seen.target.as_str()), ("PUT", "/seed?path=%2FUsers%2Fmike%2Fw&mode=clone&branch=main"));
    assert_eq!(seen.header("content-length"), Some(body.len().to_string().as_str()));
    assert_eq!(seen.header("transfer-encoding"), None, "never chunked");
    assert!(seen.body == body, "the bytes, in order");
    // A query the wire refuses is never sent.
    let bad = SeedQuery { expect: Some(H.into()), ..q };
    assert!(matches!(server.dp().put_seed(&target(), &token(9418), &bad, &file, 1).await, Err(BridgeError::Config(_))));
    assert_eq!(server.seen().len(), 1);
}

/// Each status comes back as a reply whose verdict acts on it: a refusal
/// parsed (its state, its size), the proxy's error and `Retry-After` kept.
#[tokio::test]
async fn statuses_come_back_as_replies_their_verdicts_read() {
    let vm_state = SeedState { tip: Some(H.into()), ..SeedState::default() };
    let dirty = WsRefusal::new(refusal::DIRTY, "changes of its own").with_state(vm_state.clone());
    let script = vec![
        answer(409, serde_json::to_vec(&dirty).unwrap()),
        Answer { status: 403, headers: vec![("x-aws-proxy-error", "UNAUTHORIZED".into())], body: Vec::new() },
        Answer { status: 429, headers: vec![("retry-after", "2".into())], body: Vec::new() },
        answer(404, ai_env_cli::wire::workspace::NO_SUCH_ROUTE),
        answer(503, serde_json::to_vec(&WsRefusal::new(refusal::DRAINING, "suspending")).unwrap()),
        answer(413, serde_json::to_vec(&WsRefusal::new(refusal::TOO_LARGE, "big").with_size(99)).unwrap()),
    ];
    let server = Server::start(script).await;
    let (dp, t) = (server.dp(), target());
    let r = dp.seed_state(&t, &token(9418), "/w").await.unwrap();
    assert_eq!((r.status, r.refusal.as_ref().and_then(|x| x.state.clone())), (409, Some(vm_state)));
    assert!(matches!(verdict("GET /seed", 9418, &r), Verdict::Kept { reason: KeptReason::Dirty, .. }));
    let r = dp.seed_state(&t, &token(9418), "/w").await.unwrap();
    assert_eq!((r.status, r.proxy_error.as_deref()), (403, Some("UNAUTHORIZED")));
    assert!(matches!(verdict("GET /seed", 9418, &r), Verdict::Remint { .. }));
    let r = dp.seed_state(&t, &token(9418), "/w").await.unwrap();
    assert_eq!((r.status, r.retry_after_s), (429, Some(2)));
    let r = dp.seed_state(&t, &token(9418), "/w").await.unwrap();
    match verdict("GET /seed", 9418, &r) {
        Verdict::Fail(e) => assert_eq!(CliError::from(e).exit_code(), 7, "an image without workspace_v1"),
        other => panic!("{other:?}"),
    }
    let r = dp.seed_state(&t, &token(9418), "/w").await.unwrap();
    assert_eq!(r.refusal.map(|x| x.code), Some(refusal::DRAINING.to_string()));
    let r = dp.transcript_stat(&t, &token(8080), "-w/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl").await.unwrap();
    assert_eq!((r.status, r.refusal.and_then(|x| x.size)), (413, Some(99)));
    assert_eq!(server.seen()[5].target, "/transcript?rel=-w%2F0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl");
    assert_eq!(server.seen()[5].header("x-aws-proxy-port"), Some("8080"));
}

/// A code-out answer: its manifest line parsed and checked, the pack after
/// it into the destination file; past the cap the file is removed and the
/// answer is `too_large` (exit 9); a 204 leaves the file alone.
#[tokio::test]
async fn a_codeout_answer_splits_into_its_manifest_and_pack() {
    let manifest = CodeoutManifest { v: 1, object_format: ObjectFormat::Sha1, refs: BTreeMap::from([("refs/heads/main".to_string(), H.to_string())]), head: H.into(), branch: Some("main".into()), wip_ref: None, wip_skipped: None };
    let pack = b"PACK-not-really-a-pack-but-bytes".to_vec();
    let bad = CodeoutManifest { refs: BTreeMap::from([("refs/tags/v1".to_string(), H.to_string())]), ..manifest.clone() };
    let server = Server::start(vec![answer(200, framed(&manifest, &pack)), answer(200, framed(&manifest, &pack)), answer(204, Vec::new()), answer(200, framed(&bad, &pack))]).await;
    let (dp, t) = (server.dp(), target());
    let dir = tempfile::tempdir().unwrap();
    let req = CodeoutRequest { path: "/w".into(), haves: vec![H.into()], wip: true, max_bytes: 1024, manifest_when_empty: false };
    let dest = dir.path().join("in.pack");
    let r = dp.post_codeout(&t, &token(9418), &req, &dest, 1024).await.unwrap();
    let body = r.body.unwrap();
    assert_eq!((body.manifest, body.pack_bytes), (manifest, pack.len() as u64));
    assert_eq!(std::fs::read(&dest).unwrap(), pack);
    let sent: CodeoutRequest = serde_json::from_slice(&server.seen()[0].body).unwrap();
    assert_eq!((sent, server.seen()[0].header("content-type")), (req.clone(), Some("application/json")));
    let small = dir.path().join("small.pack");
    let e = dp.post_codeout(&t, &token(9418), &req, &small, 8).await.unwrap_err();
    assert!(matches!(&e, BridgeError::WorkspaceRefused { code: c, .. } if *c == refusal::TOO_LARGE), "{e:?}");
    assert!(!small.exists(), "nothing past the cap is kept");
    let none = dir.path().join("none.pack");
    assert_eq!(dp.post_codeout(&t, &token(9418), &req, &none, 1024).await.unwrap().status, 204);
    assert!(!none.exists());
    let e = dp.post_codeout(&t, &token(9418), &req, &dir.path().join("bad.pack"), 1024).await.unwrap_err();
    assert!(e.to_string().contains("bad_refs"), "a manifest naming a tag is refused: {e}");
}

/// A redirect is the bridge's refusal, never followed (the token would follow it).
#[tokio::test]
async fn a_redirect_is_refused() {
    let server = Server::start(vec![Answer { status: 307, headers: vec![("location", "http://127.0.0.1:1/x".into())], body: Vec::new() }]).await;
    let e = server.dp().seed_state(&target(), &token(9418), "/w").await.unwrap_err();
    assert!(matches!(&e, BridgeError::Sdk { op: "workspace", .. }) && e.to_string().contains("refused"), "{e}");
    assert_eq!(server.seen().len(), 1, "the Location was never dialed");
}

/// The lab's client needs the fake API and a loopback address, as the agent knob does.
#[test]
fn the_lab_client_needs_the_fake_api() {
    let knobs = VmKnobs { agent_addr: Some("127.0.0.1:9".into()), ..VmKnobs::default() };
    assert!(matches!(HttpsEndpoint::new(&knobs), Err(BridgeError::Config(_))));
    assert!(HttpsEndpoint::new(&VmKnobs::default()).is_ok(), "no knob: HTTPS");
}
