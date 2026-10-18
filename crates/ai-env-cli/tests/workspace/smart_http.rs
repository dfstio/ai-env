//! S9 wave 1 (G2): the Mac's smart-HTTP client (`bridge::gitsmart`) and
//! `box fetch --smart-http`. The data plane's two git routes against a
//! loopback server (protocol v2's headers, an answer read to its end, one
//! cut short, the statuses `exchange` decides on, the cap); the smart-HTTP
//! fetch end to end against the git-backed fake VM, its answers the real
//! upload-pack's (as http-backend runs it: protocol v2, stateless), into
//! S8's import; then `ai-env box fetch` through the endpoint and the native
//! shim (the rig of `tests/common/remote.rs`): `--smart-http` checks the VM's
//! `git_http_v1` before any request, a dry run in either mode records no
//! token expiry in the VM's row, and a fetch notes once per workspace a
//! repository without the ai-env pre-push hook. The VM's own git routes
//! (`shim::gitcgi`, G1) are not this file's: where a test needs the VM's
//! answers through the endpoint, the endpoint answers them.
use super::common::fake_endpoint::Action;
use super::common::remote::RemoteRig;
use super::common::Harness;
use super::fixture::{api, caps, ensure_ctx, git, git_cmd, git_ok, git_out, target, FakeVm, Tokens, World};
use ai_env_cli::bridge::agent::AgentTarget;
use ai_env_cli::bridge::api::{AuthToken, Call, TOKEN_HEADER};
use ai_env_cli::bridge::codeout::{fetch_smart_http, CodeoutCtx, FetchOpts, BOX_REFS};
use ai_env_cli::bridge::dataplane::{verdict_cap, DpReply, HttpsEndpoint, Verdict};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::gitsmart::{parse_pkt, GitHttp, Pkt};
use ai_env_cli::bridge::lab::VmKnobs;
use ai_env_cli::bridge::workspace::{ensure_workspace, resolve, SeedProgress, SeedWant};
use ai_env_cli::errors::CliError;
use ai_env_cli::wire::frame::CAP_GIT_HTTP_V1;
use ai_env_cli::wire::redact::Secret;
use ai_env_cli::wire::workspace::{refusal, WsRefusal, CODE_PORT, GIT_ADVERTISEMENT_TYPE, GIT_UPLOAD_PACK_REQUEST_TYPE, GIT_UPLOAD_PACK_RESULT_TYPE};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// `text` and its LF as one pkt-line.
fn pkt(text: &str) -> String {
    format!("{:04x}{text}\n", text.len() + 5)
}

/// A v2 advertisement as git 2.50's http-backend writes it.
fn advert() -> String {
    ["version 2", "agent=git/2.50.1", "ls-refs=unborn", "fetch=shallow wait-for-done", "server-option", "object-format=sha1"].iter().map(|t| pkt(t)).collect::<String>() + "0000"
}

/// An `ls-refs` answer: HEAD on `main`, `main` at `head`.
fn ls_refs(head: &str) -> String {
    format!("{}{}0000", pkt(&format!("{head} HEAD symref-target:refs/heads/main")), pkt(&format!("{head} refs/heads/main")))
}

/// A request's data lines, each without its LF.
fn lines(mut body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(Some((p, n))) = parse_pkt(body) {
        if let Pkt::Data(d) = p {
            out.push(String::from_utf8_lossy(d.strip_suffix(b"\n").unwrap_or(d)).into_owned());
        }
        body = &body[n..];
    }
    out
}

fn exit(e: BridgeError) -> i32 {
    CliError::from(e).exit_code()
}

// ---- the data plane's git routes, against a loopback server ----

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

/// One scripted answer: a body with its `Content-Length`, or chunked (as the
/// shim streams a CGI's) in 1000-byte chunks, `cut`: without its last chunk.
struct Answer {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    chunked: bool,
    cut: bool,
}

impl Answer {
    fn plain(status: u16, body: impl Into<Vec<u8>>, headers: &[(&'static str, &str)]) -> Answer {
        Answer { status, headers: headers.iter().map(|(k, v)| (*k, (*v).to_string())).collect(), body: body.into(), chunked: false, cut: false }
    }

    fn chunked(body: impl Into<Vec<u8>>, content_type: &str) -> Answer {
        Answer { chunked: true, ..Answer::plain(200, body, &[("content-type", content_type)]) }
    }
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
                    let mut head_lines = head.split("\r\n");
                    let mut first = head_lines.next().unwrap().split(' ');
                    let (method, target) = (first.next().unwrap().to_string(), first.next().unwrap().to_string());
                    let headers: Vec<(String, String)> = head_lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
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
                    let a = script.lock().unwrap().pop_front().unwrap_or_else(|| Answer::plain(500, "no script left", &[]));
                    let mut out = format!("HTTP/1.1 {} X\r\nconnection: close\r\n", a.status);
                    for (k, v) in &a.headers {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                    if a.chunked {
                        out.push_str("transfer-encoding: chunked\r\n\r\n");
                        let _ = conn.write_all(out.as_bytes()).await;
                        for piece in a.body.chunks(1000) {
                            let _ = conn.write_all(format!("{:x}\r\n", piece.len()).as_bytes()).await;
                            let _ = conn.write_all(piece).await;
                            let _ = conn.write_all(b"\r\n").await;
                        }
                        if !a.cut {
                            let _ = conn.write_all(b"0\r\n\r\n").await;
                        }
                    } else {
                        out.push_str(&format!("content-length: {}\r\n\r\n", a.body.len()));
                        let _ = conn.write_all(out.as_bytes()).await;
                        let _ = conn.write_all(&a.body).await;
                    }
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

/// The two git routes on the code port: protocol v2 asked (`Git-Protocol`,
/// `Accept` of the route's type), the endpoint's headers and the bearer,
/// the advertisement's query exactly `service=git-upload-pack`, a request
/// with its `Content-Type` and `Content-Length` (never chunked, never a
/// `Content-Encoding`, no `Accept-Encoding` asked); a chunked answer read to
/// its end, one cut before its last chunk `Endpoint` (which `exchange` asks
/// once more); 403, 404 and 409 `busy` come back as replies for
/// `exchange`'s verdict (a re-mint, an image without `git_http_v1` exit 7, a
/// wait); an answer past the cap is `too_large` (exit 9).
#[tokio::test]
async fn the_git_routes_ask_protocol_v2_and_read_answers_to_their_end() {
    let head = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
    let (adv, ls) = (advert(), ls_refs(head));
    let busy = serde_json::to_vec(&WsRefusal::new(refusal::BUSY, "two CGI runs already")).unwrap();
    let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let server = Server::start(vec![
        Answer::chunked(adv.clone(), GIT_ADVERTISEMENT_TYPE),
        Answer::chunked(ls.clone(), GIT_UPLOAD_PACK_RESULT_TYPE),
        Answer { cut: true, ..Answer::chunked(big.clone(), GIT_UPLOAD_PACK_RESULT_TYPE) },
        Answer::plain(403, "", &[("x-aws-proxy-error", "UNAUTHORIZED")]),
        Answer::plain(404, ai_env_cli::wire::workspace::NO_SUCH_ROUTE, &[]),
        Answer::plain(409, busy, &[("retry-after", "5"), ("content-type", "application/json")]),
        Answer::chunked(big.clone(), GIT_UPLOAD_PACK_RESULT_TYPE),
    ])
    .await;
    let (dp, t) = (server.dp(), target());
    let r = dp.info_refs(&t, &token(CODE_PORT)).await.unwrap();
    assert_eq!((r.status, r.body), (200, Some(adv.into_bytes())));
    let request = format!("{}0001{}0000", pkt("command=ls-refs"), pkt("symrefs")).into_bytes();
    let mut sink = Vec::new();
    let r = dp.upload_pack(&t, &token(CODE_PORT), &request, &mut sink, 1 << 20).await.unwrap();
    assert_eq!((r.status, r.body, sink), (200, Some(ls.len() as u64), ls.into_bytes()));
    let seen = server.seen();
    let (get, post) = (&seen[0], &seen[1]);
    assert_eq!((get.method.as_str(), get.target.as_str()), ("GET", "/workspace.git/info/refs?service=git-upload-pack"));
    assert_eq!((post.method.as_str(), post.target.as_str()), ("POST", "/workspace.git/git-upload-pack"));
    for (s, accept) in [(get, GIT_ADVERTISEMENT_TYPE), (post, GIT_UPLOAD_PACK_RESULT_TYPE)] {
        assert_eq!((s.header("git-protocol"), s.header("accept")), (Some("version=2"), Some(accept)), "{s:?}");
        assert_eq!((s.header("host"), s.header("x-aws-proxy-auth"), s.header("x-aws-proxy-port")), (Some(t.endpoint.as_str()), Some("proxy-token-value"), Some("9418")));
        assert_eq!(s.header("authorization").map(str::to_string), Some(format!("Bearer {}", "s".repeat(64))));
        assert_eq!((s.header("content-encoding"), s.header("accept-encoding"), s.header("transfer-encoding")), (None, None, None), "{s:?}");
    }
    assert_eq!((post.header("content-type"), post.header("content-length")), (Some(GIT_UPLOAD_PACK_REQUEST_TYPE), Some(request.len().to_string().as_str())));
    assert_eq!(post.body, request);
    // Cut before its last chunk: a transport failure, which an idempotent exchange asks once more.
    let e = dp.upload_pack(&t, &token(CODE_PORT), &request, &mut Vec::new(), 1 << 20).await.unwrap_err();
    assert!(matches!(&e, BridgeError::Endpoint(_)), "{e:?}");
    // The statuses, as `exchange` reads them.
    let route = "POST /workspace.git/git-upload-pack";
    let r = dp.upload_pack(&t, &token(CODE_PORT), &request, &mut Vec::new(), 1 << 20).await.unwrap();
    assert_eq!((r.status, r.proxy_error.as_deref()), (403, Some("UNAUTHORIZED")));
    assert!(matches!(verdict_cap(route, CODE_PORT, CAP_GIT_HTTP_V1, &r), Verdict::Remint { .. }));
    let r = dp.upload_pack(&t, &token(CODE_PORT), &request, &mut Vec::new(), 1 << 20).await.unwrap();
    match verdict_cap(route, CODE_PORT, CAP_GIT_HTTP_V1, &r) {
        Verdict::Fail(e) => {
            assert!(e.to_string().contains("lacks git_http_v1") && e.to_string().contains("make deploy"), "{e}");
            assert_eq!(exit(e), 7);
        }
        other => panic!("{other:?}"),
    }
    let r: DpReply<u64> = dp.upload_pack(&t, &token(CODE_PORT), &request, &mut Vec::new(), 1 << 20).await.unwrap();
    assert_eq!((r.status, r.retry_after_s, r.refusal.as_ref().map(|x| x.code.as_str())), (409, Some(5), Some(refusal::BUSY)));
    assert!(matches!(verdict_cap(route, CODE_PORT, CAP_GIT_HTTP_V1, &r), Verdict::Busy { .. }));
    // Past the cap: refused, whatever came before.
    let e = dp.upload_pack(&t, &token(CODE_PORT), &request, &mut Vec::new(), 4999).await.unwrap_err();
    assert!(matches!(&e, BridgeError::WorkspaceRefused { code, .. } if *code == refusal::TOO_LARGE), "{e:?}");
    assert_eq!(exit(e), 9);
    assert_eq!(server.seen().len(), 7);
}

// ---- the smart-HTTP fetch, against the git-backed fake VM ----

/// The fake VM's repository answered by the real upload-pack, as the VM's
/// http-backend runs it (protocol v2, stateless), each answer written in
/// 1000-byte pieces; the requests it took kept.
struct UploadPackVm {
    dir: PathBuf,
    posts: Mutex<Vec<Vec<u8>>>,
}

impl UploadPackVm {
    fn new(dir: &Path) -> UploadPackVm {
        UploadPackVm { dir: dir.to_path_buf(), posts: Mutex::new(Vec::new()) }
    }

    /// `git upload-pack <args> .` in the VM's checkout with `stdin`: its stdout.
    fn run(&self, args: &[&str], stdin: &[u8]) -> Vec<u8> {
        let mut cmd = git_cmd(&self.dir);
        cmd.env("GIT_PROTOCOL", "version=2").arg("upload-pack").args(args).arg(".").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let bytes = stdin.to_vec();
        let feeder = std::thread::spawn(move || {
            let _ = input.write_all(&bytes);
        });
        let out = child.wait_with_output().unwrap();
        feeder.join().unwrap();
        assert!(out.status.success(), "upload-pack {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        out.stdout
    }

    fn posts(&self) -> Vec<Vec<u8>> {
        self.posts.lock().unwrap().clone()
    }
}

impl GitHttp for UploadPackVm {
    async fn info_refs(&self, _: &AgentTarget, _: &AuthToken) -> Result<DpReply<Vec<u8>>, BridgeError> {
        Ok(DpReply::ok(200, self.run(&["--http-backend-info-refs"], b"")))
    }

    async fn upload_pack<W: std::io::Write + Send>(&self, _: &AgentTarget, _: &AuthToken, body: &[u8], sink: &mut W, cap: u64) -> Result<DpReply<u64>, BridgeError> {
        self.posts.lock().unwrap().push(body.to_vec());
        let answer = self.run(&["--stateless-rpc"], body);
        assert!(answer.len() as u64 <= cap, "{} bytes, cap {cap}", answer.len());
        for piece in answer.chunks(1000) {
            sink.write_all(piece)?;
        }
        Ok(DpReply::ok(200, answer.len() as u64))
    }
}

/// The `codeout_fetch` audit rows of `paths`' bridge root: (via, outcome,
/// hidden), `-` for a detail a row lacks (a nothing-new row counts nothing).
fn fetch_rows(audit: &Path) -> Vec<(String, String, String)> {
    let text = std::fs::read_to_string(audit).unwrap_or_default();
    let rows = text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|r| r["event"] == "codeout_fetch");
    rows.map(|r| {
        let detail = |k: &str| r["detail"][k].as_str().unwrap_or("-").to_string();
        (detail("via"), detail("outcome"), detail("hidden"))
    })
    .collect()
}

/// A smart-HTTP fetch's row as [`fetch_rows`] reads it.
fn row(outcome: &str, hidden: &str) -> (String, String, String) {
    ("smart-http".to_string(), outcome.to_string(), hidden.to_string())
}

/// The smart-HTTP fetch end to end, into S8's import: after a seed, the
/// agent's commits on `main` and on `feature` come back as
/// `refs/remotes/box/main` and `box/feature`, the Mac's branch and worktree
/// untouched; a branch the agent names after the setup-token is counted,
/// never named, and its commit is never wanted, so it never reaches the
/// Mac's store; the `fetch` request wants exactly the two commits, with the
/// Mac's HEAD among the haves. Asked again with nothing moved, the hidden
/// branch keeps the fetch from being nothing new, as it keeps the helper's
/// 204 away: the same wants, haves now, bring an empty pack, and the hidden
/// ref is counted again. Once it is all the VM lists, nothing is wanted, no
/// `fetch` goes out, and it is still counted. The workspace row and the
/// audit (`via` `smart-http`, `hidden`) record each fetch.
#[tokio::test]
async fn a_smart_http_fetch_promotes_the_vms_refs_and_never_wants_a_hidden_one() {
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (fake_api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    ensure_workspace(&ensure_ctx(&fake_api, &vm, &paths, &cfg, &t, &c, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    let seeded = repo.head();
    // The agent commits on main and on a branch, then on a branch named after the setup-token.
    let commit = |file: &str, msg: &str| {
        std::fs::write(vm.dir.join(file), format!("{msg}\n")).unwrap();
        git(&vm.dir, &["add", file]);
        git(&vm.dir, &["commit", "-q", "-m", msg]);
        git(&vm.dir, &["rev-parse", "HEAD"])
    };
    let agent = commit("agent.txt", "agent");
    git(&vm.dir, &["checkout", "-q", "-b", "feature"]);
    let feature = commit("feature.txt", "feature");
    let token = format!("{}-{}-oat01-{}", "sk", "ant", "Kq4_".repeat(20));
    git(&vm.dir, &["checkout", "-q", "-b", &format!("x-{token}")]);
    let hidden = commit("secret.txt", "only on the hidden branch");
    git(&vm.dir, &["checkout", "-q", "main"]);
    let before = repo.state();
    let transport = Arc::new(UploadPackVm::new(&vm.dir));
    let ctx = CodeoutCtx { api: Arc::new(api().await), dp: transport.clone(), tokens: Arc::new(Tokens), paths: paths.clone(), cfg: Arc::new(cfg.clone()), target: target(), ws: ws.clone(), capture_settings: false, transcript: None };
    let report = fetch_smart_http(&ctx, FetchOpts { wip: false, max_bytes: 1 << 20 }).await.unwrap();
    assert!(report.ok && report.quarantined.is_empty() && report.bytes > 0, "{report:?}");
    let promoted: BTreeMap<String, String> = [("main", &agent), ("feature", &feature)].iter().map(|(b, id)| (format!("{BOX_REFS}{b}"), (*id).clone())).collect();
    assert_eq!(report.promoted, promoted);
    let note = report.note.clone().unwrap_or_default();
    assert!(note.contains("1 VM ref(s) skipped: a name that looks like a credential (not shown)") && !note.contains(&token), "{}", note.replace(&token, "<TOKEN>"));
    for (name, id) in &promoted {
        assert_eq!(&repo.git(&["rev-parse", name]), id, "{name}");
    }
    assert!(!git_ok(&repo.dir, &["cat-file", "-e", &format!("{hidden}^{{commit}}")]), "the hidden branch's commit never crossed");
    let after = repo.state();
    assert_eq!((after.index, after.status, after.stash), (before.index, before.status, before.stash));
    assert_eq!(repo.git(&["rev-parse", "main"]), seeded, "the Mac's branch did not move");
    // ls-refs, then fetch: exactly the two commits wanted, the Mac's HEAD a have.
    let posts = transport.posts();
    assert_eq!(posts.len(), 2);
    assert!(lines(&posts[0]).iter().any(|l| l == "command=ls-refs"), "{:?}", lines(&posts[0]));
    let fetch = lines(&posts[1]);
    let wants: Vec<&str> = fetch.iter().filter_map(|l| l.strip_prefix("want ")).collect();
    let mut want_ids = vec![agent.as_str(), feature.as_str()];
    want_ids.sort_unstable();
    assert_eq!((fetch[0].as_str(), wants), ("command=fetch", want_ids.clone()));
    assert!(fetch.iter().any(|l| *l == format!("have {seeded}")) && fetch.last().map(String::as_str) == Some("done"), "{fetch:?}");
    let row_now = ai_env_cli::bridge::workspace::rows::row_of(&paths, &ws).unwrap().unwrap();
    assert_eq!((row_now.last_fetch_vm.as_deref(), row_now.fetched.get(&format!("{BOX_REFS}feature"))), (Some(super::fixture::VM), Some(&feature)));
    // Again, nothing moved: the token-named branch is still listed and its tip is never a have, so
    // this is not nothing new (nor is it to the helper, whose 204 needs every tip had). The same two
    // wants, haves now, bring an empty pack (its 12-byte header and its sha1); the import promotes
    // the same tips and counts the hidden ref again, as after a code-out.
    let again = fetch_smart_http(&ctx, FetchOpts { wip: false, max_bytes: 1 << 20 }).await.unwrap();
    assert_eq!((&again.promoted, again.bytes), (&promoted, 32), "{again:?}");
    let note = again.note.clone().unwrap_or_default();
    assert!(note.contains("1 VM ref(s) skipped: a name that looks like a credential (not shown)") && !note.contains(&token), "{}", note.replace(&token, "<TOKEN>"));
    let posts = transport.posts();
    assert_eq!(posts.len(), 4, "ls-refs and fetch, twice");
    let fetch = lines(&posts[3]);
    let wants: Vec<&str> = fetch.iter().filter_map(|l| l.strip_prefix("want ")).collect();
    assert_eq!(wants, want_ids);
    assert!(!git_ok(&repo.dir, &["cat-file", "-e", &format!("{hidden}^{{commit}}")]), "the hidden branch's commit never crossed");
    // The token-named branch moves and is all the VM lists (HEAD on it, its other branches gone):
    // nothing to want, so no fetch goes out; the import counts it, and the Mac's box refs stay.
    git(&vm.dir, &["checkout", "-q", &format!("x-{token}")]);
    let moved = commit("secret2.txt", "the hidden branch moved");
    git(&vm.dir, &["branch", "-q", "-D", "main", "feature"]);
    let third = fetch_smart_http(&ctx, FetchOpts { wip: false, max_bytes: 1 << 20 }).await.unwrap();
    assert!(third.ok && third.promoted.is_empty() && third.bytes == 0, "{third:?}");
    let note = third.note.clone().unwrap_or_default();
    assert!(note.contains("1 VM ref(s) skipped: a name that looks like a credential (not shown)") && !note.contains(&token), "{}", note.replace(&token, "<TOKEN>"));
    assert_eq!(transport.posts().len(), 5, "the third fetch's ls-refs alone");
    assert!(!git_ok(&repo.dir, &["cat-file", "-e", &format!("{moved}^{{commit}}")]), "the moved hidden branch's commit never crossed");
    for (name, id) in &promoted {
        assert_eq!(&repo.git(&["rev-parse", name]), id, "{name} stays");
    }
    assert_eq!(fetch_rows(&paths.audit()), [row("promoted", "1"), row("promoted", "1"), row("promoted", "1")]);
    // `--wip` snapshots through POST /codeout only.
    let e = fetch_smart_http(&ctx, FetchOpts { wip: true, max_bytes: 1 << 20 }).await.unwrap_err();
    assert!(matches!(e, BridgeError::Config(_)) && transport.posts().len() == 5, "{e:?}");
}

/// The helper lists only the refs that name a commit (its listing's
/// `%(objecttype)`), and the smart-HTTP fetch promotes only those too,
/// though `ls-refs` shows a ref's type before any want for a tag alone
/// (`peel`): once the pack is on the Mac, the import's commit-only check
/// (S9, the lead's integration of G2's R2) leaves out a snapshot ref the
/// agent pointed at a blob, and one at a tree (`update-ref` takes both
/// outside refs/heads), counted in the note, never named. The fetch
/// promotes the agent's branch and does not fail; no box ref names either
/// object, and the blob never reaches the Mac's store. Asked again, both
/// are listed, fetched and left out again, counted again, the branch (had)
/// promoted again. Once they are gone, every listed tip is had: nothing
/// new, and no `fetch` goes out. A HEAD the agent pointed at a tree is
/// `not_seeded` (exit 9), as the helper answers, and no `box/HEAD` appears.
#[tokio::test]
async fn a_smart_http_fetch_takes_only_refs_that_name_a_commit() {
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (fake_api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    ensure_workspace(&ensure_ctx(&fake_api, &vm, &paths, &cfg, &t, &c, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    std::fs::write(vm.dir.join("agent.txt"), "agent\n").unwrap();
    git(&vm.dir, &["add", "agent.txt"]);
    git(&vm.dir, &["commit", "-q", "-m", "agent"]);
    let agent = git(&vm.dir, &["rev-parse", "HEAD"]);
    let o = git_out(&vm.dir, &["hash-object", "-w", "--stdin"], Some(b"a blob, not a commit\n"));
    assert!(o.status.success(), "{}", text(&o.stderr));
    let blob = text(&o.stdout).trim().to_string();
    let tree = git(&vm.dir, &["rev-parse", "HEAD^{tree}"]);
    git(&vm.dir, &["update-ref", "refs/wip/20261018T090000Z-1", &blob]);
    git(&vm.dir, &["update-ref", "refs/wip/20261018T090000Z-2", &tree]);
    let transport = Arc::new(UploadPackVm::new(&vm.dir));
    let ctx = CodeoutCtx { api: Arc::new(api().await), dp: transport.clone(), tokens: Arc::new(Tokens), paths: paths.clone(), cfg: Arc::new(cfg.clone()), target: target(), ws: ws.clone(), capture_settings: false, transcript: None };
    let opts = FetchOpts { wip: false, max_bytes: 1 << 20 };
    let main = BTreeMap::from([(format!("{BOX_REFS}main"), agent.clone())]);
    let counted = ai_env_cli::bridge::codeout::not_commit_note(2);
    let report = fetch_smart_http(&ctx, opts).await.unwrap();
    assert_eq!((&report.promoted, report.quarantined.len(), report.note.as_deref()), (&main, 0, Some(counted.as_str())), "{report:?}");
    assert_eq!(repo.git(&["for-each-ref", "--format=%(refname)", "refs/remotes/"]), format!("{BOX_REFS}main"), "no box ref names the blob or the tree");
    let fetch = lines(&transport.posts()[1]);
    let wants: Vec<&str> = fetch.iter().filter_map(|l| l.strip_prefix("want ")).collect();
    assert!(wants.contains(&blob.as_str()) && wants.contains(&tree.as_str()), "ls-refs cannot tell them from commits: {wants:?}");
    assert!(!git_ok(&repo.dir, &["cat-file", "-e", &blob]), "the blob stayed in the scratch");
    // Again: both are listed again (never haves), fetched and left out again, the branch (had) promoted again.
    let again = fetch_smart_http(&ctx, opts).await.unwrap();
    assert_eq!((&again.promoted, again.quarantined.len(), again.note.as_deref()), (&main, 0, Some(counted.as_str())), "{again:?}");
    assert_eq!(transport.posts().len(), 4, "ls-refs and fetch, twice");
    assert!(!git_ok(&repo.dir, &["cat-file", "-e", &blob]), "the blob stayed in the scratch again");
    // Once they are gone every listed tip is had: nothing new, and no fetch goes out (one that wants
    // nothing would get the VM's http-backend's head alone, a cut answer).
    git(&vm.dir, &["update-ref", "-d", "refs/wip/20261018T090000Z-1"]);
    git(&vm.dir, &["update-ref", "-d", "refs/wip/20261018T090000Z-2"]);
    let third = fetch_smart_http(&ctx, opts).await.unwrap();
    assert!(third.ok && third.promoted.is_empty() && third.bytes == 0 && third.note.is_none(), "{third:?}");
    assert_eq!(transport.posts().len(), 5, "the third fetch's ls-refs alone");
    assert_eq!(fetch_rows(&paths.audit()), [row("promoted", "0"), row("promoted", "0"), row("nothing_new", "-")]);
    // A HEAD the agent pointed at a tree.
    std::fs::write(vm.dir.join(".git").join("HEAD"), format!("{tree}\n")).unwrap();
    let e = fetch_smart_http(&ctx, opts).await.unwrap_err();
    assert!(matches!(&e, BridgeError::WorkspaceRefused { code, message } if *code == refusal::NOT_SEEDED && message.contains("names a tree")), "{e:?}");
    assert_eq!(exit(e), 9);
    assert_eq!(repo.git(&["for-each-ref", "--format=%(refname)", "refs/remotes/"]), format!("{BOX_REFS}main"), "no box/HEAD");
}

// ---- `ai-env box fetch` through the endpoint and the native shim ----

/// `ai-env box seed <work> --json` on the rig, which must exit 0.
fn box_seed(rig: &RemoteRig) {
    let o = rig.run(&["box", "seed", &rig.work().display().to_string(), "--json"], None);
    assert!(o.status.success(), "box seed: {}", String::from_utf8_lossy(&o.stderr));
}

/// `ai-env box fetch <args>` on the rig: its output, whatever its exit.
fn box_fetch(rig: &RemoteRig, args: &[&str]) -> Output {
    let mut all = vec!["box", "fetch"];
    all.extend_from_slice(args);
    rig.run(&all, None)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// How many 9418 tokens the fake API minted so far.
fn code_mints(rig: &RemoteRig) -> usize {
    rig.fake_calls().iter().filter(|c| matches!(c, Call::Token { port: CODE_PORT, .. })).count()
}

/// The code port's requests to the git routes the endpoint saw.
fn git_requests(rig: &RemoteRig) -> Vec<String> {
    rig.endpoint.attempts().iter().filter(|a| a.port == CODE_PORT && a.path.starts_with("/workspace.git")).map(|a| a.path.clone()).collect()
}

/// `box fetch --dry-run` changes nothing on the Mac, in either mode (S9,
/// the S8 follow-up): it mints its 9418 token (one per run, in the fake
/// API's calls) without recording the token's expiry, so the VM's row, which
/// the seed's recorded mint wrote, stays byte for byte as it was. The
/// code-out's dry run reads the manifest through the shim's real helper;
/// the smart-HTTP one, on a VM whose image names `git_http_v1`, reads the
/// advertisement and `ls-refs` (here answered by the endpoint) and prints
/// what would move, `via` `smart-http`. A row that records no caps is
/// refused, since its `/health` would write the row: nothing minted.
#[test]
fn box_fetch_dry_run_persists_no_token_expiry() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work().display().to_string();
    rig.update_fake(|s| {
        if !s.health_caps.iter().any(|c| c == CAP_GIT_HTTP_V1) {
            s.health_caps.push(CAP_GIT_HTTP_V1.to_string());
        }
    });
    let vm = rig.start_vm();
    box_seed(rig);
    let row = rig.bridge().join("state").join("vms").join(format!("{vm}.toml"));
    let before = std::fs::read(&row).expect("the VM's row");
    let recorded: toml::Value = toml::from_str(&text(&before)).unwrap();
    assert!(recorded.get("token_expiries").and_then(|t| t.get("9418")).is_some(), "the seed's mint recorded its expiry: {recorded}");
    let minted = code_mints(rig);
    let o = box_fetch(rig, &[&work, "--dry-run"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.starts_with("box fetch --dry-run: ") && out.contains("  refs/heads/main -> refs/remotes/box/main: new\n") && out.ends_with("nothing was fetched\n"), "{out}");
    rig.endpoint.script_port(
        CODE_PORT,
        [
            Action::Respond { status: 200, headers: vec![("content-type".into(), GIT_ADVERTISEMENT_TYPE.into())], body: advert() },
            Action::Respond { status: 200, headers: vec![("content-type".into(), GIT_UPLOAD_PACK_RESULT_TYPE.into())], body: ls_refs(rig.head()) },
        ],
    );
    let o = box_fetch(rig, &[&work, "--smart-http", "--dry-run", "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o.stdout)));
    assert_eq!((&v["dry_run"], &v["via"], v["head"].as_str(), &v["branch"], &v["hidden"]), (&Value::Bool(true), &Value::from("smart-http"), Some(rig.head()), &Value::from("main"), &Value::from(0)), "{v}");
    assert_eq!((&v["refs"][0]["box"], &v["refs"][0]["state"], v["refs"].as_array().map(Vec::len)), (&Value::from("refs/remotes/box/main"), &Value::from("new"), Some(1)), "{v}");
    assert_eq!(git_requests(rig), ["/workspace.git/info/refs?service=git-upload-pack", "/workspace.git/git-upload-pack"]);
    assert_eq!(code_mints(rig), minted + 2, "each dry run minted its own token");
    assert_eq!(std::fs::read(&row).unwrap(), before, "the VM's row as the seed left it: no token expiry persisted");
    // A row that records no caps (a VM whose first /health never answered, a row older than S7):
    // reading /health would mint a recorded 8080 token and rewrite the row, so either dry run
    // refuses (exit 1, naming how to record them), nothing minted, the row as it was.
    let mut stripped = recorded.clone();
    stripped.as_table_mut().unwrap().remove("caps").expect("the seed's /health recorded the caps");
    std::fs::write(&row, toml::to_string(&stripped).unwrap()).unwrap();
    let before = std::fs::read(&row).unwrap();
    let mints = |rig: &RemoteRig| rig.fake_calls().iter().filter(|c| matches!(c, Call::Token { .. })).count();
    let minted = mints(rig);
    for args in [&[work.as_str(), "--dry-run"][..], &[work.as_str(), "--smart-http", "--dry-run"]] {
        let o = box_fetch(rig, args);
        let err = text(&o.stderr);
        assert_eq!(o.status.code(), Some(1), "{args:?}: {err}");
        assert!(err.contains(&format!("{vm} has no capabilities on record")) && err.contains(&format!("(ai-env vm health {vm} records them)")), "{err}");
    }
    assert_eq!(mints(rig), minted, "nothing minted");
    assert_eq!(std::fs::read(&row).unwrap(), before, "the row as it was");
}

/// The workspace row's `hook_noted_at`, from its file.
fn hook_noted_at(rig: &RemoteRig) -> Option<u64> {
    let rows: toml::Value = toml::from_str(&std::fs::read_to_string(row_file(rig)).unwrap()).unwrap();
    rows["ws"][rig.work().display().to_string()].get("hook_noted_at").and_then(toml::Value::as_integer).map(|n| u64::try_from(n).unwrap())
}

/// `state/workspaces/<slug>.toml` in the rig's bridge dir.
fn row_file(rig: &RemoteRig) -> PathBuf {
    let slug = ai_env_cli::wire::slug::project_dir_name(&rig.work()).expect("the workspace's slug");
    rig.bridge().join("state").join("workspaces").join(format!("{slug}.toml"))
}

/// A fetch notes, once per workspace, that the workspace's repository has
/// no ai-env pre-push hook (S9 §4.2): the first `box fetch` says it, as the
/// contract words it, and records when (`hook_noted_at`); the next says
/// nothing. A dry run neither says nor records it. With the note never
/// recorded, a repository that has the hook (ai-env's, or a foreign one,
/// which doctor names) is not noted either.
#[test]
fn box_fetch_notes_a_missing_pre_push_hook_once() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let (work, dir) = (rig.work(), rig.work().display().to_string());
    rig.start_vm();
    box_seed(rig);
    let note = format!("ai-env: the workspace {dir} has no ai-env pre-push hook: ai-env box hook-install {dir} installs it");
    let noted = |o: &Output| text(&o.stderr).lines().filter(|l| l.contains("pre-push hook")).count();
    let o = box_fetch(rig, &[&dir, "--dry-run"]);
    assert_eq!((o.status.code(), noted(&o), hook_noted_at(rig)), (Some(0), 0, None), "{}", text(&o.stderr));
    let o = box_fetch(rig, &[&dir]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert!(text(&o.stderr).lines().any(|l| l == note) && noted(&o) == 1, "{}", text(&o.stderr));
    let at = hook_noted_at(rig).expect("the note recorded");
    let now = ai_env_cli::wire::time::unix_now();
    assert!(at <= now && at + 600 > now, "{at} {now}");
    let o = box_fetch(rig, &[&dir]);
    assert_eq!((o.status.code(), noted(&o), hook_noted_at(rig)), (Some(0), 0, Some(at)), "{}", text(&o.stderr));
    // The note never recorded, and the hook there: ai-env's, then a foreign one.
    let unrecord = || {
        let mut rows: toml::Value = toml::from_str(&std::fs::read_to_string(row_file(rig)).unwrap()).unwrap();
        rows["ws"][dir.as_str()].as_table_mut().unwrap().remove("hook_noted_at");
        std::fs::write(row_file(rig), toml::to_string(&rows).unwrap()).unwrap();
    };
    let hook = work.join(".git").join("hooks").join("pre-push");
    for body in [format!("#!/bin/sh\n{}\nexit 0\n", ai_env_cli::bridge::review::PRE_PUSH_MARK), "#!/bin/sh\n# someone's own hook\nexit 0\n".to_string()] {
        unrecord();
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(&hook, body).unwrap();
        let o = box_fetch(rig, &[&dir]);
        assert_eq!((o.status.code(), noted(&o), hook_noted_at(rig)), (Some(0), 0, None), "{}", text(&o.stderr));
    }
}

/// `--smart-http` needs the VM's `git_http_v1` (an image older than S9
/// names only `workspace_v1`, whatever the rig's own default): exit 7
/// naming `make deploy`, before any token for the code port or any request
/// to a git route. With `--wip` it is clap's usage error (exit 2): the
/// snapshot lives in `POST /codeout`.
#[test]
fn smart_http_needs_git_http_v1_before_any_request() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let dir = rig.work().display().to_string();
    rig.update_fake(|s| s.health_caps.retain(|c| c != CAP_GIT_HTTP_V1));
    rig.start_vm();
    box_seed(rig);
    let minted = code_mints(rig);
    let o = box_fetch(rig, &[&dir, "--smart-http"]);
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(7), "{err}");
    assert!(err.contains("lacks git_http_v1") && err.contains("older than S9") && err.contains("make deploy"), "{err}");
    assert_eq!((code_mints(rig), git_requests(rig)), (minted, Vec::<String>::new()), "nothing asked of the VM");
    let o = box_fetch(rig, &[&dir, "--smart-http", "--wip"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
}
