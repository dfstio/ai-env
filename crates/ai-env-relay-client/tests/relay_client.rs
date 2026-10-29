//! The real `ai-env-relay-client` and `ai-env-relay-mcp` binaries (§V-vm.8.3) against a fake relay
//! (`relay_server::RelayServer` over TLS 1.3 on 127.0.0.1, certificates from the OpenSSL 3 CLI at run time): the
//! session on the client's fd 3, the test process the client's leader, the MCP server its child. The fake compares
//! the session header itself and never prints it; no line of either binary may hold the token or the CA.
mod common;

use common::*;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A fake relay of `sources`, a client with its session, and an MCP server finding it by ancestry.
struct Rig {
    pki: Pki,
    token: String,
    relay: FakeRelay,
    client: Client,
}

impl Rig {
    async fn new(sources: Vec<ai_env_relay_proto::v1::SourceStatus>, extra: &[&str]) -> Rig {
        let pki = Pki::new("IP:127.0.0.1");
        let token = token();
        let relay = FakeRelay::start(&pki, &token, sources).await;
        let session = session_json(&token, &relay.addr.to_string(), "127.0.0.1", &pki.ca_b64());
        let client = Client::ready(&session, extra).await;
        Rig { pki, token, relay, client }
    }

    /// The MCP server, finding the client's socket by its ancestry (this process).
    async fn mcp(&self) -> Mcp {
        Mcp::start(&["--socket-dir", self.client.socket.parent().unwrap().to_str().unwrap()]).await
    }
}

/// A client whose session names `addr` and `server_name` under `ca_b64`, and its MCP server.
async fn rig_for(addr: &str, server_name: &str, ca_b64: &str) -> (Client, Mcp, String) {
    let token = token();
    let client = Client::ready(&session_json(&token, addr, server_name, ca_b64), &[]).await;
    let mcp = Mcp::start(&["--socket-dir", client.socket.parent().unwrap().to_str().unwrap()]).await;
    (client, mcp, token)
}

/// `relay_catalog`'s text is §V-vm.3.6's catalog of the fake's sources; `relay_call` `echo` returns `json` equal to
/// its params; the fake saw `x-ai-env-session` equal to the token on both RPCs (compared in the fake), the call's
/// `deadline_ms` and `limits.max_bytes` as sent. Kills M-V47.
#[tokio::test]
async fn the_catalog_and_a_call_carry_the_session_header() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut m = r.mcp().await;
    m.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "relay_catalog", "arguments": {}}})).await;
    let reply = m.next().await;
    assert_eq!(raw_text(&reply), ECHO_CATALOG_TEXT);
    assert_eq!(reply["result"]["isError"], false);
    m.send(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "relay_call", "arguments": {"source": "echo", "op": "echo", "params": {"x": 1}, "max_bytes": 1000, "deadline_ms": 30_000}}})).await;
    let reply = m.next().await;
    assert_eq!(raw_text(&reply), format!(r#"{{"source":"echo","op":"echo","request_id":"{REQUEST_ID}","content_type":"application/json","truncated":false,"bytes":7,"limit":1000,"json":{{"x":1}}}}"#));
    assert_eq!(r.relay.seen.header_ok.load(Ordering::SeqCst), 2, "the token on both RPCs");
    assert_eq!(r.relay.requests(), 2);
    assert_eq!(*r.relay.seen.last_call.lock().unwrap(), Some((30_000, Some(1000))));
    // The client writes each line before its answer, but this process reads its stderr on its own task: awaited.
    let call = format!("ai-env-relay-client: call {REQUEST_ID} outcome=ok bytes=7 truncated=false ms=");
    let both = || {
        let log = r.client.log();
        log.contains("ai-env-relay-client: catalog outcome=ok sources=1 truncated=false ms=") && log.contains(&call)
    };
    assert!(eventually(LIMIT, both).await, "{}", r.client.log());
}

/// The fake's certificate from a second CA: `unavailable`, the message starting `tls: `; the fake counted no
/// request. Control (the pin itself; a verifier that skips it needs `dangerous`, which clippy refuses).
#[tokio::test]
async fn a_relay_under_another_ca_is_refused_before_any_request() {
    let (ours, theirs) = (Pki::new("IP:127.0.0.1"), Pki::new("IP:127.0.0.1"));
    let token = token();
    let relay = FakeRelay::start(&theirs, &token, echo_sources()).await;
    let (_client, mut m, _) = rig_for(&relay.addr.to_string(), "127.0.0.1", &ours.ca_b64()).await;
    let (text, is_error) = m.tool(1, "relay_catalog", json!({})).await;
    assert!(is_error, "{text}");
    assert_eq!(text["error"]["code"], "unavailable", "{text}");
    assert!(text["error"]["message"].as_str().unwrap().starts_with("tls: "), "{text}");
    assert_eq!(relay.requests(), 0);
}

/// The certificate's SAN `127.0.0.1`, the session's `server_name` `127.0.0.2`: `unavailable`, `tls: `; no
/// request. Kills M-V48.
#[tokio::test]
async fn a_certificate_for_another_name_is_refused() {
    let pki = Pki::new("IP:127.0.0.1");
    let token = token();
    let relay = FakeRelay::start(&pki, &token, echo_sources()).await;
    let (_client, mut m, _) = rig_for(&relay.addr.to_string(), "127.0.0.2", &pki.ca_b64()).await;
    let (text, is_error) = m.tool(1, "relay_call", json!({"source": "echo", "op": "echo"})).await;
    assert!(is_error, "{text}");
    assert_eq!((text["error"]["code"].as_str(), text["source"].as_str(), text["op"].as_str()), (Some("unavailable"), Some("echo"), Some("echo")), "{text}");
    assert!(text["error"]["message"].as_str().unwrap().starts_with("tls: "), "{text}");
    assert_eq!(relay.requests(), 0);
}

/// `openssl s_server` on 127.0.0.1, TLS 1.2 only, with a certificate of the session's CA; killed on drop.
struct Tls12 {
    child: std::process::Child,
    port: u16,
}

impl Drop for Tls12 {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Tls12 {
    fn start(pki: &Pki) -> Tls12 {
        for _ in 0..5 {
            let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            let mut child = {
                let _held = SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                std::process::Command::new(openssl())
                    .args(["s_server", "-accept", &format!("127.0.0.1:{port}"), "-cert"])
                    .arg(&pki.leaf_pem)
                    .arg("-key")
                    .arg(&pki.leaf_key_pem)
                    // ALPN h2 too: only the protocol version may stand between the client and this server.
                    .args(["-tls1_2", "-alpn", "h2", "-www", "-quiet"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            };
            let until = Instant::now() + LIMIT;
            loop {
                if std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(200)).is_ok() {
                    return Tls12 { child, port };
                }
                if child.try_wait().unwrap().is_some() || Instant::now() >= until {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        panic!("openssl s_server -tls1_2 never listened");
    }
}

/// `openssl s_server -tls1_2` (ALPN `h2` offered) with the right CA's certificate: `unavailable`, `tls: `, the server's
/// protocol-version alert. Kills M-V42.
#[tokio::test]
async fn a_tls12_only_relay_is_refused_before_any_request() {
    let pki = Pki::new("IP:127.0.0.1");
    let server = Tls12::start(&pki);
    let (_client, mut m, _) = rig_for(&format!("127.0.0.1:{}", server.port), "127.0.0.1", &pki.ca_b64()).await;
    let (text, is_error) = m.tool(1, "relay_catalog", json!({})).await;
    assert!(is_error, "{text}");
    assert_eq!(text["error"]["code"], "unavailable", "{text}");
    let message = text["error"]["message"].as_str().unwrap();
    assert!(message.starts_with("tls: ") && message.contains("ProtocolVersion"), "{text}");
}

/// addr `127.0.0.1:1`: `unavailable` within 2 s, the message starting `connect 127.0.0.1:1:`. Control.
#[tokio::test]
async fn an_unreachable_relay_is_unavailable_fast() {
    let pki = Pki::new("IP:127.0.0.1");
    let (_client, mut m, _) = rig_for("127.0.0.1:1", "127.0.0.1", &pki.ca_b64()).await;
    let t = Instant::now();
    let (text, is_error) = m.tool(1, "relay_catalog", json!({})).await;
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert!(is_error, "{text}");
    assert_eq!(text["error"]["code"], "unavailable", "{text}");
    assert!(text["error"]["message"].as_str().unwrap().starts_with("connect 127.0.0.1:1:"), "{text}");
}

/// `lines` `tail` sends three 64 KiB chunks; `max_bytes` 100 000 gives `bytes` 100 000, `truncated` true, `text`;
/// the fake saw its stream dropped within 2 s. Kills M-V43.
#[tokio::test]
async fn a_stream_past_max_bytes_is_cut_truncated_and_cancelled() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut m = r.mcp().await;
    let (text, is_error) = m.tool(1, "relay_call", json!({"source": "lines", "op": "tail", "max_bytes": 100_000})).await;
    assert!(!is_error, "{text}");
    assert_eq!((text["bytes"].as_u64(), text["limit"].as_u64(), text["truncated"].as_bool()), (Some(100_000), Some(100_000), Some(true)), "{}", &text.to_string()[..200]);
    let body = text["text"].as_str().expect("a text body");
    let mut want = lines_of(0, 65_536);
    want.extend(lines_of(1, 65_536));
    want.truncate(100_000);
    assert_eq!(body.as_bytes(), want.as_slice());
    assert!(eventually(Duration::from_secs(2), || r.relay.seen.dropped.load(Ordering::SeqCst) == 1).await, "the stream was dropped at the cut");
}

/// `lines` `head`'s one final chunk marked `truncated`: `truncated` true with every byte. Control.
#[tokio::test]
async fn a_chunk_marked_truncated_reaches_the_tool() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut m = r.mcp().await;
    let (text, is_error) = m.tool(1, "relay_call", json!({"source": "lines", "op": "head"})).await;
    assert!(!is_error, "{text}");
    assert_eq!(text, json!({"source": "lines", "op": "head", "request_id": REQUEST_ID, "content_type": "text/plain", "truncated": true, "bytes": 4, "limit": 65_536, "text": "a\nb\n"}));
}

/// `fail` `denied` (a status) gives `permission_denied` with its message; `fail` `missing` (an in-band error, code 5)
/// gives `not_found`; `fail` `cut` (no final chunk) and `fail` `gap` (seq 1, then 3) give `internal`; each line names
/// the call by the relay's request id. Kills M-V59, M-V60.
#[tokio::test]
async fn relay_errors_reach_the_tool_with_their_codes() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut m = r.mcp().await;
    let (text, is_error) = m.tool(1, "relay_call", json!({"source": "fail", "op": "denied"})).await;
    assert!(is_error);
    assert_eq!(text, json!({"source": "fail", "op": "denied", "error": {"code": "permission_denied", "message": "denied by grant"}}));
    let (text, is_error) = m.tool(2, "relay_call", json!({"source": "fail", "op": "missing"})).await;
    assert!(is_error);
    assert_eq!((text["error"]["code"].as_str(), text["error"]["message"].as_str()), (Some("not_found"), Some("no such entry")), "{text}");
    for (id, op) in [(3, "cut"), (4, "gap")] {
        let (text, is_error) = m.tool(id, "relay_call", json!({"source": "fail", "op": op})).await;
        assert!(is_error, "{op}: {text}");
        assert_eq!(text["error"]["code"], "internal", "{op}: {text}");
    }
    let line = |outcome: &str| format!("call {REQUEST_ID} outcome={outcome} bytes=0");
    let done = || {
        let log = r.client.log();
        log.contains(&line("permission_denied")) && log.contains(&line("not_found")) && log.matches(&line("internal")).count() == 2
    };
    assert!(eventually(LIMIT, done).await, "{}", r.client.log());
}

/// A failed call's line names the relay's request id wherever the relay put it (§V-vm.3.8's `call <request_id|->`):
/// `fail` `denied`'s refusal status; `fail` `missing`'s error chunk, under a head that names nothing; `fail` `abort`'s
/// stream head, when a status without one ends the stream; `fail` `cut`'s, when the stream ends without its final
/// chunk; `fail` `anonymous`'s, when its error chunk names nothing. A call that no relay answered (an unreachable
/// address) stays `-`. Kills M-V57 to M-V60, M-V66.
#[tokio::test]
async fn a_failed_call_line_names_the_relays_request_id() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut m = r.mcp().await;
    for (id, op, code) in [(1, "denied", "permission_denied"), (2, "missing", "not_found"), (3, "abort", "aborted"), (4, "cut", "internal"), (5, "anonymous", "failed_precondition")] {
        let (text, is_error) = m.tool(id, "relay_call", json!({"source": "fail", "op": op})).await;
        assert!(is_error, "{op}: {text}");
        assert_eq!(text["error"]["code"], code, "{op}: {text}");
        let line = format!("ai-env-relay-client: call {REQUEST_ID} outcome={code} bytes=0 truncated=false ms=");
        assert!(eventually(LIMIT, || r.client.log().contains(&line)).await, "{op}: {}", r.client.log());
    }
    assert!(!r.client.log().contains(" call - "), "{}", r.client.log());
    let pki = Pki::new("IP:127.0.0.1");
    let (client, mut m, _) = rig_for("127.0.0.1:1", "127.0.0.1", &pki.ca_b64()).await;
    let (text, is_error) = m.tool(1, "relay_call", json!({"source": "echo", "op": "echo"})).await;
    assert!(is_error && text["error"]["code"] == "unavailable", "{text}");
    assert!(eventually(LIMIT, || client.log().contains("ai-env-relay-client: call - outcome=unavailable bytes=0")).await, "{}", client.log());
}

/// A fake of 300 sources with 2 KiB descriptions: `truncated` true, the text under 256 KiB, the sources kept a
/// prefix of the fake's. Control.
#[tokio::test]
async fn a_catalog_over_its_cap_is_cut_and_marked() {
    let r = Rig::new(many_sources(300, 2048), &[]).await;
    let mut m = r.mcp().await;
    m.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "relay_catalog", "arguments": {}}})).await;
    let reply = m.next().await;
    let raw = raw_text(&reply);
    assert!(raw.len() < 262_144, "{}", raw.len());
    let (text, is_error) = tool_text(&reply);
    assert!(!is_error);
    assert_eq!(text["truncated"], true);
    let names: Vec<&str> = text["sources"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert!(names.len() > 100 && names.len() < 300, "{}", names.len());
    assert!(names.iter().enumerate().all(|(i, n)| *n == format!("test-{i}")), "a prefix of the fake's");
    let (one, _) = m.tool(2, "relay_catalog", json!({"source": "test-7"})).await;
    assert_eq!(one["sources"].as_array().unwrap().len(), 1, "a source alone");
    assert_eq!((one["sources"][0]["name"].as_str(), one["truncated"].as_bool()), (Some("test-7"), Some(false)));
}

/// A raw connection of the test process (the leader, so admitted) that sends `hello` gets a `bad_request` line, and
/// one that sends a `call` of `v` 2 the same; so do the client's own bounds (V-R19, V-R23): a call line one byte over
/// `REQUEST_MAX`, a `deadline_ms` over 300 000, `params` that are not an object, `params` over `PARAMS_MAX`. Nothing
/// reaches the relay. Control.
#[tokio::test]
async fn the_client_answers_garbage_bad_request() {
    use ai_env_relay_client::local::{DEADLINE_CAP_MS, PARAMS_MAX, REQUEST_MAX};
    let r = Rig::new(echo_sources(), &[]).await;
    for line in ["hello", r#"{"kind":"call","v":2,"source":"echo","op":"echo"}"#, r#"{"kind":"other","v":1}"#] {
        let answer = r.client.ask(line).await;
        assert_eq!((answer["kind"].as_str(), answer["v"].as_u64(), answer["code"].as_str()), (Some("error"), Some(1), Some("bad_request")), "{line}: {answer}");
    }
    // A call that would parse, padded one byte past the line's bound and sent without its newline: the client reads
    // every byte (so the write completes) and stops there.
    let call = r#"{"kind":"call","v":1,"source":"echo","op":"echo""#;
    let long = format!("{call}{}}}", " ".repeat(REQUEST_MAX - call.len()));
    assert_eq!(long.len(), REQUEST_MAX + 1);
    let mut s = tokio::net::UnixStream::connect(&r.client.socket).await.unwrap();
    s.write_all(long.as_bytes()).await.unwrap();
    let mut out = String::new();
    tokio::time::timeout(LIMIT, s.read_to_string(&mut out)).await.expect("an answer").unwrap();
    let answer: Value = serde_json::from_str(out.trim_end()).unwrap_or_else(|e| panic!("{e}: {out:?}"));
    assert_eq!((answer["code"].as_str(), answer["message"].as_str()), (Some("bad_request"), Some(format!("the request line is over {REQUEST_MAX} bytes").as_str())), "{answer}");
    let over_params = json!({"kind": "call", "v": 1, "source": "echo", "op": "echo", "params": {"x": "y".repeat(PARAMS_MAX)}}).to_string();
    assert!(over_params.len() < REQUEST_MAX, "inside the line's bound");
    for (line, says) in [
        (json!({"kind": "call", "v": 1, "source": "echo", "op": "echo", "deadline_ms": DEADLINE_CAP_MS + 1}).to_string(), format!("deadline_ms is {} (at most {DEADLINE_CAP_MS})", DEADLINE_CAP_MS + 1)),
        (json!({"kind": "call", "v": 1, "source": "echo", "op": "echo", "params": []}).to_string(), "params must be a JSON object".to_string()),
        (over_params, format!("(at most {PARAMS_MAX})")),
    ] {
        let answer = r.client.ask(&line).await;
        assert_eq!((answer["kind"].as_str(), answer["code"].as_str()), (Some("error"), Some("bad_request")), "{line:.80}: {answer}");
        assert!(answer["message"].as_str().is_some_and(|m| m.contains(&says)), "{line:.80}: {says}: {answer}");
    }
    assert_eq!(r.relay.requests(), 0, "nothing reached the relay");
}

/// `slow` `wait`, then `notifications/cancelled` for its id: the fake saw the stream dropped within 2 s, the MCP
/// server wrote no line for that id, and a later `relay_catalog` is answered. Kills M-V44.
#[tokio::test]
async fn an_mcp_cancel_drops_the_relay_stream() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut m = r.mcp().await;
    m.send(&json!({"jsonrpc": "2.0", "id": 41, "method": "tools/call", "params": {"name": "relay_call", "arguments": {"source": "slow", "op": "wait"}}})).await;
    assert!(eventually(LIMIT, || r.relay.requests() == 1).await, "the call reached the relay");
    m.send(&json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 41, "reason": "test"}})).await;
    assert!(eventually(Duration::from_secs(2), || r.relay.seen.dropped.load(Ordering::SeqCst) == 1).await, "the relay stream was dropped");
    let (text, is_error) = m.tool(42, "relay_catalog", json!({})).await;
    assert!(!is_error, "{text}");
    r.relay.release();
    assert_eq!(m.next_within(Duration::from_millis(500)).await, None, "no line for the cancelled call");
    assert!(!m.stdout_seen.contains("\"id\":41"), "{}", m.stdout_seen);
    // The line names the call once the stream's head had reached the client, `-` before.
    let cancelled = || [REQUEST_ID, "-"].iter().any(|id| r.client.log().contains(&format!("call {id} outcome=cancelled bytes=0")));
    assert!(eventually(LIMIT, cancelled).await, "{}", r.client.log());
}

/// A raw connection's `slow` `wait`, then one more byte while the call runs (V-R24): the fake saw its stream
/// dropped, the connection ends with no answer at all, and the client's line says `outcome=cancelled`. Kills M-V68.
#[tokio::test]
async fn a_byte_from_the_caller_drops_its_call_unanswered() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut s = tokio::net::UnixStream::connect(&r.client.socket).await.unwrap();
    s.write_all(b"{\"kind\":\"call\",\"v\":1,\"source\":\"slow\",\"op\":\"wait\"}\n").await.unwrap();
    assert!(eventually(LIMIT, || r.relay.requests() == 1).await, "the call reached the relay");
    s.write_all(b"x").await.unwrap();
    assert!(eventually(LIMIT, || r.relay.seen.dropped.load(Ordering::SeqCst) == 1).await, "the relay stream was dropped");
    let mut out = String::new();
    tokio::time::timeout(LIMIT, s.read_to_string(&mut out)).await.expect("the connection ends").unwrap();
    assert_eq!(out, "", "a cancelled call is not answered");
    // As in `an_mcp_cancel_drops_the_relay_stream`, the stream's head and the byte race: either id.
    let cancelled = || [REQUEST_ID, "-"].iter().any(|id| r.client.log().contains(&format!("call {id} outcome=cancelled bytes=0 truncated=false ms=")));
    assert!(eventually(LIMIT, cancelled).await, "{}", r.client.log());
}

/// The client's `--leader` a `sleep 60` child: `isError`, `forbidden_peer`; the client's stderr holds `refused peer
/// pid=<the MCP's> uid=<uid> (not of this session)`. Kills M-V38.
#[tokio::test]
async fn a_process_outside_the_session_is_refused() {
    let pki = Pki::new("IP:127.0.0.1");
    let token = token();
    let relay = FakeRelay::start(&pki, &token, echo_sources()).await;
    let leader = sleeper();
    let session = session_json(&token, &relay.addr.to_string(), "127.0.0.1", &pki.ca_b64());
    let client = spawn_client(Some(session.as_bytes()), leader.id().unwrap(), uid(), &[]);
    client.wait_ready().await;
    let mut m = Mcp::start(&["--socket", client.socket.to_str().unwrap()]).await;
    let (text, is_error) = m.tool(1, "relay_catalog", json!({})).await;
    assert!(is_error);
    assert_eq!(text, json!({"error": {"code": "forbidden_peer", "message": "not a process of this session"}}));
    let pid = m.child.id().unwrap();
    assert!(eventually(LIMIT, || client.log().contains(&format!("ai-env-relay-client: refused peer pid={pid} uid={} (not of this session)", uid()))).await, "{}", client.log());
    assert_eq!(relay.requests(), 0);
}

/// `--agent-uid` the test's uid plus one: `forbidden_peer`, `(uid)`. Kills M-V39.
#[tokio::test]
async fn a_peer_of_another_uid_is_refused() {
    let pki = Pki::new("IP:127.0.0.1");
    let token = token();
    let relay = FakeRelay::start(&pki, &token, echo_sources()).await;
    let session = session_json(&token, &relay.addr.to_string(), "127.0.0.1", &pki.ca_b64());
    let client = spawn_client(Some(session.as_bytes()), std::process::id(), uid() + 1, &[]);
    client.wait_ready().await;
    let answer = client.ask(r#"{"kind":"catalog","v":1}"#).await;
    assert_eq!(answer, json!({"kind": "error", "v": 1, "code": "forbidden_peer", "message": format!("uid {} is not the agent's", uid())}));
    let refused = format!("refused peer pid={} uid={} (uid)", std::process::id(), uid());
    assert!(eventually(LIMIT, || client.log().contains(&refused)).await, "{}", client.log());
}

/// Eight `slow` calls held in the fake, a ninth answered `busy` at once; after the release all eight are answered.
/// Kills M-V45 (the client's cap).
#[tokio::test]
async fn the_ninth_connection_is_busy() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut held = Vec::new();
    for _ in 0..8 {
        let mut s = tokio::net::UnixStream::connect(&r.client.socket).await.unwrap();
        s.write_all(b"{\"kind\":\"call\",\"v\":1,\"source\":\"slow\",\"op\":\"wait\"}\n").await.unwrap();
        held.push(s);
    }
    assert!(eventually(LIMIT, || r.relay.requests() == 8).await, "eight calls at the relay");
    let t = Instant::now();
    let busy = r.client.ask(r#"{"kind":"catalog","v":1}"#).await;
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(busy, json!({"kind": "error", "v": 1, "code": "busy", "message": "8 calls in flight"}));
    assert!(eventually(LIMIT, || r.client.log().contains("ai-env-relay-client: busy (8 connections)")).await, "{}", r.client.log());
    r.relay.release();
    for mut s in held {
        let mut out = String::new();
        tokio::time::timeout(LIMIT, s.read_to_string(&mut out)).await.unwrap().unwrap();
        let answer: Value = serde_json::from_str(out.trim_end()).unwrap();
        assert_eq!((answer["kind"].as_str(), answer["text"].as_str()), (Some("result"), Some("released")), "{answer}");
    }
}

/// With `--channel-idle-ms 100`, two calls 300 ms apart make two TLS connections at the fake; with 60 000, one.
/// Control.
#[tokio::test]
async fn the_channel_is_dialled_anew_after_the_idle_drop() {
    for (idle, want) in [("100", 2), ("60000", 1)] {
        let r = Rig::new(echo_sources(), &["--channel-idle-ms", idle]).await;
        let call = r#"{"kind":"call","v":1,"source":"echo","op":"echo","params":{"x":1}}"#;
        assert_eq!(r.client.ask(call).await["kind"], "result");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(r.client.ask(call).await["kind"], "result");
        assert_eq!(r.relay.seen.handshakes.load(Ordering::SeqCst), want, "--channel-idle-ms {idle}");
    }
}

/// `--leader` a `sleep 60` child, killed: the client exits 0 within 4 s, its socket gone, `exit (leader gone)`.
/// Kills M-V46 (the leader poll).
#[tokio::test]
async fn the_client_exits_when_its_leader_is_gone() {
    let pki = Pki::new("IP:127.0.0.1");
    let mut leader = sleeper();
    let session = session_json(&token(), "127.0.0.1:1", "127.0.0.1", &pki.ca_b64());
    let mut client = spawn_client(Some(session.as_bytes()), leader.id().unwrap(), uid(), &[]);
    client.wait_ready().await;
    leader.kill().await.unwrap();
    let t = Instant::now();
    assert_eq!(client.exit_within(Duration::from_secs(4)).await, Some(0), "{}", client.log());
    assert!(t.elapsed() < Duration::from_secs(4));
    assert!(!client.socket.exists(), "the socket went with it");
    assert!(eventually(LIMIT, || client.log().ends_with("ai-env-relay-client: exit (leader gone)\n")).await, "{}", client.log());
}

/// SIGTERM: exit 0 within 1 s, the socket gone, `exit (term)`; a client SIGKILLed leaves its socket, and a new one
/// on the same path binds over it. Control.
#[tokio::test]
async fn term_ends_the_client_and_removes_its_socket() {
    let pki = Pki::new("IP:127.0.0.1");
    let session = session_json(&token(), "127.0.0.1:1", "127.0.0.1", &pki.ca_b64());
    let mut client = spawn_client(Some(session.as_bytes()), std::process::id(), uid(), &[]);
    client.wait_ready().await;
    let pid = libc::pid_t::try_from(client.child.id().unwrap()).unwrap();
    // SAFETY: a signal to the child this test started.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(client.exit_within(Duration::from_secs(1)).await, Some(0), "{}", client.log());
    assert!(!client.socket.exists());
    assert!(eventually(LIMIT, || client.log().ends_with("ai-env-relay-client: exit (term)\n")).await, "{}", client.log());
    // KILL leaves the socket; the next client on its path binds over it.
    let mut killed = spawn_client(Some(session.as_bytes()), std::process::id(), uid(), &[]);
    killed.wait_ready().await;
    killed.child.kill().await.unwrap();
    assert!(killed.socket.exists(), "a KILLed client leaves its socket");
    let (mut next, log) = spawn_client_at(Some(session.as_bytes()), std::process::id(), uid(), &killed.socket, killed.dir.path(), &[]);
    assert!(eventually(LIMIT, || log.lock().unwrap().contains("ai-env-relay-client: ready ")).await, "{}", log.lock().unwrap());
    let answer = ask_at(&killed.socket, "hello").await;
    assert_eq!(answer["code"], "bad_request", "the new client serves the path: {answer}");
    let _ = next.kill().await;
}

/// Each bad payload of V-R16 (too large, not JSON, `v` 2, a bad token, a public addr, a CA that is no certificate),
/// and no fd 3: exit 2, `refused: session <field>` (`refused: fd 3 …`), no socket made, the token in no line. Kills
/// M-V37.
#[tokio::test]
async fn a_bad_session_on_fd_3_refuses_to_start() {
    let pki = Pki::new("IP:127.0.0.1");
    let token = token();
    let good = session_json(&token, "10.42.0.20:7443", "10.42.0.20", &pki.ca_b64());
    let cases: Vec<(Option<String>, &str)> = vec![
        (Some(format!("{good}{}", " ".repeat(8193 - good.len()))), "refused: session size"),
        (Some("{not json".to_string()), "refused: session json"),
        (Some(good.replace("\"v\":1", "\"v\":2")), "refused: session v"),
        (Some(session_json(&format!("{token} x"), "10.42.0.20:7443", "10.42.0.20", &pki.ca_b64())), "refused: session token"),
        (Some(session_json(&token, "203.0.113.7:7443", "10.42.0.20", &pki.ca_b64())), "refused: session addr"),
        (Some(session_json(&token, "10.42.0.20:7443", "10.42.0.20", "MA==")), "refused: session ca_der_b64"),
        (None, "refused: fd 3 is not open"),
    ];
    for (payload, want) in cases {
        let mut c = spawn_client(payload.as_deref().map(str::as_bytes), std::process::id(), uid(), &[]);
        assert_eq!(c.exit_within(LIMIT).await, Some(2), "{want}: {}", c.log());
        assert!(eventually(LIMIT, || c.log().contains(want)).await, "{want}: {}", c.log());
        assert!(!c.socket.exists(), "{want}: no socket");
        assert!(!c.log().contains(&token) && !c.log().contains(&pki.ca_b64()), "{want}: {}", c.log());
    }
}

/// `--socket-dir` an empty directory: `relay_catalog` is `isError`, `no_session`, §V-vm.3.6's message. Control.
#[tokio::test]
async fn the_mcp_server_says_no_session_without_a_socket() {
    let empty = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(&["--socket-dir", empty.path().to_str().unwrap()]).await;
    let (text, is_error) = m.tool(1, "relay_catalog", json!({})).await;
    assert!(is_error);
    assert_eq!(text, json!({"error": {"code": "no_session", "message": "this chat has no relay session (it was not started with one)"}}));
    let (text, _) = m.tool(2, "relay_call", json!({"source": "echo", "op": "echo"})).await;
    assert_eq!(text["error"]["code"], "no_session", "{text}");
    m.close();
    let status = tokio::time::timeout(LIMIT, m.child.wait()).await.unwrap().unwrap();
    assert_eq!(status.code(), Some(0), "stdin's EOF ends it");
    assert_eq!(m.stderr.lock().unwrap().as_str(), "", "nothing on stderr");
}

/// `slow` `wait` with `deadline_ms` 100 and a fake that never answers: `isError`, `deadline_exceeded` within 5.5 s
/// (V-R23's ceiling, `min(deadline_ms + 5 s, DEADLINE_CAP_MS + 5 s)`), and the fake saw its stream dropped; the line
/// names the call by its stream's head. Kills M-V55, M-V59, M-V60.
#[tokio::test]
async fn a_call_past_its_ceiling_is_deadline_exceeded() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut m = r.mcp().await;
    let t = Instant::now();
    let (text, is_error) = m.tool(1, "relay_call", json!({"source": "slow", "op": "wait", "deadline_ms": 100})).await;
    let took = t.elapsed();
    assert!(is_error, "{text}");
    assert_eq!(text["error"]["code"], "deadline_exceeded", "{text}");
    assert!(took >= Duration::from_secs(5) && took < Duration::from_millis(5_500), "{took:?}");
    assert_eq!(r.relay.seen.last_call.lock().unwrap().map(|c| c.0), Some(100), "the relay got the deadline");
    assert!(eventually(Duration::from_secs(2), || r.relay.seen.dropped.load(Ordering::SeqCst) == 1).await, "the stream was dropped");
    let line = format!("ai-env-relay-client: call {REQUEST_ID} outcome=deadline_exceeded bytes=0");
    assert!(eventually(LIMIT, || r.client.log().contains(&line)).await, "{}", r.client.log());
}

/// A raw connection that sends nothing is closed after `REQUEST_WAIT` (the real 10 s) and its slot is free again:
/// with eight such connections, a ninth is `busy`, and one succeeds once the first are dropped (V-R19). Kills M-V56.
#[tokio::test]
async fn a_silent_peer_is_dropped_after_the_request_wait() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut silent = Vec::new();
    for _ in 0..8 {
        silent.push(tokio::net::UnixStream::connect(&r.client.socket).await.unwrap());
    }
    // Each silent connection takes its slot once the client accepts it: until then a ninth is served (`bad_request`).
    let until = Instant::now() + LIMIT;
    while r.client.ask("hello").await["code"] != "busy" {
        assert!(Instant::now() < until, "the eight silent connections never filled the client");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let t = Instant::now();
    for mut s in silent {
        let mut out = String::new();
        tokio::time::timeout(Duration::from_secs(15), s.read_to_string(&mut out)).await.expect("closed within the request wait").unwrap();
        assert!(out.contains("\"code\":\"bad_request\"") && out.contains("no request line within 10 s"), "{out}");
    }
    assert!(t.elapsed() >= Duration::from_secs(9), "{:?}", t.elapsed());
    let answer = r.client.ask(r#"{"kind":"call","v":1,"source":"echo","op":"echo","params":{"y":2}}"#).await;
    assert_eq!((answer["kind"].as_str(), answer["json"].clone()), (Some("result"), json!({"y": 2})), "{answer}");
}

/// Across a positive run (the catalog, a call, an error), the client's whole stderr and the MCP server's stdout and
/// stderr hold neither the token nor the CA's base64. Kills M-V53.
#[tokio::test]
async fn no_line_of_the_client_holds_the_token() {
    let r = Rig::new(echo_sources(), &[]).await;
    let mut m = r.mcp().await;
    let (_, is_error) = m.tool(1, "relay_catalog", json!({})).await;
    assert!(!is_error);
    let (_, is_error) = m.tool(2, "relay_call", json!({"source": "echo", "op": "echo", "params": {"x": 1}})).await;
    assert!(!is_error);
    let (_, is_error) = m.tool(3, "relay_call", json!({"source": "fail", "op": "denied"})).await;
    assert!(is_error);
    m.close();
    let _ = tokio::time::timeout(LIMIT, m.child.wait()).await;
    let ca = r.pki.ca_b64();
    for (what, text) in [("client stderr", r.client.log()), ("mcp stdout", m.stdout_seen.clone()), ("mcp stderr", m.stderr.lock().unwrap().clone())] {
        assert!(!text.contains(&r.token), "{what} holds the token");
        assert!(!text.contains(&ca), "{what} holds the CA");
    }
    assert!(r.client.log().contains(&format!("ready leader={} socket={} relay={} name=127.0.0.1 ca=", std::process::id(), r.client.socket.display(), r.relay.addr)), "{}", r.client.log());
}
