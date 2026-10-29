//! The relay in-process (§R-relay.7, relay 1 to 33): tonic over `tokio::io::duplex` with the rig of
//! `tests/common`. Tests marked "paused" run on tokio's paused clock and assert virtual time.

mod common;

use std::time::Duration;

use ai_env_relay::files::{content_version, Poll, FETCHED_FILE};
use ai_env_relay::lists::{GRANTS_FILE, SIGNERS_FILE, WORKERS_FILE};
use ai_env_relay::reqlog::{CALL_KEYS, STATUS_KEYS};
use ai_env_relay::Limits;
use ai_env_relay_proto::v1::{relay_frame, worker_frame, CallChunk, CallRequest, Catalog, Chunk, Limits as WireLimits, WorkerFrame};
use ai_env_worker::session::SessionClaims;
use common::rig::*;
use common::worker::*;
use tokio::time::Instant;
use tonic::Code;

fn keys_of(v: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

fn sorted(set: &[&str]) -> Vec<String> {
    let mut k: Vec<String> = set.iter().map(|s| s.to_string()).collect();
    k.sort();
    k
}

fn final_code(c: &CallChunk) -> Option<i32> {
    c.error.as_ref().map(|e| e.code)
}

/// Relay 1.
#[tokio::test]
async fn a_worker_authenticates_and_its_catalog_is_listed() {
    let rig = Rig::start().await;
    // `open` reads the first frame before this worker has sent anything.
    let mut a = TestWorker::open(&rig).await;
    assert_eq!(a.challenge.nonce.len(), 32);
    assert_eq!(a.challenge.relay_id, "relay-test");
    assert_eq!(a.challenge.protocol, 1);
    let ok = a.authenticate("worker-a", 1).await.expect("authenticated");
    assert_eq!(uuid::Uuid::parse_str(&ok.tunnel_id).unwrap().get_version_num(), 7);
    assert_eq!(ok.whitelist_version, content_version(&rig.read(WORKERS_FILE)));
    a.register(catalog_a()).await;
    rig.until(Duration::from_secs(10), "two live sources", |r| r.app.snapshot().sources_live == 2).await;
    let mut client = rig.client().await;
    let listed = list(&mut client, &rig.token("g-all")).await.expect("listed");
    assert_eq!(names(&listed), vec![("example.alpha".to_string(), true), ("example.alpha.logs".to_string(), true)]);
    for s in &listed.sources {
        assert!((s.last_seen_unix_ms - rig.clock.ms()).abs() <= 1000, "{}", s.last_seen_unix_ms);
    }
    let auth: Vec<_> = rig.lines("tunnel").into_iter().filter(|l| l["phase"] == "auth").collect();
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0]["outcome"], "ok");
    assert_eq!(auth[0]["worker"], "worker-a");
    assert_eq!(auth[0]["tunnel"], ok.tunnel_id.as_str());
}

/// Relay 2.
#[tokio::test]
async fn each_auth_fault_is_the_same_authentication_failed() {
    let rig = Rig::start().await;
    let expired = Rig::start().await;
    expired.write_workers(&[worker_entry("worker-a", 1, &["example.alpha*"], "2027-01-15T07:00:00Z")]);
    expired.poll();
    type Case = (&'static str, bool, Box<dyn Fn(&Challenge) -> Vec<worker_frame::Msg>>);
    use ai_env_relay_proto::v1::Challenge;
    let cases: Vec<Case> = vec![
        (
            "bad_signature",
            false,
            Box::new(|c| {
                let h = hello("worker-a", 1);
                let mut p = proof(c, &h, 1);
                p.signature[0] ^= 1;
                vec![worker_frame::Msg::Hello(h), worker_frame::Msg::AuthProof(p)]
            }),
        ),
        (
            "unknown_worker",
            false,
            Box::new(|c| {
                let h = hello("worker-z", 1);
                let p = proof(c, &h, 1);
                vec![worker_frame::Msg::Hello(h), worker_frame::Msg::AuthProof(p)]
            }),
        ),
        (
            "unknown_worker",
            false,
            Box::new(|c| {
                let h = hello("worker-a", 4);
                let p = proof(c, &h, 4);
                vec![worker_frame::Msg::Hello(h), worker_frame::Msg::AuthProof(p)]
            }),
        ),
        (
            "expired",
            true,
            Box::new(|c| {
                let h = hello("worker-a", 1);
                let p = proof(c, &h, 1);
                vec![worker_frame::Msg::Hello(h), worker_frame::Msg::AuthProof(p)]
            }),
        ),
        (
            "bad_alg",
            false,
            Box::new(|c| {
                let h = ai_env_relay_proto::v1::Hello { alg: 0, ..hello("worker-a", 1) };
                let p = proof(c, &h, 1);
                vec![worker_frame::Msg::Hello(h), worker_frame::Msg::AuthProof(p)]
            }),
        ),
        (
            "bad_protocol",
            false,
            Box::new(|c| {
                let h = ai_env_relay_proto::v1::Hello { protocol: 2, ..hello("worker-a", 1) };
                let p = proof(c, &h, 1);
                vec![worker_frame::Msg::Hello(h), worker_frame::Msg::AuthProof(p)]
            }),
        ),
        (
            "malformed",
            false,
            Box::new(|c| {
                let mut h = hello("worker-a", 1);
                h.public_key.truncate(31);
                let p = proof(c, &h, 1);
                vec![worker_frame::Msg::Hello(h), worker_frame::Msg::AuthProof(p)]
            }),
        ),
        (
            "out_of_order",
            false,
            Box::new(|c| {
                let h = hello("worker-a", 1);
                let p = proof(c, &h, 1);
                vec![worker_frame::Msg::AuthProof(p), worker_frame::Msg::Hello(h)]
            }),
        ),
        (
            "out_of_order",
            false,
            Box::new(|_| vec![worker_frame::Msg::Hello(hello("worker-a", 1)), worker_frame::Msg::Catalog(Catalog { sources: catalog_a() })]),
        ),
    ];
    for (reason, on_expired, frames) in cases {
        let rig = if on_expired { &expired } else { &rig };
        let mut w = TestWorker::open(rig).await;
        for f in frames(&w.challenge) {
            w.send(f).await;
        }
        let (after, end) = w.rest().await;
        // R-11: no frame after the Challenge, so no AuthOk.
        assert!(after.is_empty(), "{reason}: {after:?}");
        let status = end.expect_err("refused");
        assert_eq!((status.code(), status.message()), (Code::Unauthenticated, "authentication failed"), "{reason}");
        let line = rig.lines("tunnel").pop().unwrap();
        assert_eq!((line["outcome"].as_str(), line["reason"].as_str()), (Some("refused"), Some(reason)));
        assert_eq!(rig.app.snapshot().tunnels, 0);
    }
    // The stream closed after the Hello.
    let w = TestWorker::open(&rig).await;
    w.send(worker_frame::Msg::Hello(hello("worker-a", 1))).await;
    let TestWorker { out, mut inbound, .. } = w;
    drop(out);
    let status = match inbound.message().await {
        Ok(Some(f)) => panic!("no frame after the Challenge: {f:?}"),
        Ok(None) => panic!("ended with status 0"),
        Err(s) => s,
    };
    assert_eq!((status.code(), status.message()), (Code::Unauthenticated, "authentication failed"));
    assert_eq!(rig.lines("tunnel").pop().unwrap()["reason"], "eof");
    assert_eq!(rig.app.snapshot().tunnels, 0);
}

/// Relay 3 (paused).
#[tokio::test(start_paused = true)]
async fn the_handshake_has_five_seconds() {
    let rig = Rig::start().await;
    let mut w = TestWorker::open(&rig).await;
    let t0 = Instant::now();
    let status = w.end().await.expect_err("no Hello");
    let took = t0.elapsed();
    assert_eq!(status.code(), Code::Unauthenticated);
    assert!(took >= Duration::from_millis(4999) && took <= Duration::from_millis(5000), "{took:?}");
    assert_eq!(rig.lines("tunnel").pop().unwrap()["reason"], "timeout");

    let mut w = TestWorker::open(&rig).await;
    let t0 = Instant::now();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let h = hello("worker-a", 1);
    let p = proof(&w.challenge, &h, 1);
    w.send(worker_frame::Msg::Hello(h)).await;
    let out = w.out.clone();
    tokio::spawn(async move {
        tokio::time::sleep_until(t0 + Duration::from_millis(5100)).await;
        let _ = out.send(wf(worker_frame::Msg::AuthProof(p))).await;
    });
    let status = w.end().await.expect_err("the budget is not restarted by the Hello");
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(t0.elapsed(), Duration::from_secs(5));

    let mut w = TestWorker::open(&rig).await;
    tokio::time::sleep(Duration::from_millis(4900)).await;
    w.authenticate("worker-a", 1).await.expect("both at 4.9 s");
}

/// Relay 4.
#[tokio::test]
async fn a_captured_proof_never_opens_a_second_tunnel() {
    let rig = Rig::start().await;
    let mut t1 = TestWorker::open(&rig).await;
    let h = hello("worker-a", 1);
    let p = proof(&t1.challenge, &h, 1);
    t1.send(worker_frame::Msg::Hello(h.clone())).await;
    t1.send(worker_frame::Msg::AuthProof(p.clone())).await;
    assert!(matches!(t1.next().await.unwrap().unwrap().msg, Some(relay_frame::Msg::AuthOk(_))));
    t1.register(catalog_a()).await;
    rig.until(Duration::from_secs(10), "installed", |r| r.app.snapshot().sources_live == 2).await;
    let nonce1 = t1.challenge.nonce.clone();
    let t1 = t1.serve(Script::echo("worker-a"));

    let mut t2 = TestWorker::open(&rig).await;
    assert_ne!(t2.challenge.nonce, nonce1, "a fresh nonce per connection");
    t2.send(worker_frame::Msg::Hello(h)).await;
    t2.send(worker_frame::Msg::AuthProof(p)).await;
    let status = t2.end().await.expect_err("a replayed proof");
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(rig.lines("tunnel").pop().unwrap()["reason"], "bad_signature");
    assert_eq!(rig.app.snapshot().tunnels, 1);
    let mut client = rig.client().await;
    let (chunks, end) = drain(call(&mut client, &rig.token("g-all"), "example.alpha", "get", b"{\"n\":1}").await.unwrap()).await;
    assert!(end.is_ok());
    assert_eq!(chunks.len(), 1);
    assert_eq!(t1.invokes().len(), 1, "tunnel 1 still routes");
}

/// Relay 4's nonces: each connection's Challenge is its own.
#[tokio::test]
async fn every_challenge_has_its_own_nonce() {
    let rig = Rig::start().await;
    let a = TestWorker::open(&rig).await;
    let b = TestWorker::open(&rig).await;
    assert_ne!(a.challenge.nonce, b.challenge.nonce);
}

/// Relay 5.
#[tokio::test]
async fn the_whitelist_fails_closed_until_first_loaded() {
    let rig = Rig::start_without(limits(), &[WORKERS_FILE]).await;
    let mut a = TestWorker::open(&rig).await;
    let h = hello("worker-a", 1);
    let p = proof(&a.challenge, &h, 1);
    a.send(worker_frame::Msg::Hello(h)).await;
    a.send(worker_frame::Msg::AuthProof(p)).await;
    assert_eq!(a.end().await.expect_err("never loaded").code(), Code::Unauthenticated);
    assert_eq!(rig.lines("tunnel").pop().unwrap()["reason"], "not_loaded");
    rig.write_workers(&default_workers());
    rig.write_fetched(rig.clock.unix());
    rig.poll();
    TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
}

fn reloads(rig: &Rig, file: &str) -> Vec<serde_json::Value> {
    rig.lines("reload").into_iter().filter(|l| l["file"] == file).collect()
}

async fn refused_reason(rig: &Rig, worker_id: &str, seed: u8) -> String {
    let mut w = TestWorker::open(rig).await;
    let h = hello(worker_id, seed);
    let p = proof(&w.challenge, &h, seed);
    w.send(worker_frame::Msg::Hello(h)).await;
    w.send(worker_frame::Msg::AuthProof(p)).await;
    let status = w.end().await.expect_err("refused");
    assert_eq!(status.code(), Code::Unauthenticated);
    rig.lines("tunnel").pop().unwrap()["reason"].as_str().unwrap().to_string()
}

/// Relay 6.
#[tokio::test]
async fn a_stale_whitelist_closes_tunnels_and_refuses_handshakes() {
    let rig = Rig::start().await;
    let mut a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
    let before = reloads(&rig, "workers").len();
    rig.clock.set(T0 + 901);
    assert_eq!(rig.poll()[0].1, Poll::Stale);
    let close = a.close().await;
    assert_eq!((close.code, close.reason.as_str()), (6, "the whitelist is stale"));
    let lines = reloads(&rig, "workers");
    assert_eq!(lines.len(), before + 1);
    assert_eq!(lines.last().unwrap()["outcome"], "stale");
    assert_eq!(refused_reason(&rig, "worker-a", 1).await, "stale");
    rig.write_fetched(rig.clock.unix());
    rig.poll();
    TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
}

/// Relay 7.
#[tokio::test]
async fn a_missing_or_refused_whitelist_fails_closed_at_once() {
    let rig = Rig::start().await;
    let good = rig.read(WORKERS_FILE);
    let mut a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
    rig.remove(WORKERS_FILE);
    assert_eq!(rig.poll()[0].1, Poll::Missing);
    let close = a.close().await;
    assert_eq!((close.code, close.reason.as_str()), (6, "the whitelist is not loaded"));
    assert_eq!(reloads(&rig, "workers").last().unwrap()["outcome"], "missing");
    assert_eq!(refused_reason(&rig, "worker-a", 1).await, "not_loaded");

    rig.write(WORKERS_FILE, &good);
    rig.poll();
    let mut a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
    rig.write(WORKERS_FILE, b"[{\"worker_id\":\"worker-a\"");
    assert!(matches!(rig.poll()[0].1, Poll::Refused(_)));
    let close = a.close().await;
    assert_eq!((close.code, close.reason.as_str()), (6, "the whitelist is not loaded"));
    assert_eq!(reloads(&rig, "workers").last().unwrap()["outcome"], "refused");
    assert_eq!(refused_reason(&rig, "worker-a", 1).await, "not_loaded");

    rig.write(WORKERS_FILE, &good);
    rig.poll();
    let _a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    rig.remove(GRANTS_FILE);
    rig.poll();
    let mut client = rig.client().await;
    let refused = call(&mut client, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect_err("grants not loaded");
    assert_eq!((refused.code(), refused.message()), (Code::Unavailable, "grants not loaded"));
}

/// Relay 8.
#[tokio::test]
async fn revocation_closes_the_live_tunnel() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let mut stream = call(&mut client, &token, "example.alpha", "get", b"{}").await.unwrap();
    a.invoke(0).await;
    rig.write_workers(&default_workers()[1..]);
    rig.poll();
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (1, "revoked"));
    let last = stream.message().await.unwrap().expect("a final chunk");
    assert!(last.r#final);
    assert_eq!(final_code(&last), Some(14));
    let listed = list(&mut client, &token).await.unwrap();
    assert!(names(&listed).iter().all(|(n, _)| !n.starts_with("example.alpha")), "removed, not offline: {:?}", names(&listed));
    assert_eq!(refused_reason(&rig, "worker-a", 1).await, "unknown_worker");
    assert_eq!(rig.lines("tunnel").iter().rfind(|l| l["phase"] == "close").unwrap()["reason"], "revoked");
}

/// Relay 9.
#[tokio::test]
async fn narrowed_globs_revoke_and_widened_globs_do_not() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut workers = default_workers();
    workers[0].sources = vec!["other.*".into()];
    rig.write_workers(&workers);
    rig.poll();
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (1, "sources narrowed"));

    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut workers = default_workers();
    workers[0].sources = vec!["example.*".into(), "more.*".into()];
    workers[0].not_after = "2027-12-31T23:59:59Z".into();
    rig.write_workers(&workers);
    rig.poll();
    rig.poll();
    let mut client = rig.client().await;
    let (chunks, end) = drain(call(&mut client, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect("still routed")).await;
    assert!(end.is_ok() && chunks.len() == 1 && final_code(&chunks[0]).is_none());
    assert!(a.closes().is_empty(), "wider globs and a later not_after close nothing");
    assert_eq!(rig.app.snapshot().tunnels, 1);
}

/// Relay 10.
#[tokio::test]
async fn not_after_passing_closes_the_tunnel() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let not_after = ai_env_worker::policy::unix_of(NOT_AFTER).unwrap();
    rig.clock.set(not_after + 1);
    rig.write_fetched(rig.clock.unix());
    rig.poll();
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (1, "expired"));
}

async fn refused_catalog(rig: &Rig, worker_id: &str, seed: u8, sources: Vec<ai_env_relay_proto::v1::SourceDescriptor>) -> (u32, String) {
    let mut w = TestWorker::open(rig).await;
    w.authenticate(worker_id, seed).await.expect("authenticated");
    w.register(sources).await;
    let close = w.close().await;
    (close.code, close.reason)
}

/// Relay 11 (paused, for its (f)).
#[tokio::test(start_paused = true)]
async fn a_catalog_outside_the_globs_or_twice_is_refused() {
    let rig = Rig::start().await;
    // (a)
    let (code, reason) = refused_catalog(&rig, "worker-a", 1, vec![source("other.x", &["get"])]).await;
    assert_eq!((code, reason.as_str()), (4, "source other.x is not allowed for this worker"));
    assert_eq!(rig.app.snapshot().sources_live + rig.app.snapshot().sources_offline, 0, "nothing registered");
    // (b)
    let (code, reason) = refused_catalog(&rig, "worker-a", 1, vec![source("example.alpha", &["get"]), source("example.alpha", &["get"])]).await;
    assert_eq!((code, reason.as_str()), (4, "source example.alpha is listed twice"));
    // (c)
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut workers = default_workers();
    workers[2].sources = vec!["example.*".into()];
    rig.write_workers(&workers);
    rig.poll();
    let (code, reason) = refused_catalog(&rig, "worker-c", 5, vec![source("example.alpha", &["get"])]).await;
    assert_eq!((code, reason.as_str()), (4, "source example.alpha is served by another worker"));
    let mut client = rig.client().await;
    let (chunks, _) = drain(call(&mut client, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect("A unaffected")).await;
    assert_eq!(chunks.len(), 1);
    assert!(a.closes().is_empty());
    // (d)
    a.link.as_ref().unwrap().cut();
    rig.until(Duration::from_secs(10), "A gone", |r| r.app.snapshot().tunnels == 0).await;
    let c = TestWorker::connect(&rig, "worker-c", 5, vec![source("example.alpha", &["get"])]).await.serve(Script::echo("worker-c"));
    let (chunks, _) = drain(call(&mut client, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect("C took it")).await;
    let body: serde_json::Value = serde_json::from_slice(&chunks[0].data).unwrap();
    assert_eq!(body["worker"], "worker-c");
    drop(c);
    // (e)
    let all = Rig::start().await;
    all.write_workers(&[worker_entry("worker-a", 1, &["*"], NOT_AFTER)]);
    all.poll();
    let mut bad_op = source("example.alpha", &["get"]);
    bad_op.ops[0].name = "Bad".into();
    let mut bad_schema = source("example.alpha", &["get"]);
    bad_schema.ops[0].params_json_schema = "not json".into();
    let mut long = source("example.alpha", &["get"]);
    long.description = "d".repeat(2049);
    for catalog in [(0..65).map(|i| source(&format!("example.s{i}"), &["get"])).collect(), vec![bad_op], vec![bad_schema], vec![long]] {
        assert_eq!(refused_catalog(&all, "worker-a", 1, catalog).await.0, 4);
    }
    // (f)
    let mut w = TestWorker::open(&all).await;
    w.authenticate("worker-a", 1).await.unwrap();
    let t0 = Instant::now();
    let close = w.close().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "no catalog within 5 s"));
    assert_eq!(t0.elapsed(), Duration::from_secs(5));
}

/// Relay 12.
#[tokio::test]
async fn a_reconnect_never_unroutes_the_new_tunnel() {
    let rig = Rig::start().await;
    let mut t1 = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
    let mut t2 = TestWorker::open(&rig).await;
    t2.authenticate("worker-a", 1).await.expect("the same key");
    t2.register(catalog_a()).await;
    let superseded = |r: &Rig| r.lines("tunnel").iter().any(|l| l["phase"] == "close" && l["reason"] == "superseded");
    rig.until(Duration::from_secs(10), "tunnel 1's teardown", superseded).await;
    assert_eq!(rig.app.snapshot().tunnels, 1);
    // R-65: the close line counts the sources tunnel 1 had, although tunnel 2 has repointed them.
    let line = rig.lines("tunnel").into_iter().find(|l| l["phase"] == "close" && l["reason"] == "superseded").unwrap();
    assert_eq!(line["sources"], 2);
    let close = t1.close().await;
    assert_eq!(close.code, 2);
    let t1_link = t1.link.take();
    let t2 = t2.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let (chunks, _) = drain(call(&mut client, &token, "example.alpha", "get", b"{\"n\":1}").await.expect("routed to tunnel 2")).await;
    assert_eq!(chunks.len(), 1);
    assert_eq!(t2.invokes().len(), 1);
    t1_link.unwrap().cut();
    drop(t1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (chunks, _) = drain(call(&mut client, &token, "example.alpha", "get", b"{\"n\":2}").await.expect("a second call")).await;
    assert_eq!(chunks.len(), 1);
    assert_eq!(t2.invokes().len(), 2);
    let listed = list(&mut client, &token).await.unwrap();
    assert!(names(&listed).contains(&("example.alpha".to_string(), true)));
}

/// R-23 and R-26 (amended; paused): tunnel 1 ends and its names stay listed offline; tunnel 2 of the same worker
/// sends a narrower catalog, and the name it left out is gone, not offline, although tunnel 1 was torn down first.
#[tokio::test(start_paused = true)]
async fn a_narrower_catalog_after_a_restart_drops_the_old_names() {
    let rig = Rig::start().await;
    let t1 = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
    t1.link.as_ref().unwrap().cut();
    rig.until(Duration::from_secs(10), "tunnel 1's teardown", |r| r.app.snapshot().tunnels == 0).await;
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let listed = list(&mut client, &token).await.unwrap();
    assert_eq!(names(&listed), vec![("example.alpha".to_string(), false), ("example.alpha.logs".to_string(), false)]);

    let _t2 = TestWorker::connect(&rig, "worker-a", 1, vec![source("example.alpha", &["get", "list"])]).await.serve(Script::echo("worker-a"));
    let listed = list(&mut client, &token).await.unwrap();
    assert_eq!(names(&listed), vec![("example.alpha".to_string(), true)]);
    let gone = call(&mut client, &token, "example.alpha.logs", "get", b"{}").await.expect_err("dropped");
    assert_eq!((gone.code(), gone.message()), (Code::NotFound, "no such source"));
    let (chunks, _) = drain(call(&mut client, &token, "example.alpha", "get", b"{}").await.expect("routed to tunnel 2")).await;
    assert_eq!(chunks.len(), 1);
    let s = rig.app.snapshot();
    assert_eq!((s.sources_live, s.sources_offline), (1, 0));
}

/// R-26 (amended; paused): stopped workers stay listed offline while the whitelist allows them; once one is revoked,
/// or narrowed, the next `poll_files()` leaves nothing of it listed, with no tunnel live to close, and the other's
/// names stay.
#[tokio::test(start_paused = true)]
async fn a_stopped_worker_revoked_or_narrowed_is_listed_no_more() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
    let b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await;
    for w in [&a, &b] {
        w.link.as_ref().unwrap().cut();
    }
    rig.until(Duration::from_secs(10), "both stopped", |r| r.app.snapshot().tunnels == 0).await;
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    rig.poll();
    let all = vec![("example.alpha".to_string(), false), ("example.alpha.logs".to_string(), false), ("example.beta".to_string(), false)];
    assert_eq!(names(&list(&mut client, &token).await.unwrap()), all, "a poll drops nothing the whitelist allows");

    rig.write_workers(&default_workers()[1..]);
    rig.poll();
    assert_eq!(names(&list(&mut client, &token).await.unwrap()), vec![("example.beta".to_string(), false)]);
    let gone = call(&mut client, &token, "example.alpha", "get", b"{}").await.expect_err("revoked");
    assert_eq!((gone.code(), gone.message()), (Code::NotFound, "no such source"));

    let mut workers = default_workers();
    workers[1].sources = vec!["example.beta.*".into()];
    rig.write_workers(&workers);
    rig.poll();
    assert!(list(&mut client, &token).await.unwrap().sources.is_empty(), "B narrowed past example.beta");
    let s = rig.app.snapshot();
    assert_eq!((s.tunnels, s.sources_live, s.sources_offline), (0, 0, 0));
}

/// R-26 (amended; paused; review finding 3): the sweep runs on every fresh poll, not only on one that loads a new
/// workers file. A's entry lapses while workers.json stays as it was and no tunnel is live: the next poll leaves
/// nothing of A listed, and B's name stays.
#[tokio::test(start_paused = true)]
async fn a_stopped_worker_past_its_not_after_is_listed_no_more() {
    const A_NOT_AFTER: &str = "2027-02-01T00:00:00Z"; // after T0, before NOT_AFTER
    let rig = Rig::start().await;
    let mut workers = default_workers();
    workers[0].not_after = A_NOT_AFTER.into();
    rig.write_workers(&workers);
    rig.poll();
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
    let b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await;
    for w in [&a, &b] {
        w.link.as_ref().unwrap().cut();
    }
    rig.until(Duration::from_secs(10), "both stopped", |r| r.app.snapshot().tunnels == 0).await;
    let mut client = rig.client().await;
    let all = vec![("example.alpha".to_string(), false), ("example.alpha.logs".to_string(), false), ("example.beta".to_string(), false)];
    assert_eq!(names(&list(&mut client, &rig.token("g-all")).await.unwrap()), all, "A in force: listed offline");

    rig.clock.set(ai_env_worker::policy::unix_of(A_NOT_AFTER).unwrap() + 1);
    rig.write_fetched(rig.clock.unix());
    let polled = rig.poll();
    assert!(matches!(polled[0], ("workers", Poll::Unchanged)), "workers.json untouched");
    assert_eq!(names(&list(&mut client, &rig.token("g-all")).await.unwrap()), vec![("example.beta".to_string(), false)]);
    let s = rig.app.snapshot();
    assert_eq!((s.tunnels, s.sources_live, s.sources_offline), (0, 0, 1));
}

/// Relay 13.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_thousand_interleaved_calls_never_cross() {
    let l = Limits {
        calls_in_flight_max: 2048,
        calls_per_tunnel: 1024,
        calls_per_session: 512,
        session_burst: 10_000,
        session_per_min: 60_000,
        tunnel_queue: 1024,
        ..limits()
    };
    let rig = Rig::start_with(l).await;
    let c = TestWorker::connect(&rig, "worker-c", 5, catalog_c()).await.serve(Script::silent());
    let forger = c.out.clone();
    let delayed = |id: &'static str, forge: Option<tokio::sync::mpsc::Sender<WorkerFrame>>| {
        Script::with(move |inv, out| {
            if let Some(f) = &forge {
                let f = f.clone();
                let rid = inv.request_id.clone();
                tokio::spawn(async move {
                    let _ = f.send(wf(worker_frame::Msg::Chunk(data(&rid, 0, b"forged".to_vec(), true)))).await;
                });
            }
            let wait = Duration::from_millis(u64::from(inv.request_id.as_bytes()[0] % 7));
            let body = echo_body(id, &inv.params_json);
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                let _ = out.send(wf(worker_frame::Msg::Chunk(data(&inv.request_id, 0, body, true)))).await;
            });
        })
    };
    let _a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(delayed("worker-a", Some(forger)));
    let _b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(delayed("worker-b", None));
    let tokens: Vec<String> = (0..4).map(|_| rig.token("g-all")).collect();
    let mut clients = Vec::new();
    for _ in 0..8 {
        clients.push(rig.client().await);
    }
    let mut tasks = Vec::new();
    for i in 0..1000u32 {
        let mut client = clients[i as usize % 8].clone();
        let token = tokens[i as usize % 4].clone();
        let (source, worker) = if i % 2 == 0 { ("example.alpha", "worker-a") } else { ("example.beta", "worker-b") };
        tasks.push(tokio::spawn(async move {
            let params = format!("{{\"n\":{i}}}");
            let stream = call(&mut client, &token, source, "get", params.as_bytes()).await.expect("accepted");
            let (chunks, end) = drain(stream).await;
            assert!(end.is_ok());
            assert_eq!(chunks.len(), 1, "exactly one chunk");
            assert!(chunks[0].r#final);
            assert_ne!(chunks[0].data, b"forged".to_vec(), "never another worker's answer");
            let body: serde_json::Value = serde_json::from_slice(&chunks[0].data).unwrap();
            assert_eq!(body["params"]["n"], i);
            assert_eq!(body["worker"], worker);
        }));
    }
    for t in tasks {
        t.await.expect("a call");
    }
    rig.until(Duration::from_secs(10), "every table empty", |r| r.app.snapshot().calls_in_flight == 0).await;
    let calls = rig.lines("call");
    assert_eq!(calls.len(), 1000);
    let ids: std::collections::BTreeSet<String> = calls.iter().map(|l| l["request_id"].as_str().unwrap().to_string()).collect();
    assert_eq!(ids.len(), 1000);
    assert!(calls.iter().all(|l| l["outcome"] == "ok"));
}

/// A script that streams `n` chunks of `size` bytes, one every `every`, the last final.
fn streaming(n: u64, size: usize, every: Duration) -> Script {
    Script::with(move |inv, out| {
        tokio::spawn(async move {
            for seq in 0..n {
                tokio::time::sleep(every).await;
                let chunk = data(&inv.request_id, seq, vec![b'x'; size], seq + 1 == n);
                if out.send(wf(worker_frame::Msg::Chunk(chunk))).await.is_err() {
                    return;
                }
            }
        });
    })
}

/// Relay 14 (paused).
#[tokio::test(start_paused = true)]
async fn a_dropped_caller_cancels_its_call() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(streaming(50, 100, Duration::from_millis(100)));
    let mut client = rig.client().await;
    let mut stream = call(&mut client, &rig.token("g-all"), "example.alpha", "get", b"{}").await.unwrap();
    let first = stream.message().await.unwrap().unwrap();
    assert_eq!(first.seq, 0);
    let t0 = Instant::now();
    drop(stream);
    a.until("the Cancel", |r| !r.cancels.is_empty()).await;
    assert!(t0.elapsed() <= Duration::from_millis(10), "{:?}", t0.elapsed());
    let cancel = a.cancels()[0].clone();
    assert_eq!(cancel.reason, "caller_gone");
    assert_eq!(cancel.request_id, a.invokes()[0].request_id);
    rig.until(Duration::from_secs(1), "A's table empty", |r| r.app.snapshot().calls_in_flight == 0).await;
    let calls = rig.lines("call");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["outcome"], "cancelled");
    assert_eq!(calls[0]["bytes"], first.data.len());
}

/// Relay 15.
#[tokio::test]
async fn a_dropped_worker_fails_every_call_at_once() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let mut streams = Vec::new();
    for _ in 0..5 {
        streams.push(call(&mut client, &token, "example.alpha", "get", b"{}").await.unwrap());
    }
    a.invoke(4).await;
    let dropped_at = rig.clock.ms();
    a.link.as_ref().unwrap().cut();
    for s in streams {
        let (chunks, end) = drain(s).await;
        assert!(end.is_ok());
        assert_eq!(chunks.len(), 1, "exactly one more chunk");
        assert!(chunks[0].r#final);
        let e = chunks[0].error.as_ref().unwrap();
        assert_eq!((e.code, e.message.as_str()), (14, "the worker disconnected"));
    }
    assert_eq!(rig.app.snapshot().calls_in_flight, 0);
    let listed = list(&mut client, &token).await.unwrap();
    assert_eq!(names(&listed), vec![("example.alpha".to_string(), false), ("example.alpha.logs".to_string(), false)]);
    assert!(listed.sources.iter().all(|s| s.last_seen_unix_ms == dropped_at));
    let calls = rig.lines("call");
    assert_eq!(calls.len(), 5);
    assert!(calls.iter().all(|l| l["outcome"] == "worker_gone" && l["code"] == 14));
    // R-24's order: the fail-all ends every call, then the tunnel's close line. Without the fail-all (M-R31) each
    // caller's stream would conclude `worker_gone` on its own, only once its queue closed after that line.
    rig.until(Duration::from_secs(5), "A's close line", |r| r.lines("tunnel").iter().any(|l| l["phase"] == "close")).await;
    let lines: Vec<serde_json::Value> = rig.sink.lines().iter().map(|l| serde_json::from_str(l).unwrap()).collect();
    let close_at = lines.iter().position(|l| l["ev"] == "tunnel" && l["phase"] == "close").unwrap();
    let calls_at: Vec<usize> = lines.iter().enumerate().filter(|(_, l)| l["ev"] == "call").map(|(i, _)| i).collect();
    assert!(calls_at.len() == 5 && calls_at.iter().all(|i| *i < close_at), "call lines {calls_at:?}, the close line {close_at}");
}

/// Relay 16 (paused).
#[tokio::test(start_paused = true)]
async fn a_deadline_ends_the_call_and_cancels_the_worker() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let t0 = Instant::now();
    let stream = call_with(&mut client, &token, CallRequest { deadline_ms: 1500, ..request("example.alpha", "get", b"{}") }).await.unwrap();
    let (chunks, _) = drain(stream).await;
    assert_eq!(t0.elapsed(), Duration::from_millis(1500));
    assert_eq!(chunks.len(), 1);
    assert_eq!(final_code(&chunks[0]), Some(4));
    a.until("the Cancel", |r| !r.cancels.is_empty()).await;
    assert_eq!(a.cancels()[0].reason, "deadline");
    assert_eq!(a.invokes()[0].deadline_ms, 1500);
    for (asked, seen) in [(0, 30_000), (900_000, 600_000)] {
        let n = a.invokes().len();
        let _stream = call_with(&mut client, &token, CallRequest { deadline_ms: asked, ..request("example.alpha", "get", b"{}") }).await.unwrap();
        assert_eq!(a.invoke(n).await.deadline_ms, seen);
    }
}

/// Relay 17.
#[tokio::test]
async fn the_caps_reach_the_worker_and_bind_the_caller() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::with(|inv, out| {
        if inv.limits.unwrap().max_bytes != 204_800 {
            return;
        }
        tokio::spawn(async move {
            for seq in 0..10 {
                if out.send(wf(worker_frame::Msg::Chunk(data(&inv.request_id, seq, vec![b'x'; 65_536], seq == 9)))).await.is_err() {
                    return;
                }
            }
        });
    }));
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let mib = 1u64 << 20;
    let wide = CallRequest { limits: Some(WireLimits { max_bytes: 5 * mib, max_rows: 0, max_chunks: 0 }), ..request("example.alpha", "get", b"{}") };
    let _pending = call_with(&mut client, &token, wide).await.unwrap();
    assert_eq!(a.invoke(0).await.limits, Some(WireLimits { max_bytes: 2 * mib, max_rows: 500, max_chunks: 16 }));

    let capped = CallRequest { limits: Some(WireLimits { max_bytes: 204_800, max_rows: 0, max_chunks: 0 }), ..request("example.alpha", "get", b"{}") };
    let (chunks, end) = drain(call_with(&mut client, &token, capped).await.unwrap()).await;
    assert!(end.is_ok());
    let sizes: Vec<usize> = chunks.iter().map(|c| c.data.len()).collect();
    assert_eq!(sizes, vec![65_536, 65_536, 65_536, 8192]);
    let last = chunks.last().unwrap();
    assert!(last.r#final && last.truncated);
    a.until("byte_cap", |r| r.cancels.iter().any(|c| c.reason == "byte_cap")).await;
    rig.until(Duration::from_secs(5), "the call line", |r| r.lines("call").iter().any(|l| l["outcome"] == "truncated")).await;
    let line = rig.lines("call").into_iter().find(|l| l["outcome"] == "truncated").unwrap();
    assert_eq!((line["bytes"].as_u64(), line["truncated"].as_bool(), line["code"].as_i64()), (Some(204_800), Some(true), Some(0)));
}

/// Relay 18.
#[tokio::test]
async fn grants_default_deny() {
    let rig = Rig::start().await;
    let _a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(Script::echo("worker-b"));
    let mut client = rig.client().await;
    let denied = |r: Result<tonic::Streaming<CallChunk>, tonic::Status>| {
        let s = r.expect_err("refused");
        (s.code(), s.message().to_string())
    };
    let none = rig.token("g-none");
    assert!(list(&mut client, &none).await.unwrap().sources.is_empty());
    assert_eq!(denied(call(&mut client, &none, "example.alpha", "get", b"{}").await), (Code::PermissionDenied, "not granted".into()));

    let get = rig.token("g-alpha-get");
    let (chunks, _) = drain(call(&mut client, &get, "example.alpha", "get", b"{}").await.expect("granted")).await;
    assert_eq!(chunks.len(), 1);
    for (source, op) in [("example.alpha", "list"), ("example.beta", "get"), ("example.zzz", "get")] {
        assert_eq!(denied(call(&mut client, &get, source, op, b"{}").await), (Code::PermissionDenied, "not granted".into()), "{source}/{op}");
    }

    let all = rig.token("g-example");
    assert_eq!(denied(call(&mut client, &all, "example.zzz", "get", b"{}").await), (Code::NotFound, "no such source".into()));
    assert_eq!(denied(call(&mut client, &all, "example.alpha", "zzz", b"{}").await), (Code::NotFound, "no such op".into()));
    b.link.as_ref().unwrap().cut();
    rig.until(Duration::from_secs(10), "B offline", |r| r.app.snapshot().sources_offline == 1).await;
    assert_eq!(denied(call(&mut client, &all, "example.beta", "get", b"{}").await), (Code::Unavailable, "source offline".into()));
    // R-31's order: the op before `Offline` (an offline source keeps its descriptor, R-26).
    assert_eq!(denied(call(&mut client, &all, "example.beta", "zzz", b"{}").await), (Code::NotFound, "no such op".into()));

    // Loaded but not fresh (R-16, R-17): new grants read while `fetched` holds no time. The token signers, still
    // fresh, pass first (R-31), and the grants step refuses as for no grants file.
    rig.write(FETCHED_FILE, b"x\n");
    let mut more = default_grants();
    more.push(ai_env_relay::lists::Grant { grant_id: "g-more".into(), allow: vec!["example.alpha/get".into()] });
    rig.write_grants(&more);
    rig.poll();
    assert_eq!(denied(call(&mut client, &all, "example.alpha", "get", b"{}").await), (Code::Unavailable, "grants not loaded".into()));
    let s = list(&mut client, &all).await.expect_err("grants not fresh");
    assert_eq!((s.code(), s.message()), (Code::Unavailable, "grants not loaded"));
    rig.write_fetched(rig.clock.unix());
    rig.poll();
    list(&mut client, &all).await.expect("fresh again");

    rig.remove(GRANTS_FILE);
    rig.poll();
    assert_eq!(denied(call(&mut client, &all, "example.alpha", "get", b"{}").await), (Code::Unavailable, "grants not loaded".into()));
    let s = list(&mut client, &all).await.expect_err("no grants");
    assert_eq!((s.code(), s.message()), (Code::Unavailable, "grants not loaded"));
}

/// Relay 19.
#[tokio::test]
async fn session_tokens_gate_the_private_face_alike() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    let now = rig.clock.unix();
    let past = SessionClaims { iat: now - 7200, exp: now - 3600, ..rig.claims("g-all") };
    let other_kid = SessionClaims { kid: "mac-9".into(), ..rig.claims("g-all") };
    let changed = {
        let t = rig.token("g-all");
        let parts: Vec<&str> = t.split('.').collect();
        let json = String::from_utf8(b64url_decode(parts[1])).unwrap().replace("ai-env-relay", "ai-env-other");
        format!("v1.{}.{}", b64url_encode(json.as_bytes()), parts[2])
    };
    let bad = vec![mint(4, &rig.claims("g-all")), mint(7, &other_kid), mint(7, &past), changed];
    let assert_refused = |s: tonic::Status| {
        assert_eq!((s.code(), s.message()), (Code::Unauthenticated, "authentication failed"));
    };
    for token in &bad {
        assert_refused(list(&mut client, token).await.expect_err("list refused"));
        assert_refused(call(&mut client, token, "example.alpha", "get", b"{}").await.expect_err("call refused"));
    }
    // No header, and two.
    assert_refused(client.list_sources(tonic::Request::new(ai_env_relay_proto::v1::ListSourcesRequest {})).await.expect_err("no header"));
    let valid = rig.token("g-all");
    let mut twice = with_token(request("example.alpha", "get", b"{}"), &valid);
    twice.metadata_mut().append(ai_env_relay::session::SESSION_HEADER, valid.parse().unwrap());
    assert_refused(client.call(twice).await.expect_err("two headers"));
    // A signer removed, then one lapsed (unit tests 11 and 12, built at run time).
    rig.write_signers(&[mac_signer("2027-01-15T07:00:00Z")]);
    rig.poll();
    assert_refused(list(&mut client, &valid).await.expect_err("lapsed signer"));
    rig.write_signers(&[mac_signer(NOT_AFTER)]);
    rig.poll();
    // Unit test 11's `NotLoaded` (R-17, R-52; M-R44): the token-signers file gone, then loaded but stale.
    let signers = rig.read(SIGNERS_FILE);
    rig.remove(SIGNERS_FILE);
    rig.poll();
    assert_refused(list(&mut client, &valid).await.expect_err("no signers"));
    assert_refused(call(&mut client, &valid, "example.alpha", "get", b"{}").await.expect_err("no signers"));
    rig.write(SIGNERS_FILE, &signers);
    rig.poll();
    rig.clock.set(T0 + 901);
    assert_refused(list(&mut client, &valid).await.expect_err("stale signers"));
    assert_refused(call(&mut client, &valid, "example.alpha", "get", b"{}").await.expect_err("stale signers"));
    rig.write_fetched(rig.clock.unix());
    rig.poll();
    assert!(a.invokes().is_empty(), "nothing reached a worker");
    let (chunks, _) = drain(call(&mut client, &valid, "example.alpha", "get", b"{}").await.expect("a valid token works")).await;
    assert_eq!(chunks.len(), 1);
    rig.write_signers(&[ai_env_relay::lists::SignerEntry { signer_id: "mac-2".into(), ..mac_signer(NOT_AFTER) }]);
    rig.poll();
    assert_refused(list(&mut client, &valid).await.expect_err("mac removed"));
    assert_refused(call(&mut client, &valid, "example.alpha", "get", b"{}").await.expect_err("mac removed"));
    assert_eq!(a.invokes().len(), 1);
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(B64URL[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Vec<u8> {
    let vals: Vec<u32> = s.bytes().map(|b| B64URL.iter().position(|x| *x == b).unwrap() as u32).collect();
    let mut out = Vec::new();
    for c in vals.chunks(4) {
        let n = c.iter().enumerate().fold(0u32, |acc, (i, v)| acc | (v << (18 - 6 * i)));
        for i in 0..c.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}

/// Relay 20.
#[tokio::test]
async fn the_caller_is_the_tokens_never_the_requests() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    let claims = SessionClaims { caller_id: "mac-desk".into(), ..rig.claims("g-all") };
    let token = mint(7, &claims);
    let params = format!("{{\"session_id\":\"{}\",\"caller_id\":\"forged\"}}", rig.session_id());
    let mut req = with_token(request("example.alpha", "get", params.as_bytes()), &token);
    req.metadata_mut().insert("x-ai-env-caller", "forged".parse().unwrap());
    let (chunks, _) = drain(client.call(req).await.unwrap().into_inner()).await;
    assert_eq!(chunks.len(), 1);
    let inv = a.invoke(0).await;
    let caller = inv.caller.clone().unwrap();
    assert_eq!(
        (caller.caller_id.as_str(), caller.session_id.as_str(), caller.grant_id.as_str(), caller.vm_id.as_str()),
        ("mac-desk", claims.session_id.as_str(), "g-all", VM_ID)
    );
    let printed = format!("{inv:?}");
    assert!(!printed.contains(&token) && !printed.contains(token.split('.').nth(2).unwrap()), "no Invoke field holds the token");
}

/// Relay 21.
#[tokio::test]
async fn session_limits_refuse_the_excess() {
    let rig = Rig::start().await;
    let _a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(call(&mut client, &token, "example.alpha", "get", b"{}").await.expect("within the session's eight"));
    }
    let ninth = call(&mut client, &token, "example.alpha", "get", b"{}").await.expect_err("the ninth");
    assert_eq!((ninth.code(), ninth.message()), (Code::ResourceExhausted, "too many calls in flight"));
    let _other = call(&mut client, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect("another session");
    drop(held.pop());
    rig.until(Duration::from_secs(5), "a slot freed", |r| r.app.snapshot().calls_in_flight == 8).await;
    let again = call(&mut client, &token, "example.alpha", "get", b"{}").await;
    assert!(again.is_ok(), "once one ends, a new call: {:?}", again.err());

    let quick = rig.token("g-all");
    for _ in 0..20 {
        list(&mut client, &quick).await.expect("within the burst");
    }
    let s = list(&mut client, &quick).await.expect_err("the 21st");
    assert_eq!((s.code(), s.message()), (Code::ResourceExhausted, "rate limited"));
}

/// Relay 22's setup: A's tunnel on a small pipe that A stops reading, then calls until one is refused.
struct FullQueue {
    link: Link,
    _a: Served,
    client: ai_env_relay_proto::v1::relay_client::RelayClient<tonic::transport::Channel>,
    token: String,
    params: String,
    held: Vec<tonic::Streaming<CallChunk>>,
    refused: tonic::Status,
    waited: Duration,
}

impl FullQueue {
    /// The rig's limits for it: `tunnel_queue` 4, and room for every call it makes.
    fn limits() -> Limits {
        Limits { tunnel_queue: 4, calls_per_session: 128, calls_per_tunnel: 128, session_burst: 10_000, ..limits() }
    }

    async fn fill(rig: &Rig) -> FullQueue {
        // A small pipe: once A stops reading, the relay's writes back up within a few Invokes.
        let (channel, link) = rig.public_channel_with(tonic::transport::Endpoint::from_static("http://ai-env-relay"), 65_536).await;
        let mut a = TestWorker::open_on(channel).await.unwrap();
        a.authenticate("worker-a", 1).await.unwrap();
        a.register(catalog_a()).await;
        rig.until(Duration::from_secs(10), "installed", |r| r.app.snapshot().sources_live == 2).await;
        let a = a.serve(Script::silent());
        link.pause();
        let mut client = rig.client().await;
        let token = rig.token("g-all");
        let params = format!("{{\"pad\":\"{}\"}}", "p".repeat(65_000));
        let mut held = Vec::new();
        let (refused, waited) = loop {
            assert!(held.len() < 100, "the queue never filled");
            // At most eight calls a connection: the private face's 16 streams (R-5) never bound this setup.
            if !held.is_empty() && held.len() % 8 == 0 {
                client = rig.client().await;
            }
            let t0 = Instant::now();
            match call(&mut client, &token, "example.alpha", "get", params.as_bytes()).await {
                Ok(s) => held.push(s),
                Err(s) => break (s, t0.elapsed()),
            }
        };
        FullQueue { link, _a: a, client, token, params, held, refused, waited }
    }
}

/// Relay 22 (paused).
#[tokio::test(start_paused = true)]
async fn a_full_worker_queue_answers_busy() {
    let rig = Rig::start_with(FullQueue::limits()).await;
    let q = FullQueue::fill(&rig).await;
    assert_eq!((q.refused.code(), q.refused.message()), (Code::Unavailable, "worker busy"));
    assert_eq!(q.waited, Duration::from_secs(2));
    assert_eq!(rig.app.snapshot().calls_in_flight, q.held.len() as u64, "its entry is gone");
    assert_eq!(rig.lines("call").last().unwrap()["outcome"], "busy");
}

/// R-38 and R-61 (relay 22's setup): a caller that leaves during the enqueue wait leaves no pending entry behind,
/// and its call gets one line, `cancelled`.
#[tokio::test(start_paused = true)]
async fn a_caller_gone_during_the_enqueue_leaves_nothing_pending() {
    let rig = Rig::start_with(FullQueue::limits()).await;
    let q = FullQueue::fill(&rig).await;
    let (held, lines) = (q.held.len() as u64, rig.lines("call").len());
    let (mut client, token, params) = (q.client.clone(), q.token.clone(), q.params.clone());
    let gone = tokio::time::timeout(Duration::from_secs(1), async move { call(&mut client, &token, "example.alpha", "get", params.as_bytes()).await }).await;
    assert!(gone.is_err(), "the caller leaves 1 s into the 2 s wait");
    rig.until(Duration::from_secs(5), "its entry gone and its line", |r| r.app.snapshot().calls_in_flight == held && r.lines("call").len() == lines + 1).await;
    let line = rig.lines("call").pop().unwrap();
    assert_eq!((line["outcome"].as_str(), line["code"].as_i64()), (Some("cancelled"), Some(1)));
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(rig.app.snapshot().calls_in_flight, held, "nothing pending once the wait would have ended");
    assert_eq!(rig.lines("call").len(), lines + 1, "one line, never a second");
}

/// R-61 (relay 22's setup): a tunnel that ends during a call's enqueue wait gives that call one line, and its caller
/// 14 `source offline`.
#[tokio::test(start_paused = true)]
async fn a_tunnel_gone_during_the_enqueue_gives_one_line() {
    let rig = Rig::start_with(FullQueue::limits()).await;
    let q = FullQueue::fill(&rig).await;
    let (mut client, token, params) = (q.client.clone(), q.token.clone(), q.params.clone());
    let pending = tokio::spawn(async move { call_response(&mut client, &token, request("example.alpha", "get", params.as_bytes())).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    q.link.cut();
    let refused = pending.await.unwrap().expect_err("refused");
    assert_eq!((refused.code(), refused.message()), (Code::Unavailable, "source offline"));
    let id = request_id(refused.metadata());
    rig.until(Duration::from_secs(5), "A's close line", |r| r.lines("tunnel").iter().any(|l| l["phase"] == "close")).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mine: Vec<serde_json::Value> = rig.lines("call").into_iter().filter(|l| l["request_id"] == id.as_str()).collect();
    assert_eq!(mine.len(), 1, "exactly one call line: {mine:?}");
    // Whichever ends the call first writes it: the tunnel's fail-all (`worker_gone`) or the closed queue (`offline`).
    assert!(matches!(mine[0]["outcome"].as_str(), Some("worker_gone" | "offline")) && mine[0]["code"] == 14, "{}", mine[0]);
}

/// Relay 33 (paused, relay 22's setup): a tunnel's end closes its connection a second later even when the worker
/// reads nothing, so its last frames can never leave (R-2a: the tunnel's task ending starts the grace, not only its
/// response stream). A is revoked while its link is paused; at 2 s the link reads again and finds the connection
/// already closed.
#[tokio::test(start_paused = true)]
async fn a_tunnel_s_end_closes_its_connection_even_unread() {
    let rig = Rig::start_with(FullQueue::limits()).await;
    let q = FullQueue::fill(&rig).await;
    let others: Vec<_> = default_workers().into_iter().filter(|e| e.worker_id != "worker-a").collect();
    rig.write_workers(&others);
    rig.poll();
    let revoked = Instant::now();
    rig.until(Duration::from_secs(5), "A's close line", |r| r.lines("tunnel").iter().any(|l| l["phase"] == "close")).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(q.link.peer_closed_at(), None, "paused: nothing read yet");
    let resumed = Instant::now();
    assert!(resumed - revoked >= Duration::from_secs(2));
    q.link.resume();
    rig.until(Duration::from_secs(5), "the connection's end", |_| q.link.peer_closed_at().is_some()).await;
    assert_eq!(q.link.peer_closed_at(), Some(resumed), "closed while unread: gone as the link reads again");
}

/// Relay 23 (paused).
#[tokio::test(start_paused = true)]
async fn a_wedged_caller_is_evicted_and_others_flow() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let token = rig.token("g-all");
    let (wedged_channel, wedged_link) = rig.private_channel_with(tonic::transport::Endpoint::from_static("http://10.42.0.20"), 65_536).await;
    let mut wedged = ai_env_relay_proto::v1::relay_client::RelayClient::new(wedged_channel);
    let mut other = rig.client().await;
    let s1 = call(&mut wedged, &token, "example.alpha", "get", b"{\"call\":1}").await.unwrap();
    let call1 = a.invoke(0).await.request_id;
    let s2 = call(&mut other, &token, "example.alpha", "get", b"{\"call\":2}").await.unwrap();
    let call2 = a.invoke(1).await.request_id;
    wedged_link.pause();
    let t0 = Instant::now();
    for seq in 0..20 {
        a.send(worker_frame::Msg::Chunk(data(&call1, seq, vec![b'x'; 65_536], false))).await;
    }
    a.send(worker_frame::Msg::Chunk(data(&call2, 0, b"{}".to_vec(), true))).await;
    let (chunks2, _) = drain(s2).await;
    assert_eq!(chunks2.len(), 1);
    assert!(t0.elapsed() <= Duration::from_millis(2500), "{:?}", t0.elapsed());
    let evicted = a.cancels().into_iter().find(|c| c.request_id == call1).expect("call 1 cancelled");
    assert_eq!(evicted.reason, "caller_too_slow");
    wedged_link.resume();
    let (chunks1, end) = drain(s1).await;
    assert!(end.is_ok());
    let (data_chunks, last) = chunks1.split_at(chunks1.len() - 1);
    assert!(data_chunks.len() >= 4, "the buffered chunks first: {}", data_chunks.len());
    assert!(data_chunks.iter().enumerate().all(|(i, c)| c.seq == i as u64 && !c.r#final));
    let e = last[0].error.as_ref().expect("a final error");
    assert_eq!((e.code, e.message.as_str()), (10, "the caller read too slowly"));
    assert_eq!(last[0].seq, data_chunks.len() as u64);
}

/// Relay 24.
#[tokio::test]
async fn params_are_bounded_json_objects() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let big = format!("{{\"pad\":\"{}\"}}", "p".repeat(65_537 - 10));
    assert_eq!(big.len(), 65_537);
    for params in [big.as_bytes(), b"[1]".as_slice(), b"not json".as_slice()] {
        let s = call(&mut client, &token, "example.alpha", "get", params).await.expect_err("refused");
        assert_eq!((s.code(), s.message()), (Code::InvalidArgument, "params must be a JSON object of at most 65536 bytes"));
    }
    let (chunks, _) = drain(call(&mut client, &token, "example.alpha", "get", b"").await.unwrap()).await;
    assert_eq!(chunks.len(), 1);
    assert_eq!(a.invoke(0).await.params_json, b"{}".to_vec());
    let s = call(&mut client, &token, "Bad Name", "get", b"{}").await.expect_err("refused");
    assert_eq!((s.code(), s.message()), (Code::InvalidArgument, "invalid source or op name"));
}

/// Relay 25 (paused: every outcome's timers run on tokio's clock).
#[tokio::test(start_paused = true)]
async fn the_request_log_carries_ids_and_hashes_only() {
    let l = Limits { calls_per_session: 3, calls_per_tunnel: 2, session_burst: 20, ..limits() };
    let rig = Rig::start_with(l).await;
    // A answers by its params: echo, an error, a cut, a slow stream or a gap; B and C stay silent.
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::with(|inv, out| {
        let params: serde_json::Value = serde_json::from_slice(&inv.params_json).unwrap_or_default();
        let rid = inv.request_id.clone();
        let mode = params["mode"].as_str().unwrap_or("echo").to_string();
        tokio::spawn(async move {
            let send = |c: Chunk| {
                let out = out.clone();
                async move {
                    let _ = out.send(wf(worker_frame::Msg::Chunk(c))).await;
                }
            };
            match mode.as_str() {
                "echo" => send(data(&rid, 0, b"{\"answer\":\"ZZ-SENTINEL-DATA\"}".to_vec(), true)).await,
                "error" => send(failure(&rid, 0, 5, "ZZ-SENTINEL-DATA not found")).await,
                "cut" => {
                    for seq in 0..3 {
                        send(data(&rid, seq, vec![b'x'; 65_536], seq == 2)).await;
                    }
                }
                "slow" => {
                    for seq in 0..100 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        send(data(&rid, seq, vec![b'x'; 100], false)).await;
                    }
                }
                "gap" => send(data(&rid, 5, b"{}".to_vec(), true)).await,
                "wedge" => {
                    // A moment for the caller to stop reading once its stream has started.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    for seq in 0..24 {
                        send(data(&rid, seq, vec![b'x'; 65_536], false)).await;
                    }
                }
                _ => {}
            }
        });
    }));
    let b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(Script::silent());
    let _c = TestWorker::connect(&rig, "worker-c", 5, catalog_c()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let mut driven: Vec<(String, &str, i64)> = Vec::new();
    let token = rig.token("g-all");
    let req = |source: &str, mode: &str| request(source, "get", format!("{{\"mode\":\"{mode}\",\"q\":\"ZZ-SENTINEL-PARAM\"}}").as_bytes());

    // ok, source_error, truncated, violation: each answered by A.
    for (mode, outcome, code, limits) in [("echo", "ok", 0, None), ("error", "source_error", 5, None), ("cut", "truncated", 0, Some(100_000)), ("gap", "violation", 13, None)] {
        let mut r = req("example.alpha", mode);
        r.limits = limits.map(|b| WireLimits { max_bytes: b, max_rows: 0, max_chunks: 0 });
        let resp = call_response(&mut client, &token, r).await.unwrap();
        let id = request_id(resp.metadata());
        let _ = drain(resp.into_inner()).await;
        driven.push((id, outcome, code));
    }
    // cancelled: a slow stream dropped after its first chunk.
    let resp = call_response(&mut client, &token, req("example.alpha", "slow")).await.unwrap();
    let id = request_id(resp.metadata());
    let mut s = resp.into_inner();
    s.message().await.unwrap();
    drop(s);
    driven.push((id, "cancelled", 1));
    // deadline.
    let resp = call_response(&mut client, &token, CallRequest { deadline_ms: 1000, ..req("example.alpha", "silent") }).await.unwrap();
    let id = request_id(resp.metadata());
    let _ = drain(resp.into_inner()).await;
    driven.push((id, "deadline", 4));
    // evicted: a caller that stops reading.
    let (wedged_channel, wedged_link) = rig.private_channel_with(tonic::transport::Endpoint::from_static("http://10.42.0.20"), 65_536).await;
    let mut wedged = ai_env_relay_proto::v1::relay_client::RelayClient::new(wedged_channel);
    let resp = call_response(&mut wedged, &token, req("example.alpha", "wedge")).await.unwrap();
    wedged_link.pause();
    let id = request_id(resp.metadata());
    a.until("evicted", |r| r.cancels.iter().any(|c| c.reason == "caller_too_slow")).await;
    wedged_link.resume();
    let _ = drain(resp.into_inner()).await;
    driven.push((id, "evicted", 10));
    // busy: C's table full (two calls pending, calls_per_tunnel 2).
    let busy_token = rig.token("g-all");
    let _c1 = call(&mut client, &busy_token, "example.gamma", "get", b"{}").await.unwrap();
    let _c2 = call(&mut client, &busy_token, "example.gamma", "get", b"{}").await.unwrap();
    let refused = call(&mut client, &busy_token, "example.gamma", "get", b"{}").await.expect_err("busy");
    driven.push((request_id(refused.metadata()), "busy", 14));
    // too_many: a session at calls_per_session (3).
    let many = rig.token("g-all");
    let m1 = call(&mut client, &many, "example.beta", "get", b"{}").await.unwrap();
    let m2 = call(&mut client, &many, "example.beta", "get", b"{}").await.unwrap();
    let m3 = call(&mut client, &many, "example.alpha", "get", b"{\"mode\":\"silent\"}").await.unwrap();
    let refused = call(&mut client, &many, "example.alpha", "get", b"{}").await.expect_err("too many");
    driven.push((request_id(refused.metadata()), "too_many", 8));
    drop((m1, m2, m3));
    rig.until(Duration::from_secs(5), "only C's two pending", |r| r.app.snapshot().calls_in_flight == 2).await;
    // rate_limited: a session past its burst.
    let quick = rig.token("g-all");
    for _ in 0..20 {
        list(&mut client, &quick).await.unwrap();
    }
    let refused = call(&mut client, &quick, "example.alpha", "get", b"{}").await.expect_err("rate limited");
    driven.push((request_id(refused.metadata()), "rate_limited", 8));
    // unauthenticated, denied, not_found, invalid.
    let refused = client.call(tonic::Request::new(req("example.alpha", "echo"))).await.expect_err("no token");
    driven.push((request_id(refused.metadata()), "unauthenticated", 16));
    let refused = call(&mut client, &rig.token("g-none"), "example.alpha", "get", b"{}").await.expect_err("denied");
    driven.push((request_id(refused.metadata()), "denied", 7));
    let refused = call(&mut client, &token, "example.zzz", "get", b"{}").await.expect_err("not found");
    driven.push((request_id(refused.metadata()), "not_found", 5));
    let refused = call(&mut client, &token, "Bad Name", "get", b"{}").await.expect_err("invalid");
    driven.push((request_id(refused.metadata()), "invalid", 3));
    // worker_gone, then offline: B's transport dropped under a pending call.
    let gone = rig.token("g-all");
    let resp = call_response(&mut client, &gone, request("example.beta", "get", b"{}")).await.unwrap();
    let id = request_id(resp.metadata());
    b.until("B's invoke", |r| r.invokes.len() >= 3).await;
    b.link.as_ref().unwrap().cut();
    let _ = drain(resp.into_inner()).await;
    driven.push((id, "worker_gone", 14));
    let refused = call(&mut client, &gone, "example.beta", "get", b"{}").await.expect_err("offline");
    driven.push((request_id(refused.metadata()), "offline", 14));
    // not_ready.
    let good_grants = rig.read(GRANTS_FILE);
    rig.remove(GRANTS_FILE);
    rig.poll();
    let refused = call(&mut client, &gone, "example.alpha", "get", b"{}").await.expect_err("not ready");
    driven.push((request_id(refused.metadata()), "not_ready", 14));
    rig.write(GRANTS_FILE, &good_grants);
    rig.write_fetched(rig.clock.unix());
    rig.poll();
    // shutdown, last.
    let resp = call_response(&mut client, &rig.token("g-all"), req("example.alpha", "silent")).await.unwrap();
    let id = request_id(resp.metadata());
    rig.app.shutdown();
    let _ = drain(resp.into_inner()).await;
    driven.push((id, "shutdown", 14));

    let calls = rig.lines("call");
    let outcomes: std::collections::BTreeSet<&str> = driven.iter().map(|(_, o, _)| *o).collect();
    assert_eq!(outcomes.len(), 18, "every outcome of R-64 driven once");
    for (id, outcome, code) in &driven {
        let mine: Vec<_> = calls.iter().filter(|l| l["request_id"] == id.as_str()).collect();
        assert_eq!(mine.len(), 1, "exactly one call line for {outcome}");
        assert_eq!((mine[0]["outcome"].as_str(), mine[0]["code"].as_i64()), (Some(*outcome), Some(*code)), "{id}");
        assert_eq!(keys_of(mine[0]), sorted(&CALL_KEYS));
    }
    let gap = &driven.iter().find(|(_, o, _)| *o == "violation").unwrap().0;
    assert!(a.cancels().iter().any(|c| c.reason == "protocol" && &c.request_id == gap), "a breach cancels with `protocol`");
    let ok = calls.iter().find(|l| l["outcome"] == "ok").unwrap();
    let params = br#"{"mode":"echo","q":"ZZ-SENTINEL-PARAM"}"#;
    assert_eq!(ok["params_hmac"], ai_env_relay::reqlog::params_digest(&[9; 32], params));
    let key_texts: Vec<String> = [1u8, 2, 5, 7].iter().map(|s| ai_env_worker::keys::SigningKey::from_seed(&[*s; 32]).unwrap().public_key().b64()).collect();
    for line in rig.sink.lines() {
        assert!(!line.contains("ZZ-SENTINEL"), "{line}");
        assert!(!line.contains(&token) && !line.contains(&token[3..40]), "a token in {line}");
        assert!(key_texts.iter().all(|k| !line.contains(k.as_str())), "a key in {line}");
        assert!(!line.contains('*'), "a glob in {line}");
    }
}

/// Relay 26 (paused).
#[tokio::test(start_paused = true)]
async fn ping_keeps_a_tunnel_and_silence_closes_it() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert_eq!(rig.app.snapshot().tunnels, 1, "still registered after 5 min");
    let pings = a.log.lock().unwrap().pings.clone();
    assert!(pings.len() >= 19, "{}", pings.len());
    assert!(pings.windows(2).all(|w| w[1] == w[0] + 1) && pings[0] == 1);
    assert!(a.closes().is_empty());

    let mut b = TestWorker::open(&rig).await;
    b.authenticate("worker-b", 2).await.unwrap();
    b.register(catalog_b()).await;
    let last_frame = Instant::now();
    let b = b.serve(Script { pong: false, on_invoke: Box::new(|_, _| {}) });
    rig.until(Duration::from_secs(1), "B installed", |r| r.app.snapshot().tunnels == 2).await;
    let mut client = rig.client().await;
    // A deadline past the 45 s, so the tunnel's end (not the deadline) ends the call.
    let stream = call_with(&mut client, &rig.token("g-all"), CallRequest { deadline_ms: 60_000, ..request("example.beta", "get", b"{}") }).await.unwrap();
    let close = b.closed().await;
    assert_eq!(close.code, 5);
    assert_eq!(last_frame.elapsed(), Duration::from_secs(45));
    let (chunks, _) = drain(stream).await;
    assert_eq!(final_code(&chunks[0]), Some(14));
}

/// Relay 27 (paused): one tunnel per connection (R-6, R-2a). A first `Open` fails its handshake; a second `Open` on
/// the same connection, at once, fails at the transport: the relay closes the connection then, not after R-2a's
/// grace, so neither a 9 nor a second Challenge reaches the worker, and the connection's watch is gone.
#[tokio::test(start_paused = true)]
async fn one_tunnel_per_connection() {
    let rig = Rig::start().await;
    let (channel, link) = rig.public_channel().await;
    let mut first = TestWorker::open_on(channel.clone()).await.expect("the first Open");
    assert_eq!(rig.app.public_conns(), 1);
    let h = hello("worker-a", 1);
    let mut p = proof(&first.challenge, &h, 1);
    p.signature[0] ^= 1;
    first.send(worker_frame::Msg::Hello(h)).await;
    first.send(worker_frame::Msg::AuthProof(p)).await;
    assert_eq!(first.end().await.expect_err("a failed handshake").code(), Code::Unauthenticated);
    let ended = Instant::now();
    drop(first);
    assert_eq!(link.peer_closed_at(), None, "the connection is still up");
    let second = TestWorker::open_on(channel).await.err().expect("a second Open fails");
    assert!(second.code() != Code::FailedPrecondition && second.message() != "one tunnel per connection", "a transport failure, not a 9: {second:?}");
    rig.until(Duration::from_secs(5), "the relay closes the connection", |_| link.peer_closed_at().is_some()).await;
    assert_eq!(link.peer_closed_at(), Some(ended), "closed at the second Open, not 1 s after the tunnel's end");
    rig.until(Duration::from_secs(5), "the watch's end", |r| r.app.public_conns() == 0).await;
    assert_eq!(rig.lines("tunnel").len(), 1, "one tunnel line, the first Open's refusal: {:?}", rig.lines("tunnel"));
}

/// A bare HTTP/2 client (relay 31): it writes frames as a caller with no token might, deaf to the relay's SETTINGS,
/// and reads every frame the relay sends with the virtual time it came at (RFC 9113 §4, RFC 7541).
mod h2raw {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::time::Instant;

    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const ACK: u8 = 0x1;
    /// SETTINGS_MAX_CONCURRENT_STREAMS and SETTINGS_MAX_HEADER_LIST_SIZE (RFC 9113 §6.5.2).
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
    /// RST_STREAM's NO_ERROR and REFUSED_STREAM (RFC 9113 §7).
    pub const NO_ERROR: u32 = 0x0;
    pub const REFUSED_STREAM: u32 = 0x7;

    pub struct Frame {
        pub kind: u8,
        pub flags: u8,
        pub stream: u32,
        pub payload: Vec<u8>,
        /// When it came, from the test's start.
        pub at: Duration,
    }

    impl Frame {
        /// A RST_STREAM's error code.
        pub fn code(&self) -> u32 {
            u32::from_be_bytes([self.payload[0], self.payload[1], self.payload[2], self.payload[3]])
        }
    }

    pub struct Conn {
        io: DuplexStream,
        t0: Instant,
    }

    impl Conn {
        /// The client preface and an empty SETTINGS.
        pub async fn open(io: DuplexStream, t0: Instant) -> Conn {
            let mut c = Conn { io, t0 };
            c.io.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
            c.send(SETTINGS, 0, 0, &[]).await;
            c
        }

        pub async fn send(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
            let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
            let id = stream.to_be_bytes();
            let head = [len[1], len[2], len[3], kind, flags, id[0], id[1], id[2], id[3]];
            self.io.write_all(&head).await.unwrap();
            self.io.write_all(payload).await.unwrap();
        }

        /// The next frame, or None once the relay closed the connection. A SETTINGS is acknowledged.
        pub async fn next(&mut self) -> Option<Frame> {
            let mut head = [0u8; 9];
            self.io.read_exact(&mut head).await.ok()?;
            let mut payload = vec![0u8; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
            self.io.read_exact(&mut payload).await.ok()?;
            let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            let frame = Frame { kind: head[3], flags: head[4], stream, payload, at: self.t0.elapsed() };
            if frame.kind == SETTINGS && frame.flags & ACK == 0 {
                self.send(SETTINGS, ACK, 0, &[]).await;
            }
            Some(frame)
        }
    }

    /// A header block of literal fields, never indexed and never Huffman-coded (RFC 7541 §6.2.2).
    pub fn block(fields: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = Vec::new();
        for (name, value) in fields {
            b.push(0x00);
            int7(&mut b, name.len());
            b.extend_from_slice(name.as_bytes());
            int7(&mut b, value.len());
            b.extend_from_slice(value);
        }
        b
    }

    /// RFC 7541 §5.1's integer with a 7-bit prefix (the Huffman bit clear).
    fn int7(b: &mut Vec<u8>, n: usize) {
        if n < 0x7f {
            b.push(n as u8);
            return;
        }
        b.push(0x7f);
        let mut n = n - 0x7f;
        while n >= 0x80 {
            b.push((n % 0x80) as u8 | 0x80);
            n /= 0x80;
        }
        b.push(n as u8);
    }

    /// A SETTINGS frame's (identifier, value) pairs.
    pub fn pairs(payload: &[u8]) -> Vec<(u16, u32)> {
        payload.as_chunks::<6>().0.iter().map(|c| (u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes([c[2], c[3], c[4], c[5]]))).collect()
    }

    /// One gRPC message: its 5-byte prefix, then `body`.
    pub fn grpc(announced: u32, body: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8];
        m.extend_from_slice(&announced.to_be_bytes());
        m.extend_from_slice(body);
        m
    }
}

/// Relay 31 (paused): a caller with no token holds 16 streams a connection on the private face, 10 s each (R-5).
/// Two bare connections each open 20 `Call` streams whose one gRPC message announces 1024 bytes and sends 10, with no
/// END_STREAM. Each connection's SETTINGS say 16 streams and a 4096-byte header list; its 17th to 20th streams are
/// refused at once (REFUSED_STREAM); its first 16 are answered and reset at 10 s exactly, and none reaches the handler
/// (no call line). Meanwhile a call on another connection runs; once the 16 are cut, the connection takes a new
/// stream again.
#[tokio::test(start_paused = true)]
async fn unfinished_private_requests_are_capped_and_cut() {
    use ai_env_relay_proto::prost::Message as _;
    use h2raw::*;
    let rig = Rig::start().await;
    let _a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let headers = block(&[
        (":method", b"POST"),
        (":scheme", b"http"),
        (":path", b"/ai_env.relay.v1.Relay/Call"),
        (":authority", b"10.42.0.20"),
        ("content-type", b"application/grpc"),
        ("te", b"trailers"),
    ]);
    let unfinished = grpc(1024, &[b'x'; 10]);
    let t0 = Instant::now();
    let mut conns = Vec::new();
    for _ in 0..2 {
        let mut c = Conn::open(rig.private_raw(1 << 20), t0).await;
        for i in 0..20u32 {
            c.send(HEADERS, END_HEADERS, 2 * i + 1, &headers).await;
            c.send(DATA, 0, 2 * i + 1, &unfinished).await;
        }
        conns.push(c);
    }

    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let (chunks, end) = drain(call(&mut client, &token, "example.alpha", "get", b"{\"n\":1}").await.expect("a call beside them")).await;
    assert!(end.is_ok() && chunks.len() == 1 && chunks[0].r#final && chunks[0].error.is_none());
    assert!(t0.elapsed() < Duration::from_secs(10), "while the unfinished ones are held: {:?}", t0.elapsed());

    // Both connections read at once, each frame stamped with its arrival on the paused clock.
    let readers: Vec<_> = conns
        .into_iter()
        .map(|mut c| {
            tokio::spawn(async move {
                let mut settings = Vec::new();
                // Each stream's frames in order: (kind, flags, RST_STREAM's code, when).
                let mut seen: std::collections::BTreeMap<u32, Vec<(u8, u8, u32, Duration)>> = std::collections::BTreeMap::new();
                while seen.values().filter(|f| f.iter().any(|(kind, ..)| *kind == RST_STREAM)).count() < 20 {
                    let f = tokio::time::timeout(PATIENCE, c.next()).await.expect("a frame in time").expect("the connection stays up");
                    match f.kind {
                        SETTINGS if f.flags & ACK == 0 => settings.extend(pairs(&f.payload)),
                        RST_STREAM => seen.entry(f.stream).or_default().push((f.kind, f.flags, f.code(), f.at)),
                        HEADERS | DATA if f.stream > 0 => seen.entry(f.stream).or_default().push((f.kind, f.flags, 0, f.at)),
                        _ => {}
                    }
                }
                (c, settings, seen)
            })
        })
        .collect();
    let mut conns = Vec::new();
    for reader in readers {
        let (c, settings, seen) = reader.await.unwrap();
        assert!(settings.contains(&(MAX_CONCURRENT_STREAMS, 16)), "{settings:?}");
        assert!(settings.contains(&(MAX_HEADER_LIST_SIZE, 4096)), "{settings:?}");
        for (stream, frames) in &seen {
            if *stream <= 31 {
                // At 10 s: answered (tonic's `Timeout expired`, a trailers-only HEADERS), then reset NO_ERROR, the
                // request's unread rest dropped (RFC 9113 §8.1).
                let ten = Duration::from_secs(10);
                assert_eq!(frames, &vec![(HEADERS, END_STREAM | END_HEADERS, 0, ten), (RST_STREAM, 0, NO_ERROR, ten)], "stream {stream}");
            } else {
                assert_eq!((frames[0].0, frames[0].2, frames[0].3), (RST_STREAM, REFUSED_STREAM, Duration::ZERO), "stream {stream}: {frames:?}");
            }
        }
        assert_eq!(seen.keys().copied().collect::<Vec<u32>>(), (0..20).map(|i| 2 * i + 1).collect::<Vec<u32>>());
        conns.push(c);
    }
    let calls = rig.lines("call");
    assert_eq!(calls.len(), 1, "only the call beside them reached the handler: {calls:?}");

    // The cut freed the streams: a whole `Call` with no token on the first connection reaches the handler (16).
    let request = ai_env_relay_proto::v1::CallRequest { source: "example.alpha".into(), op: "get".into(), ..Default::default() }.encode_to_vec();
    let c = &mut conns[0];
    c.send(HEADERS, END_HEADERS, 41, &headers).await;
    c.send(DATA, END_STREAM, 41, &grpc(u32::try_from(request.len()).unwrap(), &request)).await;
    loop {
        let f = tokio::time::timeout(PATIENCE, c.next()).await.expect("a frame in time").expect("the connection stays up");
        if f.stream == 41 {
            assert_eq!((f.kind, f.flags & END_STREAM), (HEADERS, END_STREAM), "a whole answer, not a refusal");
            break;
        }
    }
    rig.until(Duration::from_secs(5), "its call line", |r| r.lines("call").len() == 2).await;
    let line = rig.lines("call").pop().unwrap();
    assert_eq!((line["outcome"].as_str(), line["code"].as_i64()), (Some("unauthenticated"), Some(16)));
}

/// Relay 32: the private face's header list holds the longest token (2048 bytes) with the request's own headers
/// and a kilobyte to spare, and refuses one of 4096 bytes before any handler (R-5).
#[tokio::test]
async fn the_private_header_list_fits_a_token_and_no_more() {
    let rig = Rig::start().await;
    let mut client = rig.client().await;
    let with = |value_len: usize, pad: usize| {
        let mut r = tonic::Request::new(ai_env_relay_proto::v1::ListSourcesRequest {});
        r.metadata_mut().insert(ai_env_relay::session::SESSION_HEADER, "t".repeat(value_len).parse().unwrap());
        if pad > 0 {
            r.metadata_mut().insert("x-pad", "p".repeat(pad).parse().unwrap());
        }
        r
    };
    let s = client.list_sources(with(2048, 1024)).await.expect_err("not a token, only its length");
    assert_eq!((s.code(), s.message()), (Code::Unauthenticated, "authentication failed"), "the handler ran");
    assert_eq!(rig.lines("list").len(), 1);

    let s = client.list_sources(with(4096, 0)).await.expect_err("over the header list");
    // h2 answers 431 (Request Header Fields Too Large) and resets the stream; tonic reads the 431 as UNKNOWN.
    assert_eq!(s.code(), Code::Unknown, "{s:?}");
    assert!(s.message().contains("431"), "{s:?}");
    assert_eq!(rig.lines("list").len(), 1, "no list line: the handler never ran");

    list(&mut client, &rig.token("g-all")).await.expect("the same connection serves on");
}

/// Relay 28.
#[tokio::test]
async fn frames_after_auth_are_checked_or_ignored() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    a.out.send(WorkerFrame { msg: None }).await.unwrap();
    rig.until(Duration::from_secs(5), "an unknown frame counted", |r| r.app.snapshot().unknown_frames == 1).await;
    assert_eq!(rig.app.snapshot().tunnels, 1);

    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let pending = call(&mut client, &token, "example.alpha.logs", "get", b"{}").await.unwrap();
    let rid = a.invoke(0).await.request_id;
    let replacement = vec![source("example.alpha", &["get"]), source("example.alpha.stats", &["get"])];
    a.send(worker_frame::Msg::Catalog(Catalog { sources: replacement })).await;
    rig.until(Duration::from_secs(5), "the catalog replaced", |r| r.app.snapshot().sources_live == 2 && r.app.snapshot().sources_offline == 0).await;
    let listed = list(&mut client, &token).await.unwrap();
    assert_eq!(names(&listed), vec![("example.alpha".to_string(), true), ("example.alpha.stats".to_string(), true)]);
    a.send(worker_frame::Msg::Chunk(data(&rid, 0, b"{}".to_vec(), true))).await;
    let (chunks, _) = drain(pending).await;
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].r#final && chunks[0].error.is_none(), "a call routed before the replacement runs to its end");

    a.send(worker_frame::Msg::Catalog(Catalog { sources: vec![source("other.x", &["get"])] })).await;
    assert_eq!(a.closed().await.code, 4);

    let mut b = TestWorker::open(&rig).await;
    b.authenticate("worker-a", 1).await.unwrap();
    b.register(catalog_a()).await;
    b.send(worker_frame::Msg::Hello(hello("worker-a", 1))).await;
    let close = b.close().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "unexpected hello after auth"));
}

/// Relay 29.
#[tokio::test]
async fn shutdown_closes_tunnels_and_ends_calls() {
    let mut rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let mut streams = Vec::new();
    for source in ["example.alpha", "example.alpha.logs", "example.beta"] {
        streams.push(call(&mut client, &token, source, "get", b"{}").await.unwrap());
    }
    b.invoke(0).await;
    a.invoke(1).await;
    rig.app.shutdown();
    for w in [&a, &b] {
        let close = w.closed().await;
        assert_eq!((close.code, close.reason.as_str()), (0, "the relay is shutting down"));
    }
    for s in streams {
        let (chunks, _) = drain(s).await;
        let e = chunks.last().unwrap().error.as_ref().unwrap();
        assert_eq!((e.code, e.message.as_str()), (14, "the relay is shutting down"));
    }
    drop(client);
    for srv in [rig.public_srv.take().unwrap(), rig.private_srv.take().unwrap()] {
        let done = tokio::time::timeout(Duration::from_secs(6), srv).await.expect("served out within 6 s");
        assert!(done.unwrap().is_ok());
    }
}

/// Relay 30 (paused).
#[tokio::test(start_paused = true)]
async fn the_status_line_counts_and_names_nothing_secret() {
    let rig = Rig::start().await;
    let _a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let _ = drain(call(&mut client, &token, "example.alpha", "get", b"{\"q\":\"ZZ-SENTINEL-PARAM\"}").await.unwrap()).await;
    tokio::time::sleep(Duration::from_secs(301)).await;
    let status = rig.lines("status");
    assert_eq!(status.len(), 1, "one line at 300 s");
    let line = &status[0];
    assert_eq!(keys_of(line), sorted(&STATUS_KEYS));
    assert_eq!((line["tunnels"].as_u64(), line["sources_live"].as_u64(), line["calls_in_flight"].as_u64()), (Some(1), Some(2), Some(0)));
    assert_eq!(line["workers_version"], format!("{:016x}", content_version(&rig.read(WORKERS_FILE))));
    let text = line.to_string();
    assert!(!text.contains('*') && !text.contains("ZZ-SENTINEL") && !text.contains(&token[3..40]));
    let key = ai_env_worker::keys::SigningKey::from_seed(&[1; 32]).unwrap().public_key().b64();
    assert!(!text.contains(&key));
}
