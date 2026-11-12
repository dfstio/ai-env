//! The relay in-process (§R-relay.7, relay 1 to 55): tonic over `tokio::io::duplex` with the rig of
//! `tests/common`. Tests marked "paused" run on tokio's paused clock and assert virtual time.

mod common;

use std::time::Duration;

use ai_env_relay::files::{content_version, Poll, FETCHED_FILE};
use ai_env_relay::lists::{ACCESS_FILE, GRANTS_FILE, SIGNERS_FILE, WORKERS_FILE};
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
    // B's entry lapsed, and A's certificate in force: this one reaches the Challenge and its proof, so `expired` stands.
    let expired = Rig::start().await;
    expired.write_workers(&[worker_entry("worker-a", 1, &["example.alpha*"], NOT_AFTER), worker_entry("worker-b", 2, &["example.beta*"], "2027-01-15T07:00:00Z")]);
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
                let h = hello("worker-b", 2);
                let p = proof(c, &h, 2);
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

    // R-126: A's `not_after` passed: no entry in force holds its certificate, so `open()` refuses it, before the Challenge.
    let lapsed = Rig::start().await;
    lapsed.write_workers(&[worker_entry("worker-a", 1, &["example.alpha*"], "2027-01-15T07:00:00Z")]);
    lapsed.poll();
    assert_eq!(refused_reason(&lapsed, 1).await, "unknown_cert");
    assert_eq!(lapsed.app.snapshot().tunnels, 0);
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
    assert_eq!(refused_reason(&rig, 1).await, "not_loaded");
    rig.write_workers(&default_workers());
    rig.write_fetched(rig.clock.unix());
    rig.poll();
    TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
}

fn reloads(rig: &Rig, file: &str) -> Vec<serde_json::Value> {
    rig.lines("reload").into_iter().filter(|l| l["file"] == file).collect()
}

/// R-126 (LD-R33): a connection presenting this seed's certificate, refused at `open()`: 16 `authentication failed`
/// with no Challenge and no frame (`open_on` takes the first frame or status), and one tunnel line with no worker and
/// no sdk; its reason.
async fn refused_reason(rig: &Rig, seed: u8) -> String {
    let (channel, _link) = rig.public_channel_as(seed).await;
    let status = TestWorker::open_on(channel).await.err().expect("refused before the Challenge");
    assert_eq!((status.code(), status.message()), (Code::Unauthenticated, "authentication failed"));
    let line = rig.lines("tunnel").pop().unwrap();
    assert_eq!((line["phase"].as_str(), line["outcome"].as_str()), (Some("auth"), Some("refused")), "{line}");
    assert_eq!((line["worker"].as_str(), line["sdk"].as_str(), line["peer"].as_str()), (Some(""), Some(""), Some(WORKER_IP)), "{line}");
    line["reason"].as_str().unwrap().to_string()
}

/// Relay 6.
#[tokio::test]
async fn a_stale_whitelist_closes_tunnels_and_refuses_handshakes() {
    let rig = Rig::start().await;
    let mut a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
    let mut challenged = TestWorker::open(&rig).await;
    let before = reloads(&rig, "workers").len();
    rig.clock.set(T0 + 901);
    assert_eq!(rig.poll()[0].1, Poll::Stale);
    let close = a.close().await;
    assert_eq!((close.code, close.reason.as_str()), (6, "the whitelist is stale"));
    let lines = reloads(&rig, "workers");
    assert_eq!(lines.len(), before + 1);
    assert_eq!(lines.last().unwrap()["outcome"], "stale");
    assert_eq!(refused_reason(&rig, 1).await, "stale");
    // R-10's own step stays (LD-R33), for a Challenge taken while the file was fresh.
    let h = hello("worker-a", 1);
    let p = proof(&challenged.challenge, &h, 1);
    challenged.send(worker_frame::Msg::Hello(h)).await;
    challenged.send(worker_frame::Msg::AuthProof(p)).await;
    assert_eq!(challenged.end().await.expect_err("stale").code(), Code::Unauthenticated);
    assert_eq!(rig.lines("tunnel").pop().unwrap()["reason"], "stale");
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
    let mut challenged = TestWorker::open(&rig).await;
    rig.remove(WORKERS_FILE);
    assert_eq!(rig.poll()[0].1, Poll::Missing);
    let close = a.close().await;
    assert_eq!((close.code, close.reason.as_str()), (6, "the whitelist is not loaded"));
    assert_eq!(reloads(&rig, "workers").last().unwrap()["outcome"], "missing");
    assert_eq!(refused_reason(&rig, 1).await, "not_loaded");
    // R-10's own step stays (LD-R33), for a Challenge taken while the file was loaded.
    let h = hello("worker-a", 1);
    let p = proof(&challenged.challenge, &h, 1);
    challenged.send(worker_frame::Msg::Hello(h)).await;
    challenged.send(worker_frame::Msg::AuthProof(p)).await;
    assert_eq!(challenged.end().await.expect_err("not loaded").code(), Code::Unauthenticated);
    assert_eq!(rig.lines("tunnel").pop().unwrap()["reason"], "not_loaded");

    rig.write(WORKERS_FILE, &good);
    rig.poll();
    let mut a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await;
    rig.write(WORKERS_FILE, b"[{\"worker_id\":\"worker-a\"");
    assert!(matches!(rig.poll()[0].1, Poll::Refused(_)));
    let close = a.close().await;
    assert_eq!((close.code, close.reason.as_str()), (6, "the whitelist is not loaded"));
    assert_eq!(reloads(&rig, "workers").last().unwrap()["outcome"], "refused");
    assert_eq!(refused_reason(&rig, 1).await, "not_loaded");

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
    // R-126: no entry in force holds A's certificate any more: refused at `open()`, before the Challenge.
    assert_eq!(refused_reason(&rig, 1).await, "unknown_cert");
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
    let mut w = TestWorker::open_as(rig, seed).await;
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

/// `TestWorker::connect` over a connection from `ip` (`Rig::public_channel_from_as`), once no tunnel is live.
async fn connect_from(rig: &Rig, ip: &str, worker_id: &str, seed: u8, sources: Vec<ai_env_relay_proto::v1::SourceDescriptor>) -> TestWorker {
    let before = rig.app.snapshot().sources_live;
    let n = sources.len() as u64;
    let (channel, link) = rig.public_channel_from_as(ip.parse().unwrap(), seed).await;
    let mut w = TestWorker::open_on(channel).await.expect("the Challenge");
    w.link = Some(link);
    w.authenticate(worker_id, seed).await.expect("authenticated");
    w.register(sources).await;
    rig.until(Duration::from_secs(10), "the catalog installed", |r| r.app.snapshot().sources_live >= before + n).await;
    w
}

/// Relay 37 (R-90): every poll judges each live tunnel's peer against the peers file. A (from `WORKER_IP`,
/// `198.51.100.10`) and C (from `198.51.100.12`) live; the file rewritten with C's `/32` alone and polled: its reload
/// line says `loaded` with its own version and entries (R-88), A gets `Close{1, "peer revoked"}`, its close line
/// `peer_revoked`, and C stays. C's entry then lapses while the file stays
/// unchanged and fresh (an `allow-ip --mine` past its day): C stays through its `not_after` second and gets
/// `Close{1, "peer revoked"}` (close line `peer_revoked`) one second later. The file removed and polled: C's next
/// tunnel gets `Close{6, "the peers list is not loaded"}` (close line `stale`). A peers file loaded while the clock is
/// past its `fetched` + 900 s (the reload's stamp of T0 + 99 with the clock at T0 + 1000, the whitelist still fresh
/// from T0 + 1000's fetch): C's next tunnel gets `Close{6, "the peers list is stale"}`.
#[tokio::test]
async fn a_peer_no_longer_listed_loses_its_tunnel() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let c = connect_from(&rig, "198.51.100.12", "worker-c", 5, catalog_c()).await.serve(Script::silent());
    rig.tunnels(2).await;
    rig.write_peers(&[peer_entry("198.51.100.12/32", "worker-c")]);
    let polled = rig.poll();
    assert!(matches!(polled[4], ("peers", Poll::Loaded { .. })), "{polled:?}");
    // R-88: its reload line names the file's own version and entries.
    let line = reloads(&rig, "peers").pop().expect("a reload line of peers");
    assert_eq!(line["outcome"], "loaded");
    assert_eq!(line["version"], format!("{:016x}", content_version(&rig.read(ai_env_relay::lists::PEERS_FILE))));
    assert_eq!(line["entries"], 1);
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (1, "peer revoked"));
    let closed = |r: &Rig, worker: &str, reason: &str| r.lines("tunnel").iter().any(|l| l["phase"] == "close" && l["worker"] == worker && l["reason"] == reason);
    rig.until(Duration::from_secs(10), "A's close line", |r| closed(r, "worker-a", "peer_revoked")).await;
    rig.tunnels(1).await;
    rig.poll();
    let mut client = rig.client().await;
    let listed = list(&mut client, &rig.token("g-all")).await.unwrap();
    assert_eq!(names(&listed), vec![("example.gamma".to_string(), true)], "A's sources removed, as a revocation's: {:?}", names(&listed));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(c.closes().is_empty(), "C's /32 is listed: its tunnel stays");
    assert_eq!(rig.app.snapshot().tunnels, 1);

    // C's entry in force until T0 + 5, then the clock and the reload's fetch moving on while the file stays as it is:
    // fresh at every poll, C allowed through its not_after second and revoked the second after.
    const C_NOT_AFTER: &str = "2027-01-15T08:00:05Z";
    let c_not_after = ai_env_worker::policy::unix_of(C_NOT_AFTER).unwrap();
    assert_eq!(c_not_after, T0 + 5);
    rig.write_peers(&[ai_env_worker::policy::PeerEntry { not_after: C_NOT_AFTER.into(), ..peer_entry("198.51.100.12/32", "worker-c") }]);
    assert!(matches!(rig.poll()[4], ("peers", Poll::Loaded { .. })));
    rig.clock.set(c_not_after);
    rig.write_fetched(c_not_after);
    assert_eq!(rig.poll()[4], ("peers", Poll::Unchanged));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(c.closes().is_empty(), "in force through its not_after second");
    rig.clock.set(c_not_after + 1);
    rig.write_fetched(c_not_after + 1);
    let polled = rig.poll();
    assert!(polled.iter().all(|(_, p)| *p == Poll::Unchanged), "every file as it was, and fresh: {polled:?}");
    let close = c.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (1, "peer revoked"));
    rig.until(Duration::from_secs(10), "C's close line", |r| closed(r, "worker-c", "peer_revoked")).await;
    rig.until(Duration::from_secs(10), "no tunnel", |r| r.app.snapshot().tunnels == 0 && r.app.snapshot().sources_live == 0).await;

    // Listed again: C's next tunnel, then the file removed and polled.
    rig.write_peers(&default_peers());
    rig.poll();
    let c = connect_from(&rig, "198.51.100.12", "worker-c", 5, catalog_c()).await.serve(Script::silent());
    rig.remove(ai_env_relay::lists::PEERS_FILE);
    assert_eq!(rig.poll()[4].1, Poll::Missing);
    let close = c.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (6, "the peers list is not loaded"));
    rig.until(Duration::from_secs(10), "C's close line", |r| closed(r, "worker-c", "stale")).await;
    rig.until(Duration::from_secs(10), "no tunnel", |r| r.app.snapshot().tunnels == 0 && r.app.snapshot().sources_live == 0).await;

    // Listed again, then every list fetched at T0 + 1000: C's next tunnel lives.
    rig.write_peers(&default_peers());
    rig.poll();
    let c = connect_from(&rig, "198.51.100.12", "worker-c", 5, catalog_c()).await.serve(Script::silent());
    rig.clock.set(T0 + 1000);
    rig.write_fetched(T0 + 1000);
    rig.poll();
    assert!(c.closes().is_empty(), "every list fresh");
    // The peers file rewritten while `fetched` holds T0 + 99: it loads as of that fetch, 901 s before the clock, while
    // the whitelist keeps T0 + 1000 (a fetch time only ever moves a file's freshness forward, R-16).
    rig.write_fetched(T0 + 99);
    rig.write_peers(&[peer_entry("198.51.100.12/32", "worker-c"), peer_entry("203.0.113.0/24", "office")]);
    let polled = rig.poll();
    assert!(matches!(polled[0], ("workers", Poll::Unchanged)) && matches!(polled[4], ("peers", Poll::Loaded { .. })), "{polled:?}");
    let close = c.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (6, "the peers list is stale"));
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
        // One answer first: it brings the face's SETTINGS (16 streams, R-5) to the client, which then queues its calls
        // instead of opening a seventeenth stream to be refused.
        let mut client = rig.client().await;
        list(&mut client, &tokens[0]).await.expect("listed");
        clients.push(client);
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

/// Relay 19 (amended: its many refused tokens on one connection are R-53's subject, not R-105's, so the connection's
/// fault cap is out of the way).
#[tokio::test]
async fn session_tokens_gate_the_private_face_alike() {
    let rig = Rig::start_with(Limits { private_faults_max: 1000, ..limits() }).await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    let now = rig.clock.unix();
    let past = SessionClaims { iat: now - 7200, exp: now - 3600, ..rig.claims("g-all") };
    let other_kid = SessionClaims { kid: "mac-9".into(), caller_id: "mac-9".into(), ..rig.claims("g-all") };
    let changed = {
        let t = rig.token("g-all");
        let parts: Vec<&str> = t.split('.').collect();
        let json = String::from_utf8(b64url_decode(parts[1])).unwrap().replace(RELAY_ID, "ai-env-other");
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

/// A token of these exact claims, signed by a seed's key: what W/M's `session::mint` would refuse to make.
fn signed(seed: u8, claims: &SessionClaims) -> String {
    let json = serde_json::to_vec(claims).unwrap();
    let signature = ai_env_worker::keys::SigningKey::from_seed(&[seed; 32]).unwrap().sign(&ai_env_worker::session::signing_input(&json));
    format!("v1.{}.{}", b64url_encode(&json), b64url_encode(&signature))
}

/// Relay 20, inverted (R-133): a token with `kid` `mac` and `caller_id` `mac-desk`, its signature good, is refused 16 and
/// reaches no worker; with both `mac` the caller is the token's, whatever the metadata says.
#[tokio::test]
async fn the_caller_is_the_tokens_never_the_requests() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    let desk = signed(7, &SessionClaims { caller_id: "mac-desk".into(), ..rig.claims("g-all") });
    let s = call(&mut client, &desk, "example.alpha", "get", b"{}").await.expect_err("another caller under this signer");
    assert_eq!((s.code(), s.message()), (Code::Unauthenticated, "authentication failed"));
    let s = list(&mut client, &desk).await.expect_err("another caller under this signer");
    assert_eq!((s.code(), s.message()), (Code::Unauthenticated, "authentication failed"));
    assert!(a.invokes().is_empty(), "nothing reached the worker");
    assert_eq!(rig.app.snapshot().sessions, 0, "no session made");
    let claims = rig.claims("g-all");
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
        ("mac", claims.session_id.as_str(), "g-all", VM_ID)
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
    // R-111 (amended): the eviction comes at once, with no hand-off wait: no time passes.
    a.until("call 1 cancelled", |r| r.cancels.iter().any(|c| c.request_id == call1)).await;
    assert!(t0.elapsed() < Duration::from_millis(100), "evicted at once, not after 2 s: {:?}", t0.elapsed());
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
    // R-146: an access list loaded; the tokens of the outcomes below that go through it are `token`'s, of its chat.
    rig.write_access(&[access_entry(CHAT, &["g-example"])]);
    rig.poll();
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
    let token = rig.chat_token("no-grant", CHAT);
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
        assert!(PEER_NETS.iter().all(|net| !line.contains(net)), "a peers network in {line}");
        assert!(!line.contains(CHAT), "a chat's id in {line}");
    }
    // The status line's values (§RS.3.1, R-146): every key of STATUS_KEYS but `ts` and `ev`, the peers file's and the
    // access file's among them.
    let status = serde_json::to_value(rig.app.snapshot()).unwrap();
    assert_eq!(keys_of(&status), sorted(&STATUS_KEYS[2..]));
    assert_eq!(status["peers_version"], format!("{:016x}", content_version(&rig.read(ai_env_relay::lists::PEERS_FILE))));
    assert_eq!(status["access_version"], format!("{:016x}", content_version(&rig.read(ACCESS_FILE))));
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

    let mut b = TestWorker::open_as(&rig, 2).await;
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
    pub const PING: u8 = 0x6;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const ACK: u8 = 0x1;
    /// SETTINGS_INITIAL_WINDOW_SIZE, SETTINGS_MAX_CONCURRENT_STREAMS and SETTINGS_MAX_HEADER_LIST_SIZE (RFC 9113
    /// §6.5.2).
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
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
    // Amended: R-103's token deadline after R-5's 10 s, so its connections outlive their unfinished streams.
    let rig = Rig::start_with(Limits { handshake_timeout_ms: 30_000, ..limits() }).await;
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
        assert!(settings.contains(&(INITIAL_WINDOW_SIZE, 65_536 + 16_384 + 16_384)), "F28: the decode cap (params_max_bytes and 16 KiB) and 16 KiB: {settings:?}");
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
    // R-146: the access list loaded from a fetch 8 s before the rig's, so its age is its own (the rest keep T0, R-16).
    rig.write_fetched(T0 - 8);
    rig.write_access(&[access_entry(CHAT, &["g-example"])]);
    assert!(matches!(rig.poll()[5], ("access", Poll::Loaded { .. })));
    let _a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let _ = drain(call(&mut client, &token, "example.alpha", "get", b"{\"q\":\"ZZ-SENTINEL-PARAM\"}").await.unwrap()).await;
    // The wall clock 42 s past the rig's fetch at T0: the line's ages count from that fetch.
    rig.clock.set(T0 + 42);
    tokio::time::sleep(Duration::from_secs(301)).await;
    let status = rig.lines("status");
    assert_eq!(status.len(), 1, "one line at 300 s");
    let line = &status[0];
    assert_eq!(keys_of(line), sorted(&STATUS_KEYS));
    assert!(line["log_suppressed"].as_u64().is_some(), "F23's count: {line}");
    assert_eq!((line["tunnels"].as_u64(), line["sources_live"].as_u64(), line["calls_in_flight"].as_u64()), (Some(1), Some(2), Some(0)));
    assert_eq!(line["workers_version"], format!("{:016x}", content_version(&rig.read(WORKERS_FILE))));
    // §RS.3.1: the peers file's version and age, never its networks or labels.
    assert_eq!(line["peers_version"], format!("{:016x}", content_version(&rig.read(ai_env_relay::lists::PEERS_FILE))));
    assert_eq!(line["peers_age_s"].as_u64(), Some(42), "fetched at the rig's T0, the wall clock at T0 + 42");
    // R-146: the access file's version and age, never a chat or a grant of it.
    assert_eq!(line["access_version"], format!("{:016x}", content_version(&rig.read(ACCESS_FILE))));
    assert_eq!(line["access_age_s"].as_u64(), Some(50), "fetched at T0 - 8, the wall clock at T0 + 42");
    let text = line.to_string();
    assert!(!text.contains(CHAT) && !text.contains("g-example"), "an access entry in {text}");
    assert!(PEER_NETS.iter().all(|net| !text.contains(net)) && !text.contains("test-net-2"), "a peers entry in {text}");
    assert!(!text.contains('*') && !text.contains("ZZ-SENTINEL") && !text.contains(&token[3..40]));
    let key = ai_env_worker::keys::SigningKey::from_seed(&[1; 32]).unwrap().public_key().b64();
    assert!(!text.contains(&key));
}

/// relay.log's lines, as `reqlog::log_subscriber`'s formatter wrote them.
#[derive(Clone, Default)]
struct Written(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Written {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Written {
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap().lines().map(str::to_string).collect()
    }
}

/// Relay 36 (F23): a thousand PING frames with the ACK flag that answer no ping of the relay's, on a public connection
/// with no `Open`, as a peer that never authenticates may send them. h2 writes a `warn` for each; through the
/// subscriber `ai-env-relay` installs (`reqlog::log_subscriber`, production's filter and cap) relay.log gains no line
/// but the relay's own (which the cap exempts, and which a poll may write meanwhile), and none of them reaches the
/// cap (the filter holds h2 at `error`). With an operator's module directive that lets them through, the cap (here
/// one line a minute) writes exactly one and counts the rest. The face's SETTINGS and its connection's WINDOW_UPDATE
/// give its windows (F28): `catalog_max_bytes` and 16 KiB.
#[tokio::test]
async fn unsolicited_ping_acks_write_no_log_lines() {
    use h2raw::*;
    let rig = Rig::start().await;
    let window = ai_env_source::wire::FRAME_MAX as u32 + 16_384;
    let per_min = Limits::default().log_refusals_per_min;
    for (spec, cap) in [(None, per_min), (Some("info,h2::proto=warn"), 1)] {
        let written = Written::default();
        let w = written.clone();
        let _guard = tracing::subscriber::set_default(ai_env_relay::reqlog::log_subscriber(spec, cap, move || w.clone()));
        let before = rig.app.snapshot().log_suppressed;
        let mut c = Conn::open(rig.public_raw(1 << 20), Instant::now()).await;
        for i in 0..1000u64 {
            c.send(PING, ACK, 0, &i.to_be_bytes()).await;
        }
        // A ping of the test's own: its answer comes after the relay read all thousand.
        c.send(PING, 0, 0, b"probe-01").await;
        let (mut settings, mut increment) = (Vec::new(), None);
        loop {
            let f = tokio::time::timeout(PATIENCE, c.next()).await.expect("a frame in time").expect("the connection stays up");
            match f.kind {
                SETTINGS if f.flags & ACK == 0 => settings.extend(pairs(&f.payload)),
                WINDOW_UPDATE if f.stream == 0 => increment = Some(u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) & 0x7fff_ffff),
                PING if f.flags & ACK != 0 && f.payload == b"probe-01" => break,
                _ => {}
            }
        }
        assert!(settings.contains(&(INITIAL_WINDOW_SIZE, window)), "each stream's window: {settings:?}");
        assert_eq!(increment, Some(window - 65_535), "the connection's window");
        // The lines of any target but the relay's own (`ai_env_relay`, `ai_env_relay::…`).
        let lines: Vec<String> = written.lines().into_iter().filter(|l| !l.contains(" ai_env_relay::") && !l.contains(" ai_env_relay: ")).collect();
        let suppressed = rig.app.snapshot().log_suppressed - before;
        match spec {
            None => {
                assert!(lines.is_empty(), "{} lines: {:?}", lines.len(), &lines[..lines.len().min(3)]);
                assert_eq!(suppressed, 0, "the filter held them before the cap");
            }
            Some(_) => {
                assert_eq!(lines.len(), 1, "{spec:?}: the cap's one line: {:?}", &lines[..lines.len().min(3)]);
                assert!(lines[0].contains(" h2::proto::ping_pong: recv PING ack that we never sent"), "{lines:?}");
                assert!(suppressed >= 999, "the cap took the rest: {suppressed}");
            }
        }
    }
}

/// A VM's client that never reads (relays 39 and 44): its streams' window is 0, so the relay can send them nothing.
/// hyper 1.11 takes one frame of a response body before it waits for send capacity, and tonic packs a frame with the
/// chunks at hand up to 32 KiB: such a stream takes its first frame's chunks out of the call's buffer, and the chunks
/// after them stay there.
async fn deaf_client(rig: &Rig) -> (ai_env_relay_proto::v1::relay_client::RelayClient<tonic::transport::Channel>, Link) {
    let endpoint = tonic::transport::Endpoint::from_static("http://10.42.0.20").initial_stream_window_size(0);
    let (channel, link) = rig.private_channel_with(endpoint, 1 << 20).await;
    (ai_env_relay_proto::v1::relay_client::RelayClient::new(channel), link)
}

/// Runs the other tasks until `f` holds, without moving tokio's clock (a budget refills with time).
async fn settle(what: &str, f: impl Fn() -> bool) {
    for _ in 0..200_000 {
        if f() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("never: {what}");
}

/// A script that answers each call with `n` chunks of `size` bytes, none final, in one write (no await between them).
fn burst(n: u64, size: usize) -> Script {
    Script::with(move |inv, out| {
        for seq in 0..n {
            let _ = out.try_send(wf(worker_frame::Msg::Chunk(data(&inv.request_id, seq, vec![b'x'; size], false))));
        }
    })
}

/// Relay 38 (paused): eight refused tokens on one private connection fault it (R-105). Each `ListSources` is 16 and
/// the eighth's status arrives; a ninth with a valid token, sent within the next second, is refused 16 all the same
/// (no token is verified on a faulted connection); a second after the eighth the connection is cut, with one peer
/// line `bad_tokens`, and a request then fails at the transport. Refusals while the token signers are not loaded are
/// the relay's own and count nothing. On a fresh connection the eighth is the one that faults, and a verified token
/// resets nothing: seven refused, a valid one served, one more refused, then a valid one 16 and the cut a second after
/// the eighth. On another, a request with no header counts too: four refused, a valid one served, three refused, and
/// the one with no header faults it.
#[tokio::test(start_paused = true)]
async fn eight_refused_tokens_cut_their_connection() {
    let rig = Rig::start().await;
    assert_eq!(Limits::default().private_faults_max, 8);
    let (channel, link) = rig.private_channel().await;
    let mut client = ai_env_relay_proto::v1::relay_client::RelayClient::new(channel);
    let refused = mint(4, &rig.claims("g-all"));
    for i in 0..8 {
        let s = list(&mut client, &refused).await.expect_err("refused");
        assert_eq!((s.code(), s.message()), (Code::Unauthenticated, "authentication failed"), "refusal {i}");
    }
    let eighth = Instant::now();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let valid = rig.token("g-all");
    let s = list(&mut client, &valid).await.expect_err("faulted: refused before any token is verified");
    assert_eq!((s.code(), s.message()), (Code::Unauthenticated, "authentication failed"));
    rig.until(Duration::from_secs(5), "the cut", |_| link.peer_closed_at().is_some()).await;
    assert_eq!(link.peer_closed_at(), Some(eighth + Duration::from_secs(1)), "cut a second after the eighth refusal");
    let s = list(&mut client, &valid).await.expect_err("the connection is cut");
    assert_ne!(s.code(), Code::Unauthenticated, "a transport failure, not the relay's 16: {s:?}");
    let peers = rig.lines("peer");
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert_eq!((peers[0]["face"].as_str(), peers[0]["reason"].as_str(), peers[0]["peer"].as_str()), (Some("private"), Some("bad_tokens"), Some(VM_IP)));
    let lists = rig.lines("list");
    assert!(lists.len() == 9 && lists.iter().all(|l| l["outcome"] == "unauthenticated" && l["code"] == 16), "{lists:?}");

    // The token signers gone: ten refusals on a new connection count nothing, so once they are back its valid token
    // is served.
    let signers = rig.read(SIGNERS_FILE);
    rig.remove(SIGNERS_FILE);
    rig.poll();
    let mut other = rig.client().await;
    for _ in 0..10 {
        assert_eq!(list(&mut other, &valid).await.expect_err("no signers").code(), Code::Unauthenticated);
    }
    rig.write(SIGNERS_FILE, &signers);
    rig.poll();
    list(&mut other, &valid).await.expect("not faulted: the relay's own refusals count nothing");
    assert_eq!(rig.lines("peer").len(), 1);

    // The count of eight, exactly, with a verified token among them.
    let (channel, link) = rig.private_channel().await;
    let mut client = ai_env_relay_proto::v1::relay_client::RelayClient::new(channel);
    for i in 0..7 {
        let s = list(&mut client, &refused).await.expect_err("refused");
        assert_eq!(s.code(), Code::Unauthenticated, "refusal {i}");
    }
    list(&mut client, &valid).await.expect("seven refused: not faulted yet");
    list(&mut client, &refused).await.expect_err("the eighth refused");
    let eighth = Instant::now();
    let s = list(&mut client, &valid).await.expect_err("the eighth faulted it: a verified token resets nothing");
    assert_eq!((s.code(), s.message()), (Code::Unauthenticated, "authentication failed"));
    rig.until(Duration::from_secs(5), "the cut", |_| link.peer_closed_at().is_some()).await;
    assert_eq!(link.peer_closed_at(), Some(eighth + Duration::from_secs(1)), "cut a second after the eighth");
    assert_eq!(rig.lines("peer").len(), 2);

    // A request with no header is a refused token too.
    let (channel, link) = rig.private_channel().await;
    let mut client = ai_env_relay_proto::v1::relay_client::RelayClient::new(channel);
    for _ in 0..4 {
        list(&mut client, &refused).await.expect_err("refused");
    }
    list(&mut client, &valid).await.expect("four refused: served");
    for _ in 0..3 {
        list(&mut client, &refused).await.expect_err("refused");
    }
    let s = client.list_sources(tonic::Request::new(ai_env_relay_proto::v1::ListSourcesRequest {})).await.expect_err("no token");
    assert_eq!(s.code(), Code::Unauthenticated);
    let eighth = Instant::now();
    list(&mut client, &valid).await.expect_err("the one with no header was the eighth");
    rig.until(Duration::from_secs(5), "the cut", |_| link.peer_closed_at().is_some()).await;
    assert_eq!(link.peer_closed_at(), Some(eighth + Duration::from_secs(1)), "cut a second after the eighth");
    let peers = rig.lines("peer");
    assert!(peers.len() == 3 && peers.iter().all(|p| p["reason"] == "bad_tokens"), "{peers:?}");
}

/// Relay 39 (paused): a call evicted while its client holds its stream and never reads it frees its session's pass
/// at once (R-106: `calls_per_session` 1, and the session's next call is admitted), while the stream keeps the
/// relay's permit (`calls_in_flight` 1, then 2) until its connection is cut 10 s after the eviction with a peer line
/// `undrained` (R-103), and `calls_in_flight` is 0 again. With `calls_in_flight_max` 2, the two make a third call 8
/// `too many calls in flight` until the cut. A call answered by one final chunk of 64 KiB, to such a client, concludes
/// `ok` at once, but hyper holds the final's frame unsent, so its stream keeps the relay's permit (`calls_in_flight`
/// 1) until the connection is cut `undrained` 10 s after the call concluded: the permit goes when hyper drops the
/// stream, not when the stream yields its last item (review B finding 1).
#[tokio::test(start_paused = true)]
async fn an_undrained_call_frees_its_session_at_once_and_its_relay_permit_at_the_cut() {
    let rig = Rig::start_with(Limits { calls_in_flight_max: 2, calls_per_session: 1, ..limits() }).await;
    // Six chunks of 64 KiB at once: the deaf stream takes the first, four fill the caller's buffer, the sixth evicts.
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(burst(6, 65_536));
    let (mut deaf, link) = deaf_client(&rig).await;
    let token = rig.token("g-all");
    let evictions = |a: &Served| a.cancels().iter().filter(|c| c.reason == "caller_too_slow").count();
    let first = call(&mut deaf, &token, "example.alpha", "get", b"{}").await.expect("the first call");
    a.until("the first eviction", |r| r.cancels.iter().any(|c| c.reason == "caller_too_slow")).await;
    let evicted = Instant::now();
    assert_eq!(evictions(&a), 1);
    assert_eq!(rig.app.snapshot().calls_in_flight, 1, "its unread stream keeps the relay's permit");
    let second = call(&mut deaf, &token, "example.alpha", "get", b"{}").await.expect("the session's pass came back with the eviction");
    a.until("the second eviction", |r| r.cancels.iter().filter(|c| c.reason == "caller_too_slow").count() == 2).await;
    assert_eq!(rig.app.snapshot().calls_in_flight, 2);
    let mut other = rig.client().await;
    let third = call(&mut other, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect_err("both permits held");
    assert_eq!((third.code(), third.message()), (Code::ResourceExhausted, "too many calls in flight"));
    tokio::time::sleep_until(evicted + Duration::from_millis(9_900)).await;
    assert_eq!(rig.app.snapshot().calls_in_flight, 2, "held until the cut");
    assert!(link.peer_closed_at().is_none() && rig.lines("peer").is_empty());
    rig.until(Duration::from_secs(1), "the undrained cut", |_| link.peer_closed_at().is_some()).await;
    assert_eq!(link.peer_closed_at(), Some(evicted + Duration::from_secs(10)), "10 s after the first eviction");
    rig.until(Duration::from_secs(1), "the permits back", |r| r.app.snapshot().calls_in_flight == 0).await;
    let peers = rig.lines("peer");
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert_eq!((peers[0]["face"].as_str(), peers[0]["reason"].as_str()), (Some("private"), Some("undrained")));
    let _ = call(&mut other, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect("a permit is free again");
    drop((first, second));

    // One final chunk of 64 KiB, sent as the Invoke comes: the call concludes at that instant.
    let rig = Rig::start().await;
    let w = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::with(|inv, out| {
        let _ = out.try_send(wf(worker_frame::Msg::Chunk(data(&inv.request_id, 0, vec![b'x'; 65_536], true))));
    }));
    let (mut deaf, link) = deaf_client(&rig).await;
    let parked = call(&mut deaf, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect("the call");
    w.until("its invoke", |r| r.invokes.len() == 1).await;
    let concluded = Instant::now();
    settle("the call concluded", || rig.lines("call").iter().any(|l| l["outcome"] == "ok")).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(rig.app.snapshot().calls_in_flight, 1, "hyper holds the final's frame, its stream and the stream's permit");
    assert!(link.peer_closed_at().is_none() && rig.lines("peer").is_empty());
    rig.until(Duration::from_secs(10), "the undrained cut", |_| link.peer_closed_at().is_some()).await;
    assert_eq!(link.peer_closed_at(), Some(concluded + Duration::from_secs(10)), "10 s after the call concluded");
    rig.until(Duration::from_secs(1), "the permit back", |r| r.app.snapshot().calls_in_flight == 0).await;
    let peers = rig.lines("peer");
    assert!(peers.len() == 1 && peers[0]["reason"] == "undrained", "{peers:?}");
    drop(parked);
}

/// Relay 40 (paused): a tunnel over its inbound budget is closed `Close{3, "inbound rate"}`, close reason `rate`
/// (R-107). (a) Frames: its first catalog and 599 frames with no variant pass, the 601st frame closes it. (b) Bytes,
/// with `call_bytes_max` and `tunnel_bytes_per_min` both 1 MiB: two live calls' chunks of 600 KiB each are no charge
/// (LD-R53), a cancelled call's late chunks then run the budget out, and each caller gets its final chunk (14). (c)
/// Bytes at the defaults: frames of 64 KiB of fields no variant knows (a decoded length of 0) exhaust the 32 MiB
/// within the frames budget. (d) Short of frames, as of bytes, the connection reads nothing more until R-2a's cut
/// (review B finding 5): on a bare HTTP/2 tunnel, a PING sent after the Close is never answered, and the connection
/// ends 1 s after the close. (e) to (i), below: LD-R53's exemption, and what it leaves charged.
#[tokio::test(start_paused = true)]
async fn a_tunnel_over_its_inbound_budget_is_closed_rate() {
    // (a) No virtual time passes from the AuthOk to the close, so the bucket gains nothing.
    let rig = Rig::start().await;
    assert_eq!(Limits::default().tunnel_frames_per_min, 600);
    let mut a = TestWorker::open(&rig).await;
    a.authenticate("worker-a", 1).await.expect("authenticated");
    a.register(catalog_a()).await;
    for _ in 0..599 {
        a.out.send(WorkerFrame { msg: None }).await.unwrap();
    }
    settle("599 frames with no variant counted", || rig.app.snapshot().unknown_frames == 599).await;
    assert_eq!(rig.app.snapshot().tunnels, 1, "600 frames pass");
    a.out.send(WorkerFrame { msg: None }).await.unwrap();
    let close = a.close().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"));
    assert_eq!(rig.app.snapshot().unknown_frames, 599, "the 601st frame closed it before anything acted on it");
    rig.until(Duration::from_secs(5), "its close line", |r| rate_lines(r) == 1).await;

    // (b)
    let rig = Rig::start_with(bytes_budget(1 << 20)).await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let late = cancelled_call(&rig, &a).await;
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let mut calls = Vec::new();
    for i in 1..=2 {
        let stream = call(&mut client, &token, "example.alpha", "get", b"{}").await.expect("a call");
        calls.push((a.invoke(i).await.request_id, tokio::spawn(drain(stream))));
    }
    for seq in 0..10 {
        for (rid, _) in &calls {
            a.send(chunk_of(rid, seq, 61_440, false)).await;
        }
    }
    read_so_far(&rig, &a, 1).await;
    send_until_closed(&a, (0..20).map(|seq| chunk_of(&late, seq, 65_536, false))).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"));
    for (_, c) in calls {
        let (chunks, end) = c.await.unwrap();
        assert!(end.is_ok());
        assert_eq!(chunks.len(), 11, "its ten chunks and the final");
        let last = chunks.last().expect("a final chunk");
        assert!(last.r#final && final_code(last) == Some(14), "{last:?}");
    }
    rig.until(Duration::from_secs(5), "its close line", |r| rate_lines(r) == 1).await;

    // (c)
    let rig = Rig::start().await;
    let mut w = raw_tunnel(&rig).await;
    let out = w.out.clone();
    let sender = tokio::spawn(async move {
        for _ in 0..560 {
            if out.send(raw::padded(65_536)).await.is_err() {
                return;
            }
        }
    });
    let close = w.close().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"));
    let unknown = rig.app.snapshot().unknown_frames;
    assert!((500..560).contains(&unknown), "32 MiB of 64 KiB frames, within the frames budget: {unknown} frames");
    rig.until(Duration::from_secs(5), "its close line", |r| rate_lines(r) == 1).await;
    sender.abort();

    // (d) As (a), on a bare HTTP/2 connection; no virtual time passes from the AuthOk to the close.
    use ai_env_relay_proto::v1::RelayFrame;
    let rig = Rig::start().await;
    let (mut c, mut pending, mut acks) = bare_tunnel(&rig, 1 << 20).await;
    c.send(h2raw::DATA, 0, 1, &bare_message(None).repeat(599)).await;
    settle("599 frames with no variant counted", || rig.app.snapshot().unknown_frames == 599).await;
    c.send(h2raw::DATA, 0, 1, &bare_message(None)).await;
    let close = bare_close(&mut c, &mut pending, &mut acks).await;
    let closed = Instant::now();
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"));
    c.send(h2raw::PING, 0, 0, b"after-01").await;
    while grpc_message::<RelayFrame>(&mut c, &mut pending, &mut acks).await.is_some() {}
    assert_eq!(acks, 0, "the PING after the Close was never read");
    assert_eq!(Instant::now() - closed, Duration::from_secs(1), "the connection ended at R-2a's cut, 1 s after the close");
    rig.until(Duration::from_secs(5), "its close line", |r| rate_lines(r) == 1).await;
}

/// The rig's limits with this bytes budget and this largest call, the budget's floor (§RS.2).
fn bytes_budget(bytes: u64) -> Limits {
    Limits { call_bytes_max: bytes, call_bytes_default: bytes, tunnel_bytes_per_min: bytes as u32, ..limits() }
}

/// The tunnels closed `rate`.
fn rate_lines(rig: &Rig) -> usize {
    rig.lines("tunnel").into_iter().filter(|l| l["phase"] == "close" && l["reason"] == "rate").count()
}

/// A chunk of `size` bytes.
fn chunk_of(request_id: &str, seq: u64, size: usize, last: bool) -> worker_frame::Msg {
    worker_frame::Msg::Chunk(data(request_id, seq, vec![b'x'; size], last))
}

/// A chunk of an id no call of the tunnel ever carried.
fn stray_chunk(i: u64, size: usize) -> worker_frame::Msg {
    chunk_of(&format!("0199a1b2-0000-7000-8000-{:012x}", 0xa00 + i), 0, size, true)
}

/// A call of `example.alpha`'s uncapped `list`, asking these caps.
fn capped_request(max_bytes: u64, max_chunks: u32) -> CallRequest {
    CallRequest { limits: Some(WireLimits { max_bytes, max_rows: 0, max_chunks }), ..request("example.alpha", "list", b"{}") }
}

/// A call its caller dropped, its Cancel read: its id, whose chunks are `Late` from now on.
async fn cancelled_call(rig: &Rig, a: &Served) -> String {
    let mut client = rig.client().await;
    let n = a.invokes().len();
    let gone = call(&mut client, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect("a call");
    let rid = a.invoke(n).await.request_id;
    drop(gone);
    a.until("its Cancel", |r| r.cancels.iter().any(|c| c.request_id == rid && c.reason == "caller_gone")).await;
    rid
}

/// Sends `frames` until the request stream goes: they run a budget out on the way.
async fn send_until_closed(a: &Served, frames: impl Iterator<Item = worker_frame::Msg>) {
    for msg in frames {
        if a.out.send(wf(msg)).await.is_err() {
            return;
        }
    }
}

/// Sends one frame with no variant and waits for it to make `counted` of them, with no virtual time for a refill:
/// every frame sent before it has been read, and the tunnel serves on.
async fn read_so_far(rig: &Rig, a: &Served, counted: u64) {
    a.out.send(WorkerFrame { msg: None }).await.unwrap();
    settle("the frames sent so far", || rig.app.snapshot().unknown_frames == counted).await;
    assert!(a.closes().is_empty(), "the tunnel serves on: {:?}", a.closes());
}

/// Relay 40 (e) (paused; LD-R53): a chunk of a live call takes no frames token. Three 256-chunk answers at once, 768
/// frames past the burst of 600 with no virtual time for a refill, close nothing; and the frames budget is whole after
/// them: with the catalog's token, 599 frames with no variant pass and the next closes the tunnel. It is still a sign
/// of life (R-29): with no Pong, a live call's chunks 30 s apart keep a tunnel past the 45 s of silence that close it
/// after the last of them.
#[tokio::test(start_paused = true)]
async fn a_live_call_s_chunks_take_no_frames_token() {
    let rig = Rig::start().await;
    let together = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::with(move |inv, out| {
        let together = std::sync::Arc::clone(&together);
        tokio::spawn(async move {
            together.wait().await;
            for seq in 0..256 {
                if out.send(wf(chunk_of(&inv.request_id, seq, 2, seq == 255))).await.is_err() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        });
    }));
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let mut calls = Vec::new();
    for _ in 0..3 {
        let stream = call_with(&mut client, &token, capped_request(0, 256)).await.expect("a call");
        calls.push(tokio::spawn(drain(stream)));
    }
    for c in calls {
        let (chunks, end) = c.await.unwrap();
        assert!(end.is_ok());
        assert!(chunks.len() == 256 && chunks.iter().all(|c| c.error.is_none()) && chunks[255].r#final, "{} chunks", chunks.len());
    }
    assert!(a.closes().is_empty(), "768 chunks of live calls: {:?}", a.closes());
    let lines = rig.lines("call");
    assert!(lines.len() == 3 && lines.iter().all(|l| l["outcome"] == "ok" && l["chunks"] == 256), "{lines:?}");
    for _ in 0..598 {
        a.out.send(WorkerFrame { msg: None }).await.unwrap();
    }
    read_so_far(&rig, &a, 599).await;
    a.out.send(WorkerFrame { msg: None }).await.unwrap();
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"));
    rig.until(Duration::from_secs(5), "its close line", |r| rate_lines(r) == 1).await;

    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script { pong: false, on_invoke: Box::new(|_, _| {}) });
    let mut client = rig.client().await;
    let req = CallRequest { deadline_ms: 120_000, ..capped_request(0, 0) };
    let stream = call_with(&mut client, &rig.token("g-all"), req).await.expect("a call");
    let caller = tokio::spawn(drain(stream));
    let rid = a.invoke(0).await.request_id;
    for seq in 0..3 {
        tokio::time::sleep(Duration::from_secs(30)).await;
        a.send(chunk_of(&rid, seq, 2, false)).await;
    }
    let last_chunk = Instant::now();
    assert!(a.closes().is_empty(), "90 s of a live call's chunks: {:?}", a.closes());
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (5, "no frame for 45 s"));
    assert_eq!(last_chunk.elapsed(), Duration::from_secs(45), "from the last chunk");
    assert_eq!(caller.await.unwrap().0.len(), 4, "its three chunks and the final");
}

/// Relay 40 (f) (paused; LD-R53): a live call's chunk's `encoded_len()` goes back to the bytes bucket. Three answers
/// of 16 MiB within a minute, 48 MiB past the burst of 32 MiB, close nothing. All of it goes back, not just enough:
/// at a budget of 1 MiB, after three answers of 1 MiB, 15 late chunks of 64 KiB still fit, and a few more close it.
#[tokio::test(start_paused = true)]
async fn a_live_call_s_bytes_go_back_to_the_budget() {
    let rig = Rig::start().await;
    assert_eq!((Limits::default().tunnel_bytes_per_min, Limits::default().call_bytes_max, Limits::default().call_chunks_max), (32 << 20, 16 << 20, 256));
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(streaming(256, 65_536, Duration::from_millis(1)));
    let t0 = Instant::now();
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let mut calls = Vec::new();
    for _ in 0..3 {
        let stream = call_with(&mut client, &token, capped_request(16 << 20, 256)).await.expect("a call");
        calls.push(tokio::spawn(drain(stream)));
    }
    for c in calls {
        let (chunks, end) = c.await.unwrap();
        assert!(end.is_ok());
        let bytes: usize = chunks.iter().map(|c| c.data.len()).sum();
        assert_eq!(bytes, 16 << 20, "{} chunks", chunks.len());
        assert!(chunks.iter().all(|c| c.error.is_none()) && chunks.last().unwrap().r#final);
    }
    assert!(t0.elapsed() < Duration::from_secs(1), "well within a minute: {:?}", t0.elapsed());
    assert!(a.closes().is_empty(), "48 MiB of live calls: {:?}", a.closes());
    let lines = rig.lines("call");
    assert!(lines.len() == 3 && lines.iter().all(|l| l["outcome"] == "ok" && l["bytes"] == 16 << 20), "{lines:?}");

    let rig = Rig::start_with(bytes_budget(1 << 20)).await;
    // `list` answers, and the `get` of `cancelled_call` does not.
    let answer = streaming(16, 65_536, Duration::from_millis(1)).on_invoke;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::with(move |inv, out| {
        if inv.op == "list" {
            answer(inv, out);
        }
    }));
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    for _ in 0..3 {
        let (chunks, end) = drain(call_with(&mut client, &token, capped_request(0, 0)).await.expect("a call")).await;
        assert!(end.is_ok() && chunks.len() == 16 && chunks.iter().all(|c| c.error.is_none()), "{} chunks", chunks.len());
    }
    let late = cancelled_call(&rig, &a).await;
    for seq in 0..15 {
        a.send(chunk_of(&late, seq, 65_536, false)).await;
    }
    read_so_far(&rig, &a, 1).await;
    send_until_closed(&a, (15..20).map(|seq| chunk_of(&late, seq, 65_536, false))).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"));
}

/// Relay 40 (g) (paused; LD-R53): a chunk of no live call is charged as R-107 says, `Late` and `Unknown` alike. A
/// cancelled call's late chunks: with the catalog's token 599 frames pass, and the next late chunk closes `inbound
/// rate`. Chunks of ids never carried, besides R-109's bucket: with 584 frames with no variant, 15 of them pass, and
/// the 16th, though R-109's bucket holds a token more, closes `inbound rate`. Their bytes do not come back: at a
/// budget of 1 MiB, late chunks of 64 KiB close it `inbound rate`, and 16 chunks of ids never carried close it
/// `inbound rate` before R-109's 17th.
#[tokio::test(start_paused = true)]
async fn chunks_of_no_live_call_stay_charged() {
    let silent = |rig| async move { TestWorker::connect(rig, "worker-a", 1, catalog_a()).await.serve(Script::silent()) };

    let rig = Rig::start().await;
    let a = silent(&rig).await;
    let late = cancelled_call(&rig, &a).await;
    for seq in 0..598 {
        a.send(chunk_of(&late, seq, 2, false)).await;
    }
    read_so_far(&rig, &a, 1).await;
    a.send(chunk_of(&late, 598, 2, false)).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"), "the 601st frame");
    rig.until(Duration::from_secs(5), "its close line", |r| rate_lines(r) == 1).await;

    let rig = Rig::start().await;
    let a = silent(&rig).await;
    for _ in 0..583 {
        a.out.send(WorkerFrame { msg: None }).await.unwrap();
    }
    for i in 0..15 {
        a.send(stray_chunk(i, 2)).await;
    }
    read_so_far(&rig, &a, 584).await;
    a.send(stray_chunk(15, 2)).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"), "the 601st frame, R-109's bucket not yet empty");

    let rig = Rig::start_with(bytes_budget(1 << 20)).await;
    let a = silent(&rig).await;
    let late = cancelled_call(&rig, &a).await;
    send_until_closed(&a, (0..20).map(|seq| chunk_of(&late, seq, 65_536, false))).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"), "late chunks' bytes do not come back");

    let rig = Rig::start_with(bytes_budget(1 << 20)).await;
    let a = silent(&rig).await;
    send_until_closed(&a, (0..17).map(|i| stray_chunk(i, 65_536))).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"), "unknown chunks' bytes do not come back");
}

/// Relay 40 (h) (paused; LD-R53): a live call's chunk that breaks its caps ends the call as it did (R-39), and
/// takes no token itself: the chunk cap's and the byte cap's truncated finals, and a `seq` out of order's code 13, each
/// with its Cancel, four live chunks in all. From then on the calls' chunks are late, and charged: with the catalog's
/// token 599 of them pass, and the next closes `inbound rate`. At a budget of 1 MiB the byte cap's chunk of 64 KiB
/// goes back, the chunks after it do not, and they close it `inbound rate`.
#[tokio::test(start_paused = true)]
async fn a_chunk_over_its_call_s_caps_ends_the_call_and_its_later_chunks_are_charged() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let token = rig.token("g-all");

    let stream = call_with(&mut client, &token, capped_request(0, 2)).await.unwrap();
    let chunk_capped = a.invoke(0).await.request_id;
    a.send(chunk_of(&chunk_capped, 0, 2, false)).await;
    a.send(chunk_of(&chunk_capped, 1, 2, false)).await;
    let (chunks, end) = drain(stream).await;
    assert!(end.is_ok() && chunks.len() == 2 && chunks[1].r#final && chunks[1].truncated, "{chunks:?}");
    a.until("chunk_cap", |r| r.cancels.iter().any(|c| c.request_id == chunk_capped && c.reason == "chunk_cap")).await;

    let stream = call_with(&mut client, &token, capped_request(100, 0)).await.unwrap();
    let byte_capped = a.invoke(1).await.request_id;
    a.send(chunk_of(&byte_capped, 0, 65_536, false)).await;
    let (chunks, end) = drain(stream).await;
    assert!(end.is_ok() && chunks.len() == 1 && chunks[0].r#final && chunks[0].truncated && chunks[0].data.len() == 100, "{} chunks", chunks.len());
    a.until("byte_cap", |r| r.cancels.iter().any(|c| c.request_id == byte_capped && c.reason == "byte_cap")).await;

    let stream = call_with(&mut client, &token, capped_request(0, 0)).await.unwrap();
    let broken = a.invoke(2).await.request_id;
    a.send(chunk_of(&broken, 5, 2, false)).await;
    let (chunks, end) = drain(stream).await;
    assert!(end.is_ok() && chunks.len() == 1 && final_code(&chunks[0]) == Some(13), "{chunks:?}");
    a.until("protocol", |r| r.cancels.iter().any(|c| c.request_id == broken && c.reason == "protocol")).await;

    let outcomes: Vec<String> = rig.lines("call").iter().map(|l| l["outcome"].as_str().unwrap().to_string()).collect();
    assert_eq!(outcomes, ["truncated", "truncated", "violation"]);
    let ended = [&chunk_capped, &byte_capped, &broken];
    for seq in 0..598 {
        a.send(chunk_of(ended[seq % 3], seq as u64, 2, false)).await;
    }
    read_so_far(&rig, &a, 1).await;
    a.send(chunk_of(&broken, 598, 2, false)).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"), "the 601st frame charged");

    let rig = Rig::start_with(bytes_budget(1 << 20)).await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let stream = call_with(&mut client, &rig.token("g-all"), capped_request(100, 0)).await.unwrap();
    let byte_capped = a.invoke(0).await.request_id;
    a.send(chunk_of(&byte_capped, 0, 65_536, false)).await;
    assert!(drain(stream).await.0[0].truncated);
    send_until_closed(&a, (1..20).map(|seq| chunk_of(&byte_capped, seq, 65_536, false))).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"), "its later chunks' bytes do not come back");
}

/// Relay 40 (i) (paused; LD-R53; M-R170's case): only what a chunk's `encoded_len()` counts goes back. At a budget of
/// 1 MiB, a live call's chunks of two bytes that each carry 64 KiB of fields `WorkerFrame` has not (a decoded length of
/// about 60) close `inbound rate`, its caller getting its final (14). At a budget of 64 KiB, on a bare HTTP/2 tunnel: a
/// live call's chunks, each in a DATA frame with 255 bytes of padding; then PINGs, and frames of a type HTTP/2 does
/// not know, none of which decodes to anything.
#[tokio::test(start_paused = true)]
async fn what_a_decoded_chunk_does_not_count_stays_charged() {
    use ai_env_relay_proto::prost::Message as _;
    let rig = Rig::start_with(bytes_budget(1 << 20)).await;
    let mut w = raw_tunnel(&rig).await;
    let mut client = rig.client().await;
    let stream = call_with(&mut client, &rig.token("g-all"), capped_request(0, 64)).await.expect("a call");
    let rid = loop {
        if let Some(relay_frame::Msg::Invoke(i)) = w.inbound.message().await.unwrap().and_then(|f| f.msg) {
            break i.request_id;
        }
    };
    let caller = tokio::spawn(drain(stream));
    let out = w.out.clone();
    let sender = tokio::spawn(async move {
        for seq in 0..32 {
            let mut frame = wf(chunk_of(&rid, seq, 2, false)).encode_to_vec();
            frame.extend(raw::padded(65_536));
            if out.send(frame).await.is_err() {
                return;
            }
        }
    });
    let close = w.close().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"));
    let (chunks, end) = caller.await.unwrap();
    assert!(end.is_ok());
    let last = chunks.last().expect("a final chunk");
    assert!(last.r#final && final_code(last) == Some(14) && (10..=17).contains(&chunks.len()), "{} chunks, the last {last:?}", chunks.len());
    rig.until(Duration::from_secs(5), "its close line", |r| rate_lines(r) == 1).await;
    sender.abort();

    // HTTP/2's padding: at most 255 bytes a DATA frame (and h2 ends a connection for its empty DATA frames), so about
    // 240 chunks, which the call's chunk cap allows. Each is read before the next is sent: its length goes back first.
    const PADDED: u8 = 0x8;
    let budget = 65_536usize;
    let rig = Rig::start_with(bytes_budget(budget as u64)).await;
    let (mut c, mut pending, mut acks) = bare_tunnel(&rig, 1 << 22).await;
    let mut client = rig.client().await;
    let stream = call_with(&mut client, &rig.token("g-all"), capped_request(0, 256)).await.expect("a call");
    let rid = loop {
        let frame = grpc_message::<ai_env_relay_proto::v1::RelayFrame>(&mut c, &mut pending, &mut acks).await.expect("its Invoke");
        if let Some(relay_frame::Msg::Invoke(i)) = frame.msg {
            break i.request_id;
        }
    };
    let caller = tokio::spawn(drain(stream));
    for seq in 0..255 {
        let frame = [&[255u8][..], &bare_message(Some(chunk_of(&rid, seq, 2, false))), &[0u8; 255][..]].concat();
        c.send(h2raw::DATA, PADDED, 1, &frame).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let close = bare_close(&mut c, &mut pending, &mut acks).await;
    assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"), "the padding of a live call's chunks");
    let (chunks, end) = caller.await.unwrap();
    assert!(end.is_ok());
    let last = chunks.last().expect("a final chunk");
    // 270 bytes of each frame stay charged (the padding, its length, the gRPC prefix and the frame's head): about 243
    // of them, where a chunk's length not given back would make it about 192.
    assert!(last.r#final && final_code(last) == Some(14) && (230..=250).contains(&chunks.len()), "{} chunks, the last {last:?}", chunks.len());

    for (what, kind, payload) in [("PINGs", h2raw::PING, vec![0u8; 8]), ("frames of an unknown type", 0xfa, vec![0u8; 16_384])] {
        let rig = Rig::start_with(bytes_budget(budget as u64)).await;
        let (mut c, mut pending, mut acks) = bare_tunnel(&rig, 1 << 22).await;
        for _ in 0..(budget + budget / 8) / (9 + payload.len()) + 1 {
            c.send(kind, 0, 0, &payload).await;
        }
        let close = bare_close(&mut c, &mut pending, &mut acks).await;
        assert_eq!((close.code, close.reason.as_str()), (3, "inbound rate"), "{what}");
        assert_eq!(rig.app.snapshot().unknown_frames, 0, "{what}: no frame decoded");
    }
}

/// One frame of a bare tunnel, as a gRPC message.
fn bare_message(msg: Option<worker_frame::Msg>) -> Vec<u8> {
    use ai_env_relay_proto::prost::Message as _;
    let m = WorkerFrame { msg }.encode_to_vec();
    h2raw::grpc(m.len() as u32, &m)
}

/// A tunnel on a bare HTTP/2 connection, a pipe of `pipe` bytes each way (relay 40's (d) and (i)): worker-a
/// authenticated, its catalog sent, its AuthOk read. Returns what `grpc_message` keeps.
async fn bare_tunnel(rig: &Rig, pipe: usize) -> (h2raw::Conn, Vec<u8>, usize) {
    use ai_env_relay_proto::v1::RelayFrame;
    let mut c = h2raw::Conn::open(rig.public_raw(pipe), Instant::now()).await;
    let headers = h2raw::block(&[
        (":method", b"POST"),
        (":scheme", b"http"),
        (":path", b"/ai_env.relay.v1.WorkerTunnel/Open"),
        (":authority", b"ai-env-relay"),
        ("content-type", b"application/grpc"),
        ("te", b"trailers"),
    ]);
    c.send(h2raw::HEADERS, h2raw::END_HEADERS, 1, &headers).await;
    let (mut pending, mut acks) = (Vec::new(), 0);
    let challenge = match grpc_message::<RelayFrame>(&mut c, &mut pending, &mut acks).await.and_then(|f| f.msg) {
        Some(relay_frame::Msg::Challenge(ch)) => ch,
        other => panic!("the Challenge first, not {other:?}"),
    };
    let h = hello("worker-a", 1);
    let p = proof(&challenge, &h, 1);
    let mut auth = bare_message(Some(worker_frame::Msg::Hello(h)));
    auth.extend(bare_message(Some(worker_frame::Msg::AuthProof(p))));
    auth.extend(bare_message(Some(worker_frame::Msg::Catalog(Catalog { sources: catalog_a() }))));
    c.send(h2raw::DATA, 0, 1, &auth).await;
    let ok = grpc_message::<RelayFrame>(&mut c, &mut pending, &mut acks).await.and_then(|f| f.msg);
    assert!(matches!(ok, Some(relay_frame::Msg::AuthOk(_))), "{ok:?}");
    (c, pending, acks)
}

/// The Close a bare tunnel gets, the frames before it skipped.
async fn bare_close(c: &mut h2raw::Conn, pending: &mut Vec<u8>, acks: &mut usize) -> ai_env_relay_proto::v1::Close {
    use ai_env_relay_proto::v1::RelayFrame;
    loop {
        match grpc_message::<RelayFrame>(c, pending, acks).await.map(|f| f.msg) {
            Some(Some(relay_frame::Msg::Close(close))) => return close,
            Some(_) => {}
            None => panic!("a Close before the connection's end"),
        }
    }
}

/// A tunnel whose frames are sent as bytes, so one can carry a field `WorkerFrame` has not (relay 40's (c) and (i)):
/// worker-a authenticated, its catalog sent, its AuthOk read.
async fn raw_tunnel(rig: &Rig) -> raw::Tunnel {
    use ai_env_relay_proto::prost::Message as _;
    let (channel, link) = rig.public_channel().await;
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    let (out, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
    let path = tonic::codegen::http::uri::PathAndQuery::from_static("/ai_env.relay.v1.WorkerTunnel/Open");
    let request = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx));
    let mut inbound = grpc.streaming(request, path, raw::Codec).await.expect("the Open").into_inner();
    let challenge = match inbound.message().await.unwrap().and_then(|f| f.msg) {
        Some(relay_frame::Msg::Challenge(c)) => c,
        other => panic!("the Challenge first, not {other:?}"),
    };
    let h = hello("worker-a", 1);
    let p = proof(&challenge, &h, 1);
    for msg in [worker_frame::Msg::Hello(h), worker_frame::Msg::AuthProof(p), worker_frame::Msg::Catalog(Catalog { sources: catalog_a() })] {
        out.send(wf(msg).encode_to_vec()).await.unwrap();
    }
    assert!(matches!(inbound.message().await.unwrap().and_then(|f| f.msg), Some(relay_frame::Msg::AuthOk(_))));
    raw::Tunnel { out, inbound, _grpc: grpc, _link: link }
}

/// A bare HTTP/2 client's read of the relay's next gRPC message on stream 1 (relays 40 (d) and (i), and 44), decoded
/// from its DATA frames (`pending` holds the bytes of one not whole yet), each PING ACK on the way counted in `acks`;
/// None once the relay ends the connection.
async fn grpc_message<M: ai_env_relay_proto::prost::Message + Default>(c: &mut h2raw::Conn, pending: &mut Vec<u8>, acks: &mut usize) -> Option<M> {
    loop {
        if pending.len() >= 5 {
            let len = u32::from_be_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
            if pending.len() >= 5 + len {
                let message = M::decode(&pending[5..5 + len]).expect("a message of its type");
                pending.drain(..5 + len);
                return Some(message);
            }
        }
        let f = tokio::time::timeout(PATIENCE, c.next()).await.expect("a frame in time")?;
        match f.kind {
            h2raw::DATA if f.stream == 1 => pending.extend_from_slice(&f.payload),
            h2raw::PING if f.flags & h2raw::ACK != 0 => *acks += 1,
            _ => {}
        }
    }
}

/// Relay 40 (c)'s and (i)'s worker stream: frames sent as bytes, so one can carry a field no variant of `WorkerFrame`
/// knows.
mod raw {
    use ai_env_relay_proto::prost::bytes::BufMut as _;
    use ai_env_relay_proto::tonic_prost::ProstCodec;
    use ai_env_relay_proto::v1::{relay_frame, Close, RelayFrame};
    use tonic::codec::{EncodeBuf, Encoder};

    /// `raw_tunnel`'s tunnel.
    pub struct Tunnel {
        pub out: tokio::sync::mpsc::Sender<Vec<u8>>,
        pub inbound: tonic::Streaming<RelayFrame>,
        pub _grpc: tonic::client::Grpc<tonic::transport::Channel>,
        pub _link: super::Link,
    }

    impl Tunnel {
        /// The Close it gets, the frames before it skipped.
        pub async fn close(&mut self) -> Close {
            loop {
                match self.inbound.message().await {
                    Ok(Some(f)) => {
                        if let Some(relay_frame::Msg::Close(c)) = f.msg {
                            return c;
                        }
                    }
                    other => panic!("a Close before the end: {other:?}"),
                }
            }
        }
    }

    /// Encodes each frame's bytes as they are; decodes `RelayFrame`s.
    pub struct Codec;

    impl tonic::codec::Codec for Codec {
        type Encode = Vec<u8>;
        type Decode = RelayFrame;
        type Encoder = AsIs;
        type Decoder = <ProstCodec<RelayFrame, RelayFrame> as tonic::codec::Codec>::Decoder;

        fn encoder(&mut self) -> AsIs {
            AsIs
        }

        fn decoder(&mut self) -> Self::Decoder {
            tonic::codec::Codec::decoder(&mut ProstCodec::<RelayFrame, RelayFrame>::default())
        }
    }

    pub struct AsIs;

    impl Encoder for AsIs {
        type Item = Vec<u8>;
        type Error = tonic::Status;

        fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), tonic::Status> {
            dst.put_slice(&item);
            Ok(())
        }
    }

    /// A frame of `n` bytes in field 99 (length-delimited), which no variant of `WorkerFrame` has: it decodes as a
    /// frame with no variant, whose decoded length is 0.
    pub fn padded(n: usize) -> Vec<u8> {
        // (99 << 3) | 2 = 794, a two-byte varint.
        let mut b = vec![0x9a, 0x06];
        let mut len = n;
        while len >= 0x80 {
            b.push((len & 0x7f) as u8 | 0x80);
            len >>= 7;
        }
        b.push(len as u8);
        b.resize(b.len() + n, b'p');
        b
    }
}

/// Relay 41 (paused): a `Pong` must answer one of the relay's last eight unanswered Pings (R-108). A Pong of the
/// outstanding seq keeps the tunnel, a late one of the older of two outstanding too; a Pong with no Ping outstanding,
/// one of a seq never sent, and one answering a Ping twice close `Close{3, "unexpected pong"}`, reason `protocol`. With
/// frames of no variant as signs of life, a Pong of the oldest of eight unanswered Pings keeps its tunnel; of nine
/// unanswered, a Pong of seq 1 finds it forgotten and closes `unexpected pong`.
#[tokio::test(start_paused = true)]
async fn a_pong_must_answer_a_ping() {
    let rig = Rig::start().await;
    let quiet = || Script { pong: false, on_invoke: Box::new(|_, _| {}) };
    let pong = |seq: u64| worker_frame::Msg::Pong(ai_env_relay_proto::v1::Pong { seq });
    let protocol_lines = |rig: &Rig| rig.lines("tunnel").into_iter().filter(|l| l["phase"] == "close" && l["reason"] == "protocol").count();

    // Answered, the newest and then a late one of the older.
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(quiet());
    a.until("two pings", |r| r.pings.len() == 2).await;
    a.send(pong(2)).await;
    a.send(pong(1)).await;
    a.until("a third ping", |r| r.pings.len() == 3).await;
    a.send(pong(3)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(a.closes().is_empty(), "every Pong answered a Ping");

    // No Ping outstanding: the first frame after the catalog.
    let b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(quiet());
    b.send(pong(1)).await;
    let close = b.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "unexpected pong"));

    // A seq never sent.
    let c = TestWorker::connect(&rig, "worker-c", 5, catalog_c()).await.serve(quiet());
    c.until("a ping", |r| !r.pings.is_empty()).await;
    c.send(pong(99)).await;
    let close = c.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "unexpected pong"));

    // A Ping answered twice.
    a.send(pong(3)).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "unexpected pong"));
    rig.until(Duration::from_secs(5), "three close lines", |r| protocol_lines(r) == 3).await;
    rig.tunnels(0).await;

    // Quiet tunnels, each kept off its silence timer (45 s) by a frame of no variant at each Ping, every 15 s: one wait a
    // Ping, since nine Pings take 135 s and one wait gives up at PATIENCE.
    let unanswered = |w: Served, n: usize| async move {
        for k in 1..=n {
            w.until(&format!("ping {k}"), |r| r.pings.len() == k).await;
            w.out.send(WorkerFrame { msg: None }).await.unwrap();
        }
        w
    };
    let eight = unanswered(TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(quiet()), 8).await;
    eight.send(pong(1)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(eight.closes().is_empty(), "the oldest of eight is remembered: {:?}", eight.closes());
    let nine = unanswered(TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(quiet()), 9).await;
    nine.send(pong(1)).await;
    let close = nine.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "unexpected pong"), "the ninth forgot the oldest");
}

/// Relay 42 (paused): chunks of no call have a budget (R-109). 40 late chunks of a cancelled call (one of the table's
/// recent calls) never count against it (R-107's frames and bytes charge them, relay 40 (g)); 16 chunks of ids never
/// carried are dropped, the tunnel serving on; the 17th closes it `Close{3, "chunks of no call"}`, reason `protocol`.
/// Every one of them is counted, the 17th before its token is asked (`dropped_chunks`). On a new tunnel, the bucket's
/// refill: after the 16, exactly one token's wait (3.75 s at 16 a minute) buys one more, and the next closes.
#[tokio::test(start_paused = true)]
async fn chunks_of_no_call_are_budgeted() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let token = rig.token("g-all");
    let gone = call(&mut client, &token, "example.alpha", "get", b"{}").await.unwrap();
    let rid = a.invoke(0).await.request_id;
    drop(gone);
    a.until("the Cancel", |r| r.cancels.iter().any(|c| c.reason == "caller_gone")).await;
    for seq in 0..40 {
        a.send(worker_frame::Msg::Chunk(data(&rid, seq, b"{}".to_vec(), false))).await;
    }
    for i in 0..16 {
        a.send(worker_frame::Msg::Chunk(data(&format!("0199a1b2-0000-7000-8000-{:012x}", 0x900 + i), 0, b"{}".to_vec(), true))).await;
    }
    // A call still answered: the frames before it were taken, and the tunnel serves on.
    let stream = call(&mut client, &token, "example.alpha", "get", b"{}").await.unwrap();
    let rid2 = a.invoke(1).await.request_id;
    a.send(worker_frame::Msg::Chunk(data(&rid2, 0, b"{\"ok\":1}".to_vec(), true))).await;
    let (chunks, _) = drain(stream).await;
    assert!(chunks.len() == 1 && final_code(&chunks[0]).is_none(), "{chunks:?}");
    assert!(a.closes().is_empty());
    assert_eq!(rig.app.dropped_chunks(), 56, "40 late and 16 unknown, dropped and counted");
    a.send(worker_frame::Msg::Chunk(data("0199a1b2-0000-7000-8000-000000000999", 0, b"{}".to_vec(), true))).await;
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "chunks of no call"));
    assert_eq!(rig.app.dropped_chunks(), 57, "the 17th is counted too");
    rig.until(Duration::from_secs(5), "its close line", |r| r.lines("tunnel").iter().any(|l| l["phase"] == "close" && l["reason"] == "protocol")).await;

    // The refill: 16 a minute, a token every 3.75 s exactly.
    rig.tunnels(0).await;
    let b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(Script::silent());
    for i in 0..16 {
        b.send(stray_chunk(i, 2)).await;
    }
    read_so_far(&rig, &b, 1).await;
    assert_eq!(rig.app.dropped_chunks(), 57 + 16);
    tokio::time::sleep(Duration::from_millis(3750)).await;
    b.send(stray_chunk(16, 2)).await;
    read_so_far(&rig, &b, 2).await;
    assert_eq!(rig.app.dropped_chunks(), 57 + 17, "one token's wait bought one more, and the tunnel serves on");
    b.send(stray_chunk(17, 2)).await;
    let close = b.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "chunks of no call"), "and only one");
}

/// Relay 43 (paused): a catalog identical to the installed one touches no lock (R-110: no validation, no registry
/// install), and catalogs have a budget: three identical catalogs make one install; a fourth within the minute
/// closes `Close{3, "catalog rate"}`, reason `rate`. On a new tunnel, the bucket's refill: after the burst of three,
/// exactly one token's wait (10 s at 6 a minute) buys one more, which installs, and the next closes.
#[tokio::test(start_paused = true)]
async fn identical_catalogs_touch_no_lock_and_catalogs_are_budgeted() {
    let rig = Rig::start().await;
    let mut a = TestWorker::open(&rig).await;
    a.authenticate("worker-a", 1).await.expect("authenticated");
    for _ in 0..3 {
        a.register(catalog_a()).await;
    }
    a.register(vec![source("example.alpha", &["get"])]).await;
    let close = a.close().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "catalog rate"));
    assert_eq!(rig.app.catalog_installs(), 1, "the identical two installed nothing; the fourth met the bucket first");
    rig.until(Duration::from_secs(5), "its close line", |r| r.lines("tunnel").iter().any(|l| l["phase"] == "close" && l["reason"] == "rate")).await;

    // The refill: 6 a minute, a token every 10 s exactly.
    let narrower = || vec![source("example.beta", &["get"])];
    let mut b = TestWorker::open_as(&rig, 2).await;
    b.authenticate("worker-b", 2).await.expect("authenticated");
    for _ in 0..3 {
        b.register(catalog_b()).await;
    }
    settle("the first of its catalogs", || rig.app.catalog_installs() == 2).await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    b.register(narrower()).await;
    settle("one token's wait bought one more", || rig.app.catalog_installs() == 3).await;
    b.register(catalog_b()).await;
    let close = b.close().await;
    assert_eq!((close.code, close.reason.as_str()), (3, "catalog rate"), "and only one");
    assert_eq!(rig.app.catalog_installs(), 3, "the fifth met the bucket first");
}

/// A script answering by its params' `mode` (relay 44): `paced` sends `n` chunks of 1 KiB 300 ms apart (the first at
/// once; the last final when `last`); `burst12` twelve chunks of 1 KiB in one write, the last final; `burst6` six
/// chunks of 64 KiB in one write, none final (`burst6final`: the sixth final).
fn by_mode() -> Script {
    Script::with(|inv, out| {
        let params: serde_json::Value = serde_json::from_slice(&inv.params_json).unwrap_or_default();
        let rid = inv.request_id.clone();
        let chunk = move |seq: u64, last: bool| wf(worker_frame::Msg::Chunk(data(&rid, seq, vec![b'x'; 1024], last)));
        match params["mode"].as_str().unwrap_or_default() {
            "burst12" => (0..12).for_each(|seq| drop(out.try_send(chunk(seq, seq == 11)))),
            mode @ ("burst6" | "burst6final") => {
                let (rid, last) = (inv.request_id.clone(), mode == "burst6final");
                (0..6).for_each(|seq| drop(out.try_send(wf(worker_frame::Msg::Chunk(data(&rid, seq, vec![b'x'; 65_536], last && seq == 5))))));
            }
            "paced" => {
                let (n, last) = (params["n"].as_u64().unwrap_or(1), params["last"].as_bool().unwrap_or(false));
                tokio::spawn(async move {
                    for seq in 0..n {
                        if seq > 0 {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                        }
                        if out.send(chunk(seq, last && seq + 1 == n)).await.is_err() {
                            return;
                        }
                    }
                });
            }
            _ => {}
        }
    })
}

/// Relay 44 (paused): a caller that stops reading never stalls its tunnel (R-111), and its evictions are charged
/// only when it left a chunk unread a second (R-112). Two sessions on one tunnel: the slow one never reads (a stream
/// window of 0) and calls again after each eviction, its worker sending each call's chunks 300 ms apart; the other's
/// 16 chunks, 300 ms apart too, complete within its 6 s deadline. The slow stream takes its first chunk (hyper's one
/// frame, `deaf_client`); the next four fill its buffer, and each slow call is evicted as the chunk after them finds
/// the buffer full after one yield, 1.5 s after the call, with no wait (`Cancel{"caller_too_slow"}`), its oldest
/// buffered chunk 1.2 s old, so charged; after the third eviction the slow session's fourth call is refused 8 `rate
/// limited`. A worker's burst of 12 chunks in one write, to a caller that reads, completes with no eviction (the
/// yield); bursts of 6 chunks to a caller that never reads (the first taken, four buffered, the sixth evicting) evict
/// without a charge (their oldest buffered chunk 0 s old), so a fourth such call is admitted.
#[tokio::test(start_paused = true)]
async fn a_caller_that_stops_reading_never_stalls_its_tunnel() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(by_mode());
    let evicted = |r: &Recorded, rid: &str| r.cancels.iter().any(|c| c.request_id == rid && c.reason == "caller_too_slow");

    let mut reader = rig.client().await;
    let reader_token = rig.token("g-all");
    let t0 = Instant::now();
    let other = tokio::spawn(async move {
        let req = CallRequest { deadline_ms: 6000, ..request("example.alpha", "get", br#"{"mode":"paced","n":16,"last":true}"#) };
        drain(call_with(&mut reader, &reader_token, req).await.expect("the other call")).await
    });
    let (mut deaf, _deaf_link) = deaf_client(&rig).await;
    let slow = rig.token("g-all");
    let mut held = Vec::new();
    for i in 0..3 {
        let started = Instant::now();
        let resp = call_response(&mut deaf, &slow, request("example.alpha", "get", br#"{"mode":"paced","n":8,"last":false}"#)).await.expect("a slow call");
        let rid = request_id(resp.metadata());
        a.until("its eviction", |r| evicted(r, &rid)).await;
        assert_eq!(started.elapsed(), Duration::from_millis(1500), "slow call {i}: evicted as its sixth chunk came, with no wait");
        held.push(resp);
    }
    let refused = call(&mut deaf, &slow, "example.alpha", "get", br#"{"mode":"paced","n":8}"#).await.expect_err("three charged evictions");
    assert_eq!((refused.code(), refused.message()), (Code::ResourceExhausted, "rate limited"));
    let (chunks, end) = other.await.unwrap();
    assert!(end.is_ok());
    assert!(chunks.len() == 16 && chunks.iter().all(|c| c.error.is_none()) && chunks[15].r#final, "{} chunks", chunks.len());
    assert_eq!(t0.elapsed(), Duration::from_millis(4500), "the other call's chunks came as they were sent");
    let lines = rig.lines("call");
    assert_eq!(lines.iter().filter(|l| l["outcome"] == "evicted").count(), 3);
    assert_eq!(lines.iter().filter(|l| l["outcome"] == "rate_limited").count(), 1);

    // A burst to a caller that reads: the yield lets it drain, so nothing is evicted.
    let mut reader = rig.client().await;
    let (chunks, end) = drain(call(&mut reader, &rig.token("g-all"), "example.alpha", "get", br#"{"mode":"burst12"}"#).await.unwrap()).await;
    assert!(end.is_ok());
    assert!(chunks.len() == 12 && chunks.iter().all(|c| c.error.is_none()) && chunks[11].r#final, "{chunks:?}");

    // Bursts to a caller that never reads: evicted, and never charged.
    let (mut deaf, _deaf_link) = deaf_client(&rig).await;
    let bursty = rig.token("g-all");
    for _ in 0..3 {
        let resp = call_response(&mut deaf, &bursty, request("example.alpha", "get", br#"{"mode":"burst6"}"#)).await.expect("a burst call");
        let rid = request_id(resp.metadata());
        a.until("its eviction", |r| evicted(r, &rid)).await;
        held.push(resp);
    }
    let fourth = call(&mut deaf, &bursty, "example.alpha", "get", br#"{"mode":"burst6"}"#).await;
    assert!(fourth.is_ok(), "uncharged evictions: a fourth call is admitted: {:?}", fourth.err());
    assert!(a.closes().is_empty(), "the tunnel never stalled nor closed");

    // A last chunk that finds the buffer full is kept, and evicts nothing (R-42, R-111): a bare client whose streams
    // have no window, then a burst of six chunks of 64 KiB, the sixth final (hyper takes the first, four fill the
    // buffer); once the client grants a window it reads all six, the sixth its worker's own final.
    use ai_env_relay_proto::prost::Message as _;
    let mut c = h2raw::Conn::open(rig.private_raw(1 << 20), Instant::now()).await;
    c.send(h2raw::SETTINGS, 0, 0, &[0x00, 0x04, 0, 0, 0, 0]).await;
    let token = rig.token("g-all");
    let headers = h2raw::block(&[
        (":method", b"POST"),
        (":scheme", b"http"),
        (":path", b"/ai_env.relay.v1.Relay/Call"),
        (":authority", b"10.42.0.20"),
        ("content-type", b"application/grpc"),
        ("te", b"trailers"),
        ("x-ai-env-session", token.as_bytes()),
    ]);
    c.send(h2raw::HEADERS, h2raw::END_HEADERS, 1, &headers).await;
    let params = br#"{"mode":"burst6final"}"#;
    let req = request("example.alpha", "get", params).encode_to_vec();
    c.send(h2raw::DATA, h2raw::END_STREAM, 1, &h2raw::grpc(req.len() as u32, &req)).await;
    a.until("its invoke", |r| r.invokes.iter().any(|i| i.params_json == params)).await;
    let rid = a.invokes().into_iter().find(|i| i.params_json == params).expect("its invoke").request_id;
    rig.until(Duration::from_secs(5), "its call line", |r| r.lines("call").iter().any(|l| l["request_id"] == rid.as_str())).await;
    let line = rig.lines("call").into_iter().find(|l| l["request_id"] == rid.as_str()).expect("its call line");
    assert_eq!(line["outcome"], "ok", "the full buffer's last chunk ended the call, and evicted nothing");
    assert!(!a.cancels().iter().any(|c| c.request_id == rid), "no Cancel for it");
    for stream in [1u32, 0] {
        c.send(h2raw::WINDOW_UPDATE, 0, stream, &(1u32 << 20).to_be_bytes()).await;
    }
    let (mut pending, mut acks) = (Vec::new(), 0);
    let mut chunks = Vec::new();
    while chunks.len() < 6 {
        chunks.push(grpc_message::<CallChunk>(&mut c, &mut pending, &mut acks).await.expect("the call's chunks"));
    }
    assert_eq!(chunks.iter().map(|c| c.seq).collect::<Vec<u64>>(), (0..6).collect::<Vec<u64>>());
    let last = &chunks[5];
    assert!(last.r#final && last.error.is_none() && last.data.len() == 65_536, "the worker's own final: {:?}", (last.r#final, &last.error, last.data.len()));
    assert!(chunks[..5].iter().all(|c| !c.r#final && c.error.is_none()));
}

/// One public connection through `admit` from the rig's worker address, whose ban is the subject: refused before any TLS
/// byte, with a peer line `banned`.
async fn banned_at_admit(rig: &Rig) {
    let (_client, server) = tokio::io::duplex(1 << 16);
    assert!(rig.app.admit(ai_env_relay::Face::Public, server, WORKER_IP.parse().unwrap()).await.is_none(), "refused");
    let line = rig.lines("peer").pop().expect("a peer line");
    assert_eq!((line["reason"].as_str(), line["peer"].as_str()), (Some("banned"), Some(WORKER_IP)), "{line}");
}

/// Relay 45 (R-125 to R-128): a certificate serves its own worker only. A's fingerprint with B's key, B's proof sound:
/// 16 `authentication failed` with no frame after the Challenge, its tunnel line `cert_mismatch` (R-127's fault, after
/// the signature). A's fingerprint with A's key, and B's with B's, each authenticate. `public_channel_bare()`: 16 with no
/// Challenge, `no_cert` (R-126). A list entry without `tls_fp` is refused both ways: `unknown_cert` at `open()` for a
/// certificate nobody holds, `cert_mismatch` for a proof of that entry on another's certificate. Each of the three words
/// is one fault of its address (R-102): with `ban_faults` 1 the address's next connection is `banned`.
#[tokio::test]
async fn a_certificate_serves_its_own_worker_only() {
    let one_fault = || Limits { ban_faults: 1, ..limits() };
    let rig = Rig::start_with(one_fault()).await;
    let mut w = TestWorker::open(&rig).await;
    let h = hello("worker-b", 2);
    let p = proof(&w.challenge, &h, 2);
    w.send(worker_frame::Msg::Hello(h)).await;
    w.send(worker_frame::Msg::AuthProof(p)).await;
    let (after, end) = w.rest().await;
    assert!(after.is_empty(), "no frame after the Challenge: {after:?}");
    let status = end.expect_err("A's certificate never serves B's key");
    assert_eq!((status.code(), status.message()), (Code::Unauthenticated, "authentication failed"));
    let line = rig.lines("tunnel").pop().unwrap();
    assert_eq!((line["phase"].as_str(), line["outcome"].as_str(), line["reason"].as_str()), (Some("auth"), Some("refused"), Some("cert_mismatch")), "{line}");
    assert_eq!((line["worker"].as_str(), line["peer"].as_str()), (Some("worker-b"), Some(WORKER_IP)), "{line}");
    assert_eq!(rig.app.snapshot().tunnels, 0);
    banned_at_admit(&rig).await;

    // Each certificate with its own worker.
    let rig = Rig::start().await;
    let _a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let _b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(Script::silent());
    rig.tunnels(2).await;

    let rig = Rig::start_with(one_fault()).await;
    assert_eq!(refused_reason(&rig, 9).await, "unknown_cert", "a certificate no entry holds");
    banned_at_admit(&rig).await;

    let rig = Rig::start_with(one_fault()).await;
    let (channel, _link) = rig.public_channel_bare().await;
    let status = TestWorker::open_on(channel).await.err().expect("no certificate, no Challenge");
    assert_eq!((status.code(), status.message()), (Code::Unauthenticated, "authentication failed"));
    let line = rig.lines("tunnel").pop().unwrap();
    assert_eq!((line["phase"].as_str(), line["outcome"].as_str(), line["reason"].as_str()), (Some("auth"), Some("refused"), Some("no_cert")), "{line}");
    assert_eq!((line["worker"].as_str(), line["sdk"].as_str()), (Some(""), Some("")), "{line}");
    assert_eq!(rig.lines("tunnel").len(), 1, "one line");
    banned_at_admit(&rig).await;

    // No client certificate on an entry: its worker cannot connect, whichever certificate it presents.
    let rig = Rig::start().await;
    let mut workers = default_workers();
    workers[0].tls_fp = None;
    rig.write_workers(&workers);
    rig.poll();
    assert_eq!(refused_reason(&rig, 1).await, "unknown_cert", "A's certificate is nobody's now");
    let mut w = TestWorker::open_as(&rig, 2).await;
    let h = hello("worker-a", 1);
    let p = proof(&w.challenge, &h, 1);
    w.send(worker_frame::Msg::Hello(h)).await;
    w.send(worker_frame::Msg::AuthProof(p)).await;
    assert_eq!(w.end().await.expect_err("an entry without tls_fp").code(), Code::Unauthenticated);
    assert_eq!(rig.lines("tunnel").pop().unwrap()["reason"], "cert_mismatch");
}

/// Relay 49 (R-49): an answer over `list_max_bytes` is refused 8 `catalog too large`, with its list line, and the bound
/// is the encoded answer's after the grant's filter: a grant narrowed to one op is served the same source.
#[tokio::test]
async fn a_list_over_its_cap_is_refused() {
    assert_eq!(Limits::default().list_max_bytes, 507_904, "LD-R50's share of a stream, 496 KiB");
    let rig = Rig::start_with(Limits { list_max_bytes: 65_536, ..limits() }).await;
    let ops: Vec<String> = (0..48).map(|i| if i == 0 { "get".to_string() } else { format!("op-{i}") }).collect();
    let mut large = source("example.alpha", &ops.iter().map(String::as_str).collect::<Vec<_>>());
    large.ops.iter_mut().for_each(|op| op.description = "d".repeat(2048));
    let _a = TestWorker::connect(&rig, "worker-a", 1, vec![large]).await.serve(Script::silent());
    let mut client = rig.client().await;
    let s = list(&mut client, &rig.token("g-all")).await.expect_err("over the cap");
    assert_eq!((s.code(), s.message()), (Code::ResourceExhausted, "catalog too large"));
    let line = rig.lines("list").pop().unwrap();
    assert_eq!((line["outcome"].as_str(), line["code"].as_i64()), (Some("too_large"), Some(8)));
    let listed = list(&mut client, &rig.token("g-alpha-get")).await.expect("its one op fits");
    assert_eq!(names(&listed), vec![("example.alpha".to_string(), true)]);
}

/// Relay 50 (paused; R-103's last bullet): the relay's stop cuts a private connection a second later with no line. A
/// client that never reads holds a silent call at the stop: its connection closes one second after the stop (an idle
/// one would close at once, on tonic's GOAWAY; the undrained cut would come at 10 s), and no peer line is written.
#[tokio::test(start_paused = true)]
async fn the_stop_cuts_a_private_connection_a_second_later_with_no_line() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::silent());
    let (mut deaf, link) = deaf_client(&rig).await;
    let held = call(&mut deaf, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect("a silent call");
    a.invoke(0).await;
    let stop = Instant::now();
    rig.app.shutdown();
    rig.until(Duration::from_secs(20), "the cut", |_| link.peer_closed_at().is_some()).await;
    assert_eq!(link.peer_closed_at(), Some(stop + Duration::from_secs(1)), "a second after the stop");
    assert!(rig.lines("peer").is_empty(), "{:?}", rig.lines("peer"));
    drop(held);
}

/// Relay 51 (paused; R-103's last bullet): a stop already seen beats a cut due at the same instant. 32 private
/// connections with no request, their token deadline due at 5 s, and the stop at exactly 5 s, before any of their
/// watches ran (`advance` fires their timers and returns here first: a current-thread runtime polls its `block_on`
/// future before the tasks those timers woke). Every watch then sees both, and no `auth_timeout` is written. An
/// unbiased select would pick the due cut for about a quarter of them.
#[tokio::test(start_paused = true)]
async fn a_stop_beats_a_cut_due_at_the_same_instant() {
    let rig = Rig::start().await;
    let t0 = Instant::now();
    let mut idle = Vec::new();
    for _ in 0..32 {
        idle.push(rig.private_channel().await);
    }
    tokio::time::sleep_until(t0 + Duration::from_millis(4999)).await;
    assert!(rig.lines("peer").is_empty());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(t0.elapsed(), Duration::from_secs(5));
    assert!(rig.lines("peer").is_empty(), "no watch ran before the stop");
    rig.app.shutdown();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(rig.lines("peer").is_empty(), "{:?}", rig.lines("peer"));
    drop(idle);
}

/// The relay with the access tests' limits (a session's rate never in the way) and everything it logs through relay.log's
/// own subscriber, at every level of the relay's targets, for the rest of the test's thread.
async fn access_rig() -> (Rig, Written, tracing::subscriber::DefaultGuard) {
    let written = Written::default();
    let w = written.clone();
    let guard = tracing::subscriber::set_default(ai_env_relay::reqlog::log_subscriber(Some("trace"), 60_000, move || w.clone()));
    hear_the_relay();
    let rig = Rig::start_with(Limits { session_burst: 10_000, session_per_min: 60_000, ..limits() }).await;
    (rig, written, guard)
}

/// Every log callsite hit so far speaks to this thread's subscriber. Tests run side by side, and with one subscriber
/// registered `tracing` caches a callsite off when its first hit comes on a thread with none: a line of that callsite
/// would then not be seen here until the cache is rebuilt, its absence proving nothing.
fn hear_the_relay() {
    tracing::callsite::rebuild_interest_cache();
}

/// A source's name and its ops, as `ListSources` shows them.
fn listed_ops(r: &ai_env_relay_proto::v1::ListSourcesResponse) -> Vec<(String, Vec<String>)> {
    r.sources.iter().map(|s| s.descriptor.as_ref().unwrap()).map(|d| (d.name.clone(), d.ops.iter().map(|o| o.name.clone()).collect())).collect()
}

/// One row of `listed_ops`.
fn ops_row(name: &str, ops: &[&str]) -> (String, Vec<String>) {
    (name.to_string(), ops.iter().map(|o| o.to_string()).collect())
}

/// A refused call's (code, message).
fn refusal(r: Result<tonic::Streaming<CallChunk>, tonic::Status>) -> (Code, String) {
    let s = r.expect_err("refused");
    (s.code(), s.message().to_string())
}

/// The call answered: its chunks' one final and no error. `Script::echo`'s answer, or a held call's.
async fn answered(r: Result<tonic::Streaming<CallChunk>, tonic::Status>) {
    let (chunks, end) = drain(r.expect("granted")).await;
    assert!(end.is_ok(), "{end:?}");
    assert!(chunks.last().is_some_and(|c| c.r#final && c.error.is_none()), "{chunks:?}");
}

/// Relay 52 (R-145): a running token, minted once with a grant in no list. No entry: an empty catalog and 7 `not
/// granted`. An entry for its chat, polled: the same token lists that grant's ops and its calls reach the worker, and
/// the worker's `Caller.grant_id` and the call line's `grant` name the grant that allowed the call, while the list line and
/// a denied call's line keep the token's. Two grants: `ListSources` unions them, a call goes through the first that
/// allows it, a token's own grant before any of the entry's. Its removal, polled: the same token is back to nothing,
/// with no tunnel closed, while a call in flight finishes (its line naming its grant). No line of the request log or
/// relay.log holds the chat's id, and no `Invoke` carries it.
#[tokio::test]
async fn an_access_entry_opens_a_running_token_and_its_removal_closes_it() {
    let (rig, written, _guard) = access_rig().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(Script::echo("worker-b"));
    let c = TestWorker::connect(&rig, "worker-c", 5, catalog_c()).await.serve(Script::silent());
    let mut client = rig.client().await;
    let token = rig.chat_token("no-grant", CHAT);
    let denied = (Code::PermissionDenied, "not granted".to_string());

    assert!(list(&mut client, &token).await.unwrap().sources.is_empty(), "no entry: nothing");
    assert_eq!(refusal(call(&mut client, &token, "example.alpha", "get", b"{}").await), denied, "no entry: not granted");
    assert_eq!(a.invokes().len(), 0);

    rig.write_access(&[access_entry(CHAT, &["g-alpha-get"]), access_entry(OTHER_CHAT, &["g-all"])]);
    assert!(matches!(rig.poll()[5], ("access", Poll::Loaded { .. })));
    let line = reloads(&rig, "access").pop().expect("a reload line of access");
    assert_eq!((line["outcome"].as_str(), line["entries"].as_u64()), (Some("loaded"), Some(2)));
    assert_eq!(line["version"], format!("{:016x}", content_version(&rig.read(ACCESS_FILE))));
    assert_eq!(listed_ops(&list(&mut client, &token).await.unwrap()), [ops_row("example.alpha", &["get"])], "the same token, its grant's one op");
    assert_eq!(rig.lines("list").pop().unwrap()["grant"], "no-grant", "the list line keeps the token's grant");
    answered(call(&mut client, &token, "example.alpha", "get", b"{}").await).await;
    let invoke = a.invoke(0).await;
    let caller = invoke.caller.as_ref().unwrap();
    assert_eq!(caller.grant_id, "g-alpha-get", "the worker hears the grant that allowed the call");
    assert_eq!((caller.caller_id.as_str(), caller.vm_id.as_str()), ("mac", VM_ID));
    let call_line = |r: &Rig, rid: &str| r.lines("call").into_iter().find(|l| l["request_id"] == rid).unwrap_or_else(|| panic!("the call line of {rid}"));
    rig.until(Duration::from_secs(10), "its call line", |r| r.lines("call").iter().any(|l| l["request_id"] == invoke.request_id.as_str())).await;
    assert_eq!(call_line(&rig, &invoke.request_id)["grant"], "g-alpha-get", "so does its line");
    for (source, op) in [("example.alpha", "list"), ("example.beta", "get"), ("example.zzz", "get")] {
        assert_eq!(refusal(call(&mut client, &token, source, op, b"{}").await), denied, "{source}/{op}: still before the source lookup");
        assert_eq!(rig.lines("call").pop().unwrap()["grant"], "no-grant", "{source}/{op}: a denied call's line keeps the token's grant");
    }

    // Two grants, sorted on render: the union of their ops, and a call through the first that allows it.
    hear_the_relay();
    rig.write_access(&[access_entry(CHAT, &["g-example", "g-alpha-get"])]);
    assert!(matches!(rig.poll()[5], ("access", Poll::Loaded { .. })));
    let every = [ops_row("example.alpha", &["get", "list"]), ops_row("example.alpha.logs", &["get", "list"]), ops_row("example.beta", &["get", "list"]), ops_row("example.gamma", &["get"])];
    assert_eq!(listed_ops(&list(&mut client, &token).await.unwrap()), every);
    answered(call(&mut client, &token, "example.alpha", "get", b"{}").await).await;
    answered(call(&mut client, &token, "example.alpha", "list", b"{}").await).await;
    answered(call(&mut client, &token, "example.beta", "get", b"{}").await).await;
    let mine = [a.invoke(1).await, a.invoke(2).await, b.invoke(0).await];
    assert_eq!(mine.each_ref().map(|i| i.caller.as_ref().unwrap().grant_id.as_str()), ["g-alpha-get", "g-example", "g-example"], "the first that allows each");
    assert_eq!(refusal(call(&mut client, &token, "other.x", "get", b"{}").await), denied, "neither grant allows it");
    let own = rig.chat_token("g-example", CHAT);
    answered(call(&mut client, &own, "example.alpha", "get", b"{}").await).await;
    assert_eq!(a.invoke(3).await.caller.unwrap().grant_id, "g-example", "a token's own grant first");

    // A call in flight through the entry; the entry removed, the other chat's staying: the token is back to nothing at
    // its next request, the call finishes, and no tunnel hears of it.
    let held = call(&mut client, &token, "example.gamma", "get", b"{}").await;
    let invoke = c.invoke(0).await;
    assert_eq!(invoke.caller.as_ref().unwrap().grant_id, "g-example");
    rig.write_access(&[access_entry(OTHER_CHAT, &["g-all"])]);
    assert!(matches!(rig.poll()[5], ("access", Poll::Loaded { .. })));
    assert!(list(&mut client, &token).await.unwrap().sources.is_empty(), "removed: nothing");
    assert_eq!(refusal(call(&mut client, &token, "example.alpha", "get", b"{}").await), denied, "removed: not granted");
    c.send(worker_frame::Msg::Chunk(data(&invoke.request_id, 0, b"{}".to_vec(), true))).await;
    answered(held).await;
    rig.until(Duration::from_secs(10), "the held call's line", |r| r.lines("call").iter().any(|l| l["request_id"] == invoke.request_id.as_str())).await;
    let line = call_line(&rig, &invoke.request_id);
    assert_eq!((line["outcome"].as_str(), line["grant"].as_str()), (Some("ok"), Some("g-example")), "a call in flight finishes");
    assert!(a.closes().is_empty() && b.closes().is_empty() && c.closes().is_empty(), "no tunnel is closed by this list");
    assert_eq!(rig.app.snapshot().tunnels, 3);

    // Allowed again, the same token once more: both ways.
    rig.write_access(&[access_entry(CHAT, &["g-alpha-get"])]);
    rig.poll();
    answered(call(&mut client, &token, "example.alpha", "get", b"{}").await).await;

    let served = [a.invokes(), b.invokes(), c.invokes()].concat();
    assert!(served.iter().all(|i| !format!("{i:?}").contains(CHAT)), "R-54: no Invoke carries the chat's id");
    // A refused token writes relay.log's line (R-53): the subscriber hears the relay's tasks.
    for _ in 0..2 {
        assert_eq!(list(&mut client, "not-a-token").await.expect_err("refused").code(), Code::Unauthenticated);
        hear_the_relay();
    }
    assert_eq!(list(&mut client, "not-a-token").await.expect_err("refused").code(), Code::Unauthenticated);
    let (requests, log) = (rig.sink.lines(), written.lines());
    assert!(log.iter().any(|l| l.contains("a session token was refused")), "{log:?}");
    assert!(requests.iter().any(|l| l.contains("\"ev\":\"call\"")) && requests.iter().any(|l| l.contains("\"ev\":\"reload\"")));
    for line in requests.iter().chain(&log) {
        assert!(!line.contains(CHAT) && !line.contains(OTHER_CHAT), "a chat's id in {line}");
    }
}

/// Relay 53's two tokens of one chat, one with a grant in no list and one with `g-alpha-get`, on one live tunnel and one
/// client, and what every other file's status keys said before any step.
struct OneChat<'a> {
    rig: &'a Rig,
    worker: Served,
    client: ai_env_relay_proto::v1::relay_client::RelayClient<tonic::transport::Channel>,
    link: Link,
    bare: String,
    own: String,
    others: (String, String, String, String, bool),
}

impl OneChat<'_> {
    fn others_now(&self) -> (String, String, String, String, bool) {
        let s = self.rig.app.snapshot();
        (s.workers_version, s.signers_version, s.grants_version, s.peers_version, s.tls_loaded)
    }

    /// What holds whatever the list's state: every other file loaded at its version, no tunnel, connection or session lost.
    fn alone(&self, what: &str) {
        let s = self.rig.app.snapshot();
        assert_eq!(self.others_now(), self.others, "{what}: every other file stays loaded");
        assert!(self.worker.closes().is_empty() && s.tunnels == 1 && s.sources_live == 2, "{what}: no tunnel is closed: {:?}", self.worker.closes());
        assert!(self.link.peer_closed_at().is_none(), "{what}: no client's connection");
        assert_eq!(s.sessions, 2, "{what}: no session");
    }

    /// The entry adds nothing, and the token with a grant of its own keeps it.
    async fn closed(&mut self, what: &str) {
        let denied = (Code::PermissionDenied, "not granted".to_string());
        assert!(list(&mut self.client, &self.bare).await.unwrap().sources.is_empty(), "{what}: the entry adds nothing to a list");
        assert_eq!(refusal(call(&mut self.client, &self.bare, "example.alpha", "get", b"{}").await), denied, "{what}: nor to a call");
        assert_eq!(listed_ops(&list(&mut self.client, &self.own).await.unwrap()), [ops_row("example.alpha", &["get"])], "{what}: the token's own grant stands");
        answered(call(&mut self.client, &self.own, "example.alpha", "get", b"{}").await).await;
        assert_eq!(refusal(call(&mut self.client, &self.own, "example.alpha", "list", b"{}").await), denied, "{what}: and nothing more");
        self.alone(what);
    }

    /// The entry adds its grant, to either token.
    async fn open(&mut self, what: &str) {
        let every = [ops_row("example.alpha", &["get", "list"]), ops_row("example.alpha.logs", &["get", "list"])];
        assert_eq!(listed_ops(&list(&mut self.client, &self.bare).await.unwrap()), every, "{what}: the entry adds to a list");
        answered(call(&mut self.client, &self.bare, "example.alpha", "list", b"{}").await).await;
        assert_eq!(listed_ops(&list(&mut self.client, &self.own).await.unwrap()), every, "{what}: the union with the token's own");
        answered(call(&mut self.client, &self.own, "example.alpha", "list", b"{}").await).await;
        self.alone(what);
    }
}

/// Relay 53 (R-144, R-145): the list fails closed, and alone. Never written (`missing`, once), refused by the shared parser
/// or as bytes, removed, its entry lapsed, or loaded from a fetch 901 s old while every other list is fresh: the entry adds
/// nothing, and a token keeps its own grant (`OneChat::closed`). Each time no tunnel is closed, no client's connection and
/// no session is lost, every other file stays loaded at its own version (`OneChat::alone`), and a good list applies again
/// at once (`OneChat::open`).
#[tokio::test]
async fn the_access_list_fails_closed_and_alone() {
    let (rig, written, _guard) = access_rig().await;
    let worker = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let (channel, link) = rig.private_channel().await;
    let client = ai_env_relay_proto::v1::relay_client::RelayClient::new(channel);
    let (bare, own) = (rig.chat_token("no-grant", CHAT), rig.chat_token("g-alpha-get", CHAT));
    let mut chat = OneChat { rig: &rig, worker, client, link, bare, own, others: Default::default() };
    chat.others = chat.others_now();
    assert!(!chat.others.0.is_empty() && !chat.others.1.is_empty() && !chat.others.2.is_empty() && !chat.others.3.is_empty() && chat.others.4);
    let last_reload = |r: &Rig| {
        let line = reloads(r, "access").pop().expect("a reload line of access");
        (line["outcome"].as_str().unwrap().to_string(), line["version"].as_str().unwrap().to_string(), line["entries"].as_u64().unwrap())
    };

    // Never written: reported once, as the rig's first poll found it.
    assert_eq!(reloads(&rig, "access").len(), 1);
    assert_eq!(last_reload(&rig), ("missing".to_string(), String::new(), 0));
    assert_eq!(rig.poll()[5], ("access", Poll::Unchanged));
    assert_eq!(reloads(&rig, "access").len(), 1, "an absent list is reported once");
    assert_eq!(rig.app.snapshot().access_version, "");
    chat.closed("never written").await;

    rig.write_access(&[access_entry(CHAT, &["g-example"])]);
    assert!(matches!(rig.poll()[5], ("access", Poll::Loaded { .. })));
    chat.open("loaded").await;

    // Refused, whatever refuses it: unloaded, its version gone, and its text no value.
    let good = rig.read(ACCESS_FILE);
    let not_uuid = String::from_utf8(good.clone()).unwrap().replace(CHAT, "not-a-uuid");
    let unknown = String::from_utf8(good.clone()).unwrap().replacen("\"chat\"", "\"extra\":1,\"chat\"", 1);
    let cases: [(&[u8], &str); 4] = [
        (not_uuid.as_bytes(), "access: entry 0: chat is not a uuid (lowercase 8-4-4-4-12 hex)"),
        (unknown.as_bytes(), "access: entry 0: an unknown field"),
        (b"[", "access: not a JSON array (line 1, column 1)"),
        (&[0xff, 0xfe], "not UTF-8"),
    ];
    for (bytes, text) in cases {
        hear_the_relay();
        rig.write(ACCESS_FILE, bytes);
        assert_eq!(rig.poll()[5], ("access", Poll::Refused(text.to_string())));
        assert_eq!(last_reload(&rig), ("refused".to_string(), String::new(), 0));
        assert_eq!(rig.app.snapshot().access_version, "", "{text}");
        chat.closed(text).await;
        rig.write(ACCESS_FILE, &good);
        assert!(matches!(rig.poll()[5], ("access", Poll::Loaded { .. })), "{text}");
        assert_eq!(rig.app.snapshot().access_version, format!("{:016x}", content_version(&good)));
        chat.open("restored").await;
    }

    // Removed.
    rig.remove(ACCESS_FILE);
    assert_eq!(rig.poll()[5], ("access", Poll::Missing));
    assert_eq!(last_reload(&rig), ("missing".to_string(), String::new(), 0));
    chat.closed("removed").await;
    rig.write(ACCESS_FILE, &good);
    rig.poll();
    chat.open("written again").await;

    // Lapsed, the file as it was and fresh: in force through its not_after second, nothing one second later.
    const LAPSES: &str = "2027-01-15T08:00:05Z";
    let lapses = ai_env_worker::policy::unix_of(LAPSES).unwrap();
    assert_eq!(lapses, T0 + 5);
    let until = |not_after: &str| ai_env_worker::policy::AccessEntry { not_after: not_after.into(), ..access_entry(CHAT, &["g-example"]) };
    rig.write_access(&[until(LAPSES)]);
    assert!(matches!(rig.poll()[5], ("access", Poll::Loaded { .. })));
    rig.clock.set(lapses);
    rig.write_fetched(lapses);
    assert_eq!(rig.poll()[5], ("access", Poll::Unchanged));
    chat.open("through its not_after second").await;
    rig.clock.set(lapses + 1);
    rig.write_fetched(lapses + 1);
    let polled = rig.poll();
    assert!(polled.iter().all(|(_, p)| *p == Poll::Unchanged), "every file as it was, and fresh: {polled:?}");
    chat.closed("lapsed").await;

    // Stale alone: the clock and every list at T0 + 1000, then a new list loaded from a `fetched` of T0 + 99, 901 s
    // before the clock (a fetch time only ever moves a file's freshness forward, R-16: the rest keep T0 + 1000). `loaded`
    // would serve it; `fresh` serves nothing.
    rig.clock.set(T0 + 1000);
    rig.write_fetched(T0 + 1000);
    assert_eq!(rig.poll()[5], ("access", Poll::Unchanged));
    rig.write_fetched(T0 + 99);
    rig.write_access(&[access_entry(CHAT, &["g-example"])]);
    let polled = rig.poll();
    assert!(polled[..5].iter().all(|(_, p)| *p == Poll::Unchanged) && matches!(polled[5], ("access", Poll::Loaded { .. })), "{polled:?}");
    assert_eq!(rig.app.snapshot().access_age_s, 901);
    chat.closed("stale").await;
    assert_eq!(rig.poll()[5], ("access", Poll::Unchanged));
    chat.closed("stale, a poll later").await;
    rig.write_fetched(T0 + 1000);
    assert_eq!(rig.poll()[5], ("access", Poll::Unchanged));
    assert_eq!(rig.app.snapshot().access_age_s, 0);
    chat.open("fresh again").await;

    // A refused list's text and every reload line hold no value of it; a call line names the grant it went through.
    let log = written.lines();
    assert!(log.iter().any(|l| l.contains("a live file was refused: access: ")), "{log:?}");
    for line in rig.sink.lines().iter().chain(&log) {
        assert!(!line.contains(CHAT) && !line.contains("not-a-uuid"), "a chat in {line}");
    }
    let reload_lines = rig.lines("reload");
    assert!(reload_lines.iter().map(ToString::to_string).chain(log).all(|l| !l.contains("g-example")), "a grant of the list in {reload_lines:?}");
}

/// Relay 54 (R-145): the list's key is the token's `chat_id` and nothing else. A token with no `chat_id` whose
/// `session_id` is the entry's chat matches no entry, nor does one naming another chat with that `session_id`; each lists
/// and calls under its own grant alone. A token of that chat, with any session, matches.
#[tokio::test]
async fn a_token_without_a_chat_matches_no_entry() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    rig.write_access(&[access_entry(CHAT, &["g-all"])]);
    assert!(matches!(rig.poll()[5], ("access", Poll::Loaded { .. })));
    let denied = (Code::PermissionDenied, "not granted".to_string());
    let with = |chat: Option<&str>, grant: &str| mint(7, &SessionClaims { session_id: CHAT.into(), chat_id: chat.map(str::to_string), ..rig.claims(grant) });
    for (token, what) in [(with(None, "no-grant"), "no chat"), (with(Some(OTHER_CHAT), "no-grant"), "another chat")] {
        assert!(list(&mut client, &token).await.unwrap().sources.is_empty(), "{what}");
        assert_eq!(refusal(call(&mut client, &token, "example.alpha", "get", b"{}").await), denied, "{what}");
    }
    for (token, what) in [(with(None, "g-alpha-get"), "no chat"), (with(Some(OTHER_CHAT), "g-alpha-get"), "another chat")] {
        assert_eq!(listed_ops(&list(&mut client, &token).await.unwrap()), [ops_row("example.alpha", &["get"])], "{what}: its own grant alone");
        assert_eq!(refusal(call(&mut client, &token, "example.alpha", "list", b"{}").await), denied, "{what}");
    }
    assert_eq!(a.invokes().len(), 0, "nothing reached the worker");
    let chat = rig.chat_token("no-grant", CHAT);
    answered(call(&mut client, &chat, "example.alpha", "list", b"{}").await).await;
    assert_eq!(a.invoke(0).await.caller.unwrap().grant_id, "g-all", "the entry's chat, with any session");
}

/// A token signer of a seed's key, with these grants.
fn signer_of(id: &str, seed: u8, grants: Option<&[&str]>) -> ai_env_relay::lists::SignerEntry {
    ai_env_relay::lists::SignerEntry {
        signer_id: id.into(),
        public_key: ai_env_worker::keys::SigningKey::from_seed(&[seed; 32]).unwrap().public_key().b64(),
        grants: grants.map(|g| g.iter().map(|s| (*s).to_string()).collect()),
        ..mac_signer(NOT_AFTER)
    }
}

/// A fresh session's claims of the signer `id` for `grant_id`: it is its own caller (R-133).
fn claims_of(rig: &Rig, id: &str, grant_id: &str) -> SessionClaims {
    SessionClaims { kid: id.into(), caller_id: id.into(), ..rig.claims(grant_id) }
}

/// Relay 46 (R-135, R-145): `kid` `mac-a` for a grant only `mac-b` holds: `ListSources` and `Call` 7 `not granted` (outcome
/// `denied`), its line naming the caller, no session made and nothing at a worker; its own grant passes, on both, by the
/// one glob of its set that matches, neither the first nor the last; a signer without `grants` reaches every grant.
/// An access entry takes a signer no further than its set, on both calls alike: a set matching a token's `no-grant` and
/// one grant of the entry's two lists that grant's ops and calls through it, the worker's `Caller.grant_id` and the call
/// line's `grant` naming it, while the other, which the entry sorts first, reaches nothing; a set matching only the
/// token's own grant gets nothing from the entry; a set matching the entry but not the token's own grant is refused
/// as above, entry or no entry; a signer without `grants` reaches all the entry holds; and a running token loses what
/// the entry gave it when its signer's set narrows.
#[tokio::test]
async fn a_signer_mints_for_its_own_grants_only() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    rig.write_signers(&[signer_of("mac-a", 7, Some(&["a-nothing", "g-alpha-*", "z-nothing"])), signer_of("mac-b", 8, Some(&["g-example"])), signer_of("mac-c", 9, None)]);
    rig.poll();
    let denied = |s: tonic::Status| {
        assert_eq!((s.code(), s.message()), (Code::PermissionDenied, "not granted"));
    };
    // Every grant the list holds but its own, whichever rules that grant has: `g-all` would reach everything.
    for grant in ["g-example", "g-all"] {
        let token = mint(7, &claims_of(&rig, "mac-a", grant));
        denied(list(&mut client, &token).await.expect_err("ListSources under another signer's grant"));
        denied(call(&mut client, &token, "example.alpha", "get", b"{}").await.expect_err("Call under another signer's grant"));
    }
    assert_eq!(rig.app.snapshot().sessions, 0, "no session made");
    assert!(a.invokes().is_empty(), "nothing reached a worker");
    let line = rig.lines("list").pop().expect("a list line");
    assert_eq!((line["outcome"].as_str(), line["caller"].as_str(), line["grant"].as_str(), line["code"].as_i64()), (Some("denied"), Some("mac-a"), Some("g-all"), Some(7)));
    let line = rig.lines("call").pop().expect("a call line");
    assert_eq!((line["outcome"].as_str(), line["caller"].as_str(), line["grant"].as_str(), line["code"].as_i64()), (Some("denied"), Some("mac-a"), Some("g-all"), Some(7)));

    // Its own grant, by its glob, on both.
    let own = mint(7, &claims_of(&rig, "mac-a", "g-alpha-get"));
    assert_eq!(names(&list(&mut client, &own).await.expect("its own grant")), [("example.alpha".to_string(), true)]);
    let (chunks, _) = drain(call(&mut client, &own, "example.alpha", "get", b"{}").await.expect("its own grant")).await;
    assert_eq!(chunks.len(), 1);
    assert_eq!(rig.app.snapshot().sessions, 1, "its session");
    // The grant's own rules still bind what the signer may name.
    denied(call(&mut client, &own, "example.alpha", "list", b"{}").await.expect_err("g-alpha-get holds no list"));
    // mac-b holds the grant mac-a could not name; its token for mac-a's grant is refused the same.
    let theirs = mint(8, &claims_of(&rig, "mac-b", "g-example"));
    list(&mut client, &theirs).await.expect("mac-b's own grant");
    denied(list(&mut client, &mint(8, &claims_of(&rig, "mac-b", "g-alpha-get"))).await.expect_err("mac-a's grant"));
    // A signer without `grants` reaches every grant: today's reach.
    for grant in ["g-all", "g-example", "g-alpha-get"] {
        let token = mint(9, &claims_of(&rig, "mac-c", grant));
        list(&mut client, &token).await.unwrap_or_else(|e| panic!("{grant}: {e}"));
        let (chunks, _) = drain(call(&mut client, &token, "example.alpha", "get", b"{}").await.unwrap_or_else(|e| panic!("{grant}: {e}"))).await;
        assert_eq!(chunks.len(), 1, "{grant}");
    }
    assert_eq!(a.invokes().len(), 4, "its one call, then the three of mac-c");

    // R-145: through an access entry. `g-all` sorts first in it and allows everything; `g-alpha-get` allows one op.
    rig.write_signers(&[
        signer_of("mac-a", 7, Some(&["a-nothing", "g-alpha-*", "z-nothing"])),
        signer_of("mac-c", 9, None),
        signer_of("mac-d", 10, Some(&["no-grant", "g-alpha-*"])),
        signer_of("mac-e", 11, Some(&["g-alpha-*"])),
        signer_of("mac-f", 12, Some(&["no-grant"])),
    ]);
    rig.write_access(&[access_entry(CHAT, &["g-alpha-get", "g-all"])]);
    rig.poll();
    let chat_of = |seed: u8, id: &str, grant: &str| mint(seed, &SessionClaims { chat_id: Some(CHAT.into()), ..claims_of(&rig, id, grant) });
    let every = [ops_row("example.alpha", &["get", "list"]), ops_row("example.alpha.logs", &["get", "list"])];

    // The one grant of the two its set matches, on a list and a call alike, and it alone names the call.
    let one_of_two = chat_of(10, "mac-d", "no-grant");
    assert_eq!(listed_ops(&list(&mut client, &one_of_two).await.expect("its own grant")), [ops_row("example.alpha", &["get"])], "g-alpha-get's one op, not g-all's");
    let line = rig.lines("list").pop().expect("a list line");
    assert_eq!((line["outcome"].as_str(), line["caller"].as_str(), line["grant"].as_str()), (Some("ok"), Some("mac-d"), Some("no-grant")), "the list line keeps the token's");
    answered(call(&mut client, &one_of_two, "example.alpha", "get", b"{}").await).await;
    let invoke = a.invoke(4).await;
    assert_eq!(invoke.caller.as_ref().unwrap().grant_id, "g-alpha-get", "the grant that allowed it, though g-all comes first");
    rig.until(Duration::from_secs(10), "its call line", |r| r.lines("call").iter().any(|l| l["request_id"] == invoke.request_id.as_str())).await;
    let line = rig.lines("call").into_iter().find(|l| l["request_id"] == invoke.request_id.as_str()).unwrap();
    assert_eq!((line["outcome"].as_str(), line["grant"].as_str()), (Some("ok"), Some("g-alpha-get")), "so does its line");
    denied(call(&mut client, &one_of_two, "example.alpha", "list", b"{}").await.expect_err("only g-all allows it"));
    let line = rig.lines("call").pop().expect("a call line");
    assert_eq!((line["outcome"].as_str(), line["grant"].as_str()), (Some("denied"), Some("no-grant")), "a denied call's line keeps the token's");

    // A token's own grant under a set that leaves out the entry's other: the same, its own grant named once.
    let own_named = chat_of(7, "mac-a", "g-alpha-get");
    assert_eq!(listed_ops(&list(&mut client, &own_named).await.expect("its own grant")), [ops_row("example.alpha", &["get"])]);
    denied(call(&mut client, &own_named, "example.alpha", "list", b"{}").await.expect_err("only g-all allows it"));

    // A set matching the token's own grant and none of the entry's: an empty catalog and 7, a session made.
    let sessions = rig.app.snapshot().sessions;
    let none_of_two = chat_of(12, "mac-f", "no-grant");
    assert!(list(&mut client, &none_of_two).await.expect("its own grant").sources.is_empty(), "the entry adds nothing");
    denied(call(&mut client, &none_of_two, "example.alpha", "get", b"{}").await.expect_err("the entry adds nothing"));
    assert_eq!(rig.app.snapshot().sessions, sessions + 1, "its own grant let it in");

    // A set matching the entry but not the token's own grant: R-135 first, so the entry never counts and no session is made.
    let not_its_own = chat_of(11, "mac-e", "no-grant");
    denied(list(&mut client, &not_its_own).await.expect_err("no-grant is not its own"));
    denied(call(&mut client, &not_its_own, "example.alpha", "get", b"{}").await.expect_err("no-grant is not its own"));
    assert_eq!(rig.app.snapshot().sessions, sessions + 1, "no session made");
    let line = rig.lines("call").pop().expect("a call line");
    assert_eq!((line["outcome"].as_str(), line["caller"].as_str(), line["grant"].as_str()), (Some("denied"), Some("mac-e"), Some("no-grant")));

    // A signer with no set: all the entry holds, and each call through the first of its grants that allows it.
    assert_eq!(a.invokes().len(), 5, "the one call above");
    let no_set = chat_of(9, "mac-c", "no-grant");
    assert_eq!(listed_ops(&list(&mut client, &no_set).await.expect("today's reach")), every, "both grants");
    answered(call(&mut client, &no_set, "example.alpha", "list", b"{}").await).await;
    assert_eq!(a.invoke(5).await.caller.unwrap().grant_id, "g-all");
    answered(call(&mut client, &no_set, "example.alpha.logs", "get", b"{}").await).await;
    assert_eq!(a.invoke(6).await.caller.unwrap().grant_id, "g-all");
    assert_eq!(a.invokes().len(), 7);

    // Per request, with no cache: the running token of a signer whose set narrows loses what the entry gave it.
    rig.write_signers(&[signer_of("mac-d", 10, Some(&["no-grant"]))]);
    rig.poll();
    assert!(list(&mut client, &one_of_two).await.expect("its own grant").sources.is_empty(), "the set narrowed");
    denied(call(&mut client, &one_of_two, "example.alpha", "get", b"{}").await.expect_err("the set narrowed"));
    assert_eq!(a.invokes().len(), 7);
}

/// Relay 47 (R-136): with `sessions_per_signer` 2, a third session of one signer is 8 `too many sessions` (outcome
/// `too_many`), on both calls; its two go on, another signer's session is admitted, and another signer's token naming a
/// session this one made is refused the same.
#[tokio::test]
async fn one_signer_cannot_fill_the_sessions() {
    let rig = Rig::start_with(Limits { sessions_per_signer: 2, ..limits() }).await;
    let _a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    rig.write_signers(&[signer_of("mac", 7, None), signer_of("mac-b", 8, None)]);
    rig.poll();
    let first = rig.claims("g-all");
    let (one, two) = (mint(7, &first), rig.token("g-all"));
    list(&mut client, &one).await.expect("the first");
    let (chunks, _) = drain(call(&mut client, &two, "example.alpha", "get", b"{}").await.expect("the second")).await;
    assert_eq!(chunks.len(), 1);
    assert_eq!(rig.app.snapshot().sessions, 2);
    let third = rig.token("g-all");
    let s = list(&mut client, &third).await.expect_err("the third, a list");
    assert_eq!((s.code(), s.message()), (Code::ResourceExhausted, "too many sessions"));
    let s = call(&mut client, &third, "example.alpha", "get", b"{}").await.expect_err("the third, a call");
    assert_eq!((s.code(), s.message()), (Code::ResourceExhausted, "too many sessions"));
    assert_eq!(rig.app.snapshot().sessions, 2, "a refused session holds nothing");
    let line = rig.lines("list").pop().expect("a list line");
    assert_eq!((line["outcome"].as_str(), line["caller"].as_str(), line["code"].as_i64()), (Some("too_many"), Some("mac"), Some(8)));
    let line = rig.lines("call").pop().expect("a call line");
    assert_eq!((line["outcome"].as_str(), line["caller"].as_str(), line["code"].as_i64()), (Some("too_many"), Some("mac"), Some(8)));
    list(&mut client, &one).await.expect("a session it holds goes on");
    list(&mut client, &mint(8, &claims_of(&rig, "mac-b", "g-all"))).await.expect("another signer's session");
    assert_eq!(rig.app.snapshot().sessions, 3);
    // A session is its signer's: mac-b's good token naming mac's session enters nothing.
    let across = mint(8, &SessionClaims { session_id: first.session_id.clone(), ..claims_of(&rig, "mac-b", "g-all") });
    let s = list(&mut client, &across).await.expect_err("mac's session, a list");
    assert_eq!((s.code(), s.message()), (Code::ResourceExhausted, "too many sessions"));
    let s = call(&mut client, &across, "example.alpha", "get", b"{}").await.expect_err("mac's session, a call");
    assert_eq!((s.code(), s.message()), (Code::ResourceExhausted, "too many sessions"));
    let line = rig.lines("call").pop().expect("a call line");
    assert_eq!((line["outcome"].as_str(), line["caller"].as_str(), line["code"].as_i64()), (Some("too_many"), Some("mac-b"), Some(8)));
    assert_eq!(rig.app.snapshot().sessions, 3, "nothing new");
    list(&mut client, &one).await.expect("mac's own token still enters it");
}

/// Relay 48 (R-137): this rig's relay is `relay-test`, not the default id, and the tokens of every other test here are
/// minted for it. A token for the default relay, or for any other, is refused 16 on both calls: no session, nothing at a
/// worker; and its signature is good, so nothing but `aud` refused it.
#[tokio::test]
async fn a_relay_refuses_a_token_minted_for_another() {
    assert_ne!(RELAY_ID, ai_env_worker::session::SESSION_AUD, "this relay is not the default one");
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let mut client = rig.client().await;
    for aud in [ai_env_worker::session::SESSION_AUD, "relay-other"] {
        let token = mint(7, &SessionClaims { aud: aud.into(), ..rig.claims("g-all") });
        let s = list(&mut client, &token).await.expect_err("minted for another relay");
        assert_eq!((s.code(), s.message()), (Code::Unauthenticated, "authentication failed"), "{aud}");
        let s = call(&mut client, &token, "example.alpha", "get", b"{}").await.expect_err("minted for another relay");
        assert_eq!((s.code(), s.message()), (Code::Unauthenticated, "authentication failed"), "{aud}");
    }
    assert_eq!(rig.app.snapshot().sessions, 0, "no session made");
    assert!(a.invokes().is_empty(), "nothing reached a worker");
    let (chunks, _) = drain(call(&mut client, &rig.token("g-all"), "example.alpha", "get", b"{}").await.expect("minted for this relay")).await;
    assert_eq!(chunks.len(), 1);
    assert_eq!(a.invokes().len(), 1);
}

/// Relay 55 (R-155, with R-135 and R-145; M-R186): a restricted grant reaches a chat only through the sole signer, and the
/// relay needs no change. The two signers as `relay allow` binds them: `mac` (seed 7) to `no-grant` and the open grant
/// (`g-alpha-get` here), `mac-sole` (seed 8) to those and the restricted one (`g-example`). One chat's entry holds both
/// grants. Two tokens of that chat with the same own grant, one of each signer: `mac`'s lists and calls the open grant's
/// op alone, and is refused 7 `not granted` on the rest, nothing reaching the restricted grant's worker; `mac-sole`'s lists
/// both grants' ops and its call reaches that worker, whose `Caller` names `mac-sole` and the restricted grant. A `mac` token
/// whose own grant is the restricted one is refused whole, no session made; another chat's `mac-sole` token gets nothing
/// from this chat's entry.
#[tokio::test]
async fn a_restricted_grant_reaches_a_chat_only_through_the_sole_signer() {
    let rig = Rig::start().await;
    let a = TestWorker::connect(&rig, "worker-a", 1, catalog_a()).await.serve(Script::echo("worker-a"));
    let b = TestWorker::connect(&rig, "worker-b", 2, catalog_b()).await.serve(Script::echo("worker-b"));
    let mut client = rig.client().await;
    rig.write_signers(&[signer_of("mac", 7, Some(&["no-grant", "g-alpha-get"])), signer_of("mac-sole", 8, Some(&["g-alpha-get", "g-example", "no-grant"]))]);
    rig.write_access(&[access_entry(CHAT, &["g-alpha-get", "g-example"])]);
    rig.poll();
    let chat_of = |seed: u8, id: &str, chat: &str, grant: &str| mint(seed, &SessionClaims { chat_id: Some(chat.into()), ..claims_of(&rig, id, grant) });
    let (shared, sole) = (chat_of(7, "mac", CHAT, "no-grant"), chat_of(8, "mac-sole", CHAT, "no-grant"));
    let denied = (Code::PermissionDenied, "not granted".to_string());

    // `mac`: the open grant alone, whatever the entry holds.
    assert_eq!(listed_ops(&list(&mut client, &shared).await.expect("its own grant")), [ops_row("example.alpha", &["get"])], "the open grant's one op");
    answered(call(&mut client, &shared, "example.alpha", "get", b"{}").await).await;
    let caller = a.invoke(0).await.caller.unwrap();
    assert_eq!((caller.caller_id.as_str(), caller.grant_id.as_str()), ("mac", "g-alpha-get"));
    for (source, op) in [("example.alpha", "list"), ("example.alpha.logs", "get"), ("example.beta", "get")] {
        assert_eq!(refusal(call(&mut client, &shared, source, op, b"{}").await), denied, "{source}/{op}: the restricted grant alone allows it");
    }
    assert!(b.invokes().is_empty(), "nothing reached the restricted grant's worker");

    // `mac-sole`: both grants, each call through the first that allows it.
    let every = [ops_row("example.alpha", &["get", "list"]), ops_row("example.alpha.logs", &["get", "list"]), ops_row("example.beta", &["get", "list"])];
    assert_eq!(listed_ops(&list(&mut client, &sole).await.expect("its own grant")), every);
    answered(call(&mut client, &sole, "example.beta", "get", b"{}").await).await;
    let caller = b.invoke(0).await.caller.unwrap();
    assert_eq!((caller.caller_id.as_str(), caller.grant_id.as_str()), ("mac-sole", "g-example"), "the restricted grant, through the sole signer");
    answered(call(&mut client, &sole, "example.alpha", "list", b"{}").await).await;
    assert_eq!(a.invoke(1).await.caller.unwrap().grant_id, "g-example");
    answered(call(&mut client, &sole, "example.alpha", "get", b"{}").await).await;
    assert_eq!(a.invoke(2).await.caller.unwrap().grant_id, "g-alpha-get", "the open grant first");

    // `mac` naming the restricted grant as its own: refused whole (R-135), no session made.
    let sessions = rig.app.snapshot().sessions;
    let own = chat_of(7, "mac", CHAT, "g-example");
    let s = list(&mut client, &own).await.expect_err("the restricted grant as its own");
    assert_eq!((s.code(), s.message()), (Code::PermissionDenied, "not granted"));
    assert_eq!(refusal(call(&mut client, &own, "example.beta", "get", b"{}").await), denied);
    assert_eq!(rig.app.snapshot().sessions, sessions, "no session made");
    // Another chat's sole token: nothing from this chat's entry.
    let theirs = chat_of(8, "mac-sole", OTHER_CHAT, "no-grant");
    assert!(list(&mut client, &theirs).await.expect("its own grant").sources.is_empty(), "another chat's entry");
    assert_eq!(refusal(call(&mut client, &theirs, "example.beta", "get", b"{}").await), denied);
    assert_eq!((a.invokes().len(), b.invokes().len()), (3, 1), "the three calls above and the one");
}
