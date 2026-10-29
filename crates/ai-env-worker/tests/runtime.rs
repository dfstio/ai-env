//! The worker runtime against a scripted relay (§WM-worker-mac.8.2, WM-T12 to WM-T30): TLS 1.3 under the
//! test CA over `tokio::io::duplex`, the handshake, reconnects, calls and their output. Timings are short
//! (`common::quick`): milliseconds, not seconds.

mod common;

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use ai_env_relay_proto::v1::{relay_frame, worker_frame, Chunk, SigAlg};
use ai_env_worker::ai_env_source::redact::Rule;
use ai_env_worker::ai_env_source::testkit::{sample, EchoSource, Scripted, ScriptedSource};
use ai_env_worker::ai_env_source::{
    wire, BoxFuture, CallContext, CallRequest, DataSource, OpDescriptor, Output, OutputKind, Redactor, SourceDescriptor, SourceError, TextStream,
};
use ai_env_worker::keys::{Alg, PublicKey, SigningKey};
use ai_env_worker::signer::{AuthChallenge, SignError, Signer};
use ai_env_worker::{map, BuildError, Tuning, Worker, WorkerError};
use common::fake_relay::{self, cancel, invoke, ping, FakeRelay, Next, Script, WAIT};
use common::{builder, certs::pki, key, quick, sources};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_stream::Stream;

/// A worker running until the sender is used or dropped.
fn spawn(worker: Worker) -> (oneshot::Sender<()>, tokio::task::JoinHandle<Result<(), WorkerError>>) {
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(worker.run_until(async move {
        let _ = stopped.await;
    }));
    (stop, task)
}

/// A request id: a UUIDv7's shape.
fn rid(i: usize) -> String {
    format!("0199a1b2-0000-7000-8000-{i:012}")
}

fn data(chunks: &[Chunk]) -> Vec<u8> {
    chunks.iter().flat_map(|c| c.data.clone()).collect()
}

fn last(chunks: &[Chunk]) -> &Chunk {
    chunks.last().expect("a chunk")
}

/// The final chunk's error code, if any.
fn code(chunks: &[Chunk]) -> Option<i32> {
    last(chunks).error.as_ref().map(|e| e.code)
}

/// Chunks of one call follow WM-R25: `seq` from 0 without a gap, one final chunk, the last.
fn well_formed(id: &str, chunks: &[Chunk]) {
    for (i, c) in chunks.iter().enumerate() {
        assert_eq!(c.request_id, id);
        assert_eq!(c.seq, i as u64, "{id}: seq");
        assert_eq!(c.r#final, i + 1 == chunks.len(), "{id}: only the last is final");
        assert!(c.data.len() <= wire::CHUNK_MAX, "{id}: chunk {i} of {} bytes", c.data.len());
        if !c.r#final {
            assert!(c.error.is_none() && !c.truncated, "{id}: error and truncated only on the final chunk");
        }
    }
}

/// A double (the leak guard's `RecordingSource`): it counts its `descriptor()` calls and answers its one op
/// `get` with a stream it builds from what the test gives it, recording when that stream is dropped.
struct RecordingSource {
    descriptor: SourceDescriptor,
    descriptors: AtomicUsize,
    items: Mutex<Option<StreamItems>>,
    dropped: Arc<AtomicBool>,
}

/// The items of the next stream.
enum StreamItems {
    /// All at once, lazily, as many as polled.
    Lines(Vec<String>),
    /// These, then an `Err` item.
    Failing(Vec<String>, SourceError),
    /// As the test sends them.
    Fed(mpsc::UnboundedReceiver<String>),
}

impl RecordingSource {
    fn new(name: &str, items: Option<StreamItems>) -> Arc<RecordingSource> {
        let descriptor = SourceDescriptor::new(name, "0.1.0", "A test source.").op(OpDescriptor::new("get", "Gets.").output(OutputKind::Stream).read_only(true));
        Arc::new(RecordingSource { descriptor, descriptors: AtomicUsize::new(0), items: Mutex::new(items), dropped: Arc::new(AtomicBool::new(false)) })
    }
}

/// A stream that records its drop.
struct Watched {
    inner: Pin<Box<dyn Stream<Item = Result<String, SourceError>> + Send>>,
    dropped: Arc<AtomicBool>,
}

impl Stream for Watched {
    type Item = Result<String, SourceError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl DataSource for RecordingSource {
    fn descriptor(&self) -> SourceDescriptor {
        self.descriptors.fetch_add(1, Ordering::SeqCst);
        self.descriptor.clone()
    }

    fn call<'s, 'f>(&'s self, _req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        let items = self.items.lock().expect("items").take();
        let dropped = self.dropped.clone();
        Box::pin(async move {
            let inner: Pin<Box<dyn Stream<Item = Result<String, SourceError>> + Send>> = match items {
                Some(StreamItems::Lines(lines)) => Box::pin(ai_env_worker::ai_env_source::stream_iter(lines.into_iter().map(Ok))),
                Some(StreamItems::Failing(lines, e)) => Box::pin(ai_env_worker::ai_env_source::stream_iter(lines.into_iter().map(Ok).chain([Err(e)]))),
                Some(StreamItems::Fed(rx)) => Box::pin(tokio_stream::StreamExt::map(tokio_stream::wrappers::UnboundedReceiverStream::new(rx), Ok)),
                None => return Err(SourceError::Internal("no stream left".into())),
            };
            Ok(Output::stream(TextStream::lines(Watched { inner, dropped })))
        })
    }
}

/// A double (the leak guard's `PanickingSource`): its `call` panics before it returns a future, as a
/// hand-written impl may.
struct PanickingSource {
    descriptor: SourceDescriptor,
}

impl DataSource for PanickingSource {
    fn descriptor(&self) -> SourceDescriptor {
        self.descriptor.clone()
    }

    fn call<'s, 'f>(&'s self, _req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        panic!("panic-text-before-any-future");
    }
}

/// An `#[async_trait]` signer (Q-WM19) standing in for an agent's: bound to the worker id `other`.
struct BoundSigner {
    key: SigningKey,
}

#[async_trait::async_trait]
impl Signer for BoundSigner {
    fn alg(&self) -> Alg {
        Alg::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    fn bound_worker_id(&self) -> Option<&str> {
        Some("other")
    }

    async fn sign_worker_auth(&self, c: &AuthChallenge) -> Result<[u8; 64], SignError> {
        let t = wire::transcript(&c.relay_id, &c.nonce, &c.worker_id, 1, self.key.public_key().bytes(), c.protocol);
        Ok(self.key.sign(&t))
    }
}

/// WM-T12.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_handshake_signs_the_challenge_and_pushes_the_catalog() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let echo = sources::echo();
    let sleeper = sources::sleeper(0);
    let worker = builder(&relay).source(echo.clone()).source(sleeper.clone()).build().expect("builds");
    assert_eq!((worker.worker_id(), worker.public_key()), ("worker-a", key().public_key()));
    let (stop, task) = spawn(worker);
    let mut tunnel = relay.tunnel(WAIT).await;
    assert_eq!(tunnel.hello.worker_id, "worker-a");
    assert_eq!(tunnel.hello.alg, SigAlg::Ed25519 as i32);
    assert_eq!(tunnel.hello.public_key, key().public_key().bytes().to_vec());
    assert_eq!(tunnel.hello.protocol, 1);
    assert_eq!(tunnel.hello.sdk_version, ai_env_worker::SDK_VERSION);
    assert!(tunnel.proof_ok, "the proof verifies over §P's transcript");
    let catalog = tunnel.catalog.clone().expect("a catalog");
    assert_eq!(catalog.sources, vec![map::descriptor(&echo.descriptor()), map::descriptor(&sleeper.descriptor())]);
    let more: Vec<_> = tunnel.drain(Duration::from_millis(300)).await;
    assert!(!more.iter().any(|m| matches!(m, worker_frame::Msg::Catalog(_))), "exactly one catalog: {more:?}");
    assert_eq!(relay.alpn(), vec![Some(b"h2".to_vec())], "the worker offered ALPN h2");
    let _ = stop.send(());
    assert_eq!(task.await.expect("joined"), Ok(()));
}

/// WM-T13.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_handshake_waits_the_refused_floor() {
    let t = quick();
    let mut relay = FakeRelay::start(&pki().relay_a);
    relay.script(&[Script::RefuseProof, Script::RefuseProof, Script::RefuseProof]);
    let (stop, task) = spawn(builder(&relay).source(sources::echo()).build().expect("builds"));
    let tunnel = relay.tunnel(Duration::from_secs(5)).await;
    let dials = relay.dials();
    let refused = relay.refusals();
    assert_eq!((dials.len(), refused.len()), (4, 3), "three refusals, then the tunnel");
    for i in 0..3 {
        let gap = dials[i + 1].saturating_duration_since(refused[i]);
        assert!(gap >= t.refused_floor, "dial {} came {gap:?} after the refusal before it", i + 2);
    }
    assert_eq!(relay.connections(), 4, "each dial a new connection (A-M3)");

    let closed = tunnel.close(wire::close::REVOKED, "revoked").await;
    let _next = relay.tunnel(Duration::from_secs(5)).await;
    let dials = relay.dials();
    assert!(dials[4].saturating_duration_since(closed) >= t.refused_floor, "REVOKED waits the floor too");
    assert_eq!(relay.connections(), 5);
    let _ = stop.send(());
    let _ = task.await;

    let mut fresh = FakeRelay::start(&pki().relay_a);
    let (stop, task) = spawn(builder(&fresh).source(sources::echo()).build().expect("builds"));
    let tunnel = fresh.tunnel(WAIT).await;
    let closed = tunnel.close(wire::close::NORMAL, "the relay is shutting down").await;
    let _next = fresh.tunnel(WAIT).await;
    let gap = fresh.dials()[1].saturating_duration_since(closed);
    assert!(gap < t.backoff_min.mul_f64(1.25) + Duration::from_millis(100), "NORMAL is transient: {gap:?}");
    assert_eq!(fresh.connections(), 2);
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T14.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnects_double_and_reset_after_a_stable_tunnel() {
    let t = Tuning {
        backoff_min: Duration::from_millis(100),
        backoff_max: Duration::from_millis(1600),
        reset_after: Duration::from_millis(400),
        refused_floor: Duration::from_millis(1600),
        ..quick()
    };
    // The gaps are measured from the fake's end of a tunnel to the next dial: transport and teardown add a
    // little to the worker's own wait.
    let slack = Duration::from_millis(100);
    let mut relay = FakeRelay::start(&pki().relay_a);
    let (stop, task) = spawn(builder(&relay).source(sources::echo()).tuning(t.clone()).build().expect("builds"));
    let mut ends = Vec::new();
    for _ in 0..5 {
        let tunnel = relay.tunnel(WAIT).await;
        ends.push(tunnel.close(wire::close::NORMAL, "drain").await);
    }
    let stable = relay.tunnel(WAIT).await;
    let dials = relay.dials();
    let mut step = t.backoff_min;
    for (i, end) in ends.iter().enumerate() {
        let gap = dials[i + 1].saturating_duration_since(*end);
        assert!(gap >= step.mul_f64(0.75) && gap < step.mul_f64(1.25) + slack, "gap {i}: {gap:?} for a step of {step:?}");
        step = (step * 2).min(t.backoff_max);
    }
    tokio::time::sleep(t.reset_after + Duration::from_millis(100)).await;
    let end = stable.close(wire::close::NORMAL, "drain").await;
    let _next = relay.tunnel(WAIT).await;
    let gap = relay.dials()[6].saturating_duration_since(end);
    assert!(gap >= t.backoff_min.mul_f64(0.75) && gap < t.backoff_min.mul_f64(1.25) + slack, "after a stable tunnel: {gap:?}");
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T15.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pings_get_their_pongs_and_a_silent_relay_is_left() {
    let t = Tuning { idle_timeout: Duration::from_millis(400), ..quick() };
    let mut relay = FakeRelay::start(&pki().relay_a);
    let (stop, task) = spawn(builder(&relay).source(sources::echo()).tuning(t.clone()).build().expect("builds"));
    let mut tunnel = relay.tunnel(WAIT).await;
    tunnel.send(ping(7)).await;
    let silent_from = Instant::now();
    match tunnel.next(WAIT).await {
        Next::Frame(worker_frame::Msg::Pong(p)) => assert_eq!(p.seq, 7),
        other => panic!("the first frame after the catalog: {other:?}"),
    }
    assert!(tunnel.ended(Duration::from_secs(3)).await, "the worker leaves a silent relay");
    let silent_for = silent_from.elapsed();
    assert!(silent_for >= Duration::from_millis(350) && silent_for < Duration::from_secs(2), "{silent_for:?}");
    let _again = relay.tunnel(WAIT).await;
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T16.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_thousand_interleaved_calls_answer_their_own_requests() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let worker = builder(&relay).source(sources::echo()).max_in_flight(64).max_queued(1024).build().expect("builds");
    let (stop, task) = spawn(worker);
    let mut tunnel = relay.tunnel(WAIT).await;
    let sender = tunnel.sender();
    let sending = tokio::spawn(async move {
        for i in 0..1000 {
            sender.send(invoke(&rid(i), "echo", "echo", &format!(r#"{{"text":"msg-{i}"}}"#), 30_000, (0, 0, 0))).await;
            if i % 25 == 0 {
                sender.send(ping(i as u64)).await;
            }
        }
    });
    let sent: HashSet<String> = (0..1000).map(rid).collect();
    let mut calls: HashMap<String, Vec<Chunk>> = HashMap::new();
    let mut finals = 0;
    let until = Instant::now() + Duration::from_secs(60);
    while finals < 1000 {
        match tunnel.next(until.saturating_duration_since(Instant::now())).await {
            Next::Frame(worker_frame::Msg::Chunk(c)) => {
                assert!(sent.contains(&c.request_id), "a chunk for an id never sent: {}", c.request_id);
                if c.r#final {
                    finals += 1;
                }
                calls.entry(c.request_id.clone()).or_default().push(c);
            }
            Next::Frame(worker_frame::Msg::Pong(_)) => {}
            other => panic!("after {finals} finals: {other:?}"),
        }
    }
    sending.await.expect("sent");
    assert_eq!(calls.len(), 1000);
    for i in 0..1000 {
        let chunks = &calls[&rid(i)];
        well_formed(&rid(i), chunks);
        assert_eq!(chunks.iter().filter(|c| c.r#final).count(), 1);
        assert!(code(chunks).is_none(), "{:?}", last(chunks).error);
        assert_eq!(data(chunks), format!(r#"{{"text":"msg-{i}"}}"#).into_bytes(), "call {i} got its own params back");
    }
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T17.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cap_queues_then_refuses_busy() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let sleeper = sources::sleeper(6);
    let worker = builder(&relay).source(sleeper.clone()).max_in_flight(2).max_queued(1).build().expect("builds");
    let (stop, task) = spawn(worker);
    let mut tunnel = relay.tunnel(WAIT).await;
    for i in 0..4 {
        tunnel.send(invoke(&rid(i), "test-sleeper", "get", "{}", 60_000, (0, 0, 0))).await;
    }
    let busy = tunnel.call(&rid(3), WAIT).await;
    assert_eq!(busy.len(), 1);
    assert_eq!(code(&busy), Some(8), "RESOURCE_EXHAUSTED");
    assert_eq!(busy[0].error.as_ref().map(|e| e.message.as_str()), Some("worker busy: 2 calls in flight, 1 queued"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(sleeper.calls().len(), 2, "two run, one waits");
    assert_eq!(sleeper.in_flight(), 2);

    tunnel.send(cancel(&rid(0))).await;
    assert_eq!(code(&tunnel.call(&rid(0), WAIT).await), Some(1));
    let until = Instant::now() + WAIT;
    while sleeper.calls().len() < 3 && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(sleeper.calls().len(), 3, "the queued call starts when a slot frees");
    assert_eq!(sleeper.calls()[2].request_id, rid(2));

    // Two run again (1 and 2): a call queued with a short deadline leaves the queue unstarted.
    let queued_at = Instant::now();
    tunnel.send(invoke(&rid(4), "test-sleeper", "get", "{}", 300, (0, 0, 0))).await;
    let late = tunnel.call(&rid(4), WAIT).await;
    assert_eq!(code(&late), Some(4), "DEADLINE_EXCEEDED");
    assert!(queued_at.elapsed() < Duration::from_secs(2));
    assert_eq!(sleeper.calls().len(), 3, "it never started");
    assert!(sleeper.max_in_flight() <= 2);
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T18.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deadline_cancels_the_source() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let sleeper = sources::sleeper(1);
    let (stop, task) = spawn(builder(&relay).source(sleeper.clone()).build().expect("builds"));
    let mut tunnel = relay.tunnel(WAIT).await;
    let sent = Instant::now();
    tunnel.send(invoke(&rid(1), "test-sleeper", "get", "{}", 200, (0, 0, 0))).await;
    let chunks = tunnel.call(&rid(1), WAIT).await;
    let took = sent.elapsed();
    assert_eq!(chunks.len(), 1);
    assert_eq!(code(&chunks), Some(4));
    assert_eq!(last(&chunks).error.as_ref().map(|e| e.message.as_str()), Some("deadline of 200 ms passed"));
    assert!(took >= Duration::from_millis(100) && took <= Duration::from_millis(1000), "{took:?}");
    assert_eq!(sleeper.cancelled(), 1, "the source saw its cancel");
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T19.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_frame_cancels_the_call_and_answers_once() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let sleeper = sources::sleeper(1);
    let (stop, task) = spawn(builder(&relay).source(sleeper.clone()).build().expect("builds"));
    let mut tunnel = relay.tunnel(WAIT).await;
    tunnel.send(invoke(&rid(1), "test-sleeper", "get", "{}", 60_000, (0, 0, 0))).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(sleeper.in_flight(), 1);
    tunnel.send(cancel(&rid(1))).await;
    let chunks = tunnel.call(&rid(1), WAIT).await;
    assert_eq!((chunks.len(), code(&chunks)), (1, Some(1)), "one final CANCELLED");
    assert_eq!(sleeper.cancelled(), 1, "the source saw its cancel");
    tunnel.send(cancel(&rid(1))).await;
    tunnel.send(cancel(&rid(99))).await;
    let after = tunnel.drain(Duration::from_millis(300)).await;
    assert!(after.is_empty(), "nothing more for the id, nothing for an unknown one: {after:?}");
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T20.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_tunnel_cancels_every_call() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let sleeper = sources::sleeper(5);
    let worker = builder(&relay).source(sleeper.clone()).max_in_flight(3).max_queued(2).build().expect("builds");
    let (stop, task) = spawn(worker);
    let tunnel = relay.tunnel(WAIT).await;
    for i in 0..5 {
        tunnel.send(invoke(&rid(i), "test-sleeper", "get", "{}", 60_000, (0, 0, 0))).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!((sleeper.calls().len(), sleeper.in_flight()), (3, 3));
    let dropped = tunnel.drop_stream();
    let until = dropped + Duration::from_millis(100);
    while sleeper.cancelled() < 3 && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(sleeper.cancelled(), 3, "every running call's token tripped within 100 ms");
    let next = relay.tunnel(WAIT).await;
    assert!(next.catalog.is_some());
    assert_eq!(sleeper.in_flight(), 0, "none of them runs when the next catalog comes");
    assert_eq!(sleeper.calls().len(), 3, "the queued ones never started");
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T21.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn output_is_chunked_capped_and_flagged() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let text = sources::text("test-text", "x".repeat(200 * 1024));
    let json = sources::json("test-json", serde_json::json!({ "blob": "z".repeat(2 << 20) }));
    let empty = sources::text("test-empty", String::new());
    let big_items = RecordingSource::new("test-big", Some(StreamItems::Lines((0..10).map(|i| format!("{i}{}", "y".repeat(30 * 1024))).collect())));
    let rows = RecordingSource::new("test-rows", Some(StreamItems::Lines((0..10).map(|i| format!("row-{i}")).collect())));
    let (feed, fed) = mpsc::unbounded_channel();
    let paced = RecordingSource::new("test-paced", Some(StreamItems::Fed(fed)));
    let crossing = RecordingSource::new("test-crossing", Some(StreamItems::Lines(vec!["a".repeat(60_000), "b".repeat(300_000)])));
    let late_error = RecordingSource::new("test-late-error", Some(StreamItems::Failing(vec!["d".repeat(70_000)], SourceError::Unavailable("backend down".into()))));
    let (feed_big, fed_big) = mpsc::unbounded_channel();
    let blocked = RecordingSource::new("test-blocked", Some(StreamItems::Fed(fed_big)));
    let worker = builder(&relay)
        .source(text)
        .source(json)
        .source(empty)
        .source(big_items.clone())
        .source(rows.clone())
        .source(paced.clone())
        .source(crossing.clone())
        .source(late_error.clone())
        .source(blocked.clone())
        .source(sources::echo())
        .build()
        .expect("builds");
    let (stop, task) = spawn(worker);
    let mut tunnel = relay.tunnel(WAIT).await;

    tunnel.send(invoke(&rid(1), "test-text", "get", "{}", 30_000, (150 * 1024, 0, 0))).await;
    let c = tunnel.call(&rid(1), WAIT).await;
    well_formed(&rid(1), &c);
    assert_eq!(c.iter().map(|c| c.data.len()).collect::<Vec<_>>(), [65_536, 65_536, 22_528]);
    assert!(last(&c).truncated && code(&c).is_none());
    assert!(c.iter().all(|c| c.content_type == wire::CONTENT_TEXT));

    tunnel.send(invoke(&rid(2), "test-json", "get", "{}", 30_000, (1 << 20, 0, 0))).await;
    let c = tunnel.call(&rid(2), WAIT).await;
    assert_eq!(c.len(), 1, "one final chunk");
    assert!(c[0].data.is_empty() && c[0].r#final);
    assert_eq!(code(&c), Some(8), "RESOURCE_EXHAUSTED");
    assert!(c[0].error.as_ref().is_some_and(|e| e.message.contains("over max_bytes 1048576")), "{:?}", c[0].error);
    assert_eq!(c[0].content_type, wire::CONTENT_JSON);

    tunnel.send(invoke(&rid(3), "test-big", "get", "{}", 30_000, (0, 0, 3))).await;
    let c = tunnel.call(&rid(3), WAIT).await;
    well_formed(&rid(3), &c);
    assert_eq!(c.len(), 3, "three chunks");
    assert!(last(&c).truncated && code(&c).is_none(), "the third final and truncated");
    assert_eq!(data(&c).len(), 3 * 65_536);
    assert!(c.iter().all(|c| c.content_type == wire::CONTENT_TEXT));
    assert!(big_items.dropped.load(Ordering::SeqCst), "the stream was dropped");

    tunnel.send(invoke(&rid(4), "test-empty", "get", "{}", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(4), WAIT).await;
    assert_eq!(c.len(), 1);
    assert!(c[0].r#final && c[0].data.is_empty() && !c[0].truncated && c[0].error.is_none());
    assert_eq!(c[0].content_type, wire::CONTENT_TEXT);

    tunnel.send(invoke(&rid(5), "test-rows", "get", "{}", 30_000, (0, 4, 0))).await;
    let c = tunnel.call(&rid(5), WAIT).await;
    well_formed(&rid(5), &c);
    assert_eq!(String::from_utf8(data(&c)).expect("text"), "row-0\nrow-1\nrow-2\nrow-3\n", "exactly 4 lines (A-M9)");
    assert!(last(&c).truncated);
    assert!(rows.dropped.load(Ordering::SeqCst));

    tunnel.send(invoke(&rid(6), "test-paced", "get", "{}", 30_000, (0, 0, 0))).await;
    let feeding = tokio::spawn(async move {
        for i in 0..100 {
            let _ = feed.send(format!("item-{i}"));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let c = tunnel.call(&rid(6), Duration::from_secs(20)).await;
    feeding.await.expect("fed");
    well_formed(&rid(6), &c);
    assert_eq!(c.len(), 2, "one data chunk, then the final (A-M10)");
    assert_eq!(c[0].data.len(), (0..100).map(|i| format!("item-{i}\n").len()).sum::<usize>());
    assert!(c[1].data.is_empty() && !c[1].truncated);

    // An item that crosses the byte cap with slots left: the part that fits goes as chunks of at most
    // CHUNK_MAX, never as one (P-R18).
    tunnel.send(invoke(&rid(7), "test-crossing", "get", "{}", 30_000, (200_000, 0, 0))).await;
    let c = tunnel.call(&rid(7), WAIT).await;
    well_formed(&rid(7), &c);
    assert_eq!(c.iter().map(|c| c.data.len()).collect::<Vec<_>>(), [65_536, 65_536, 65_536, 3_392, 0]);
    assert_eq!(data(&c).len(), 200_000);
    assert!(last(&c).truncated && code(&c).is_none());
    assert!(crossing.dropped.load(Ordering::SeqCst));

    // An `Err` item when only the final chunk's slot is left: what is pending cannot go, and the final chunk
    // says so (WM-R29, WM-R30).
    tunnel.send(invoke(&rid(8), "test-late-error", "get", "{}", 30_000, (0, 0, 2))).await;
    let c = tunnel.call(&rid(8), WAIT).await;
    well_formed(&rid(8), &c);
    assert_eq!(c.iter().map(|c| c.data.len()).collect::<Vec<_>>(), [65_536, 0]);
    assert_eq!(code(&c), Some(14));
    assert!(last(&c).truncated, "the last 4465 bytes stayed unsent");

    // A cancel while the outbound queue is full and most of an item is pending: it goes first, as chunks of
    // at most CHUNK_MAX, then the final CANCELLED (A-M10), and the tunnel stays up.
    tunnel.send(invoke(&rid(9), "test-blocked", "get", "{}", 30_000, (16 << 20, 0, 256))).await;
    let item = "c".repeat(12 << 20);
    let _ = feed_big.send(item.clone());
    let first = match tunnel.next(WAIT).await {
        Next::Frame(worker_frame::Msg::Chunk(c)) => c,
        other => panic!("the first chunk: {other:?}"),
    };
    // The relay reads nothing meanwhile: the worker fills its queue and waits for room.
    tokio::time::sleep(Duration::from_millis(300)).await;
    tunnel.send(cancel(&rid(9))).await;
    let mut c = vec![first];
    c.extend(tunnel.call(&rid(9), WAIT).await);
    well_formed(&rid(9), &c);
    assert_eq!(code(&c), Some(1), "CANCELLED");
    assert_eq!(data(&c).len(), item.len() + 1, "what was pending went first");
    assert!(blocked.dropped.load(Ordering::SeqCst));
    tunnel.send(invoke(&rid(10), "echo", "echo", r#"{"text":"still up"}"#, 30_000, (0, 0, 0))).await;
    assert_eq!(data(&tunnel.call(&rid(10), WAIT).await), br#"{"text":"still up"}"#.to_vec(), "the tunnel stays up");
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T22.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_leaves_unredacted() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let samples: Vec<(String, String)> = [Rule::Jwt, Rule::Dsn, Rule::Pem, Rule::Bearer].into_iter().map(sample).collect();
    let mixed = samples.iter().map(|(text, _)| text.as_str()).collect::<Vec<_>>().join("\n");
    let jwt = &samples[0].0["token ".len()..];
    let dsn_part = "placeholder-1";
    let pem_body = "A".repeat(64);
    let bearer_token = format!("{}-{}", "0".repeat(8), "a".repeat(8));
    let hex = sample(Rule::Hex64).0["key ".len()..].to_string();
    let secrets = [jwt.to_string(), dsn_part.to_string(), pem_body.clone(), bearer_token.clone(), hex.clone()];
    let pem_lines = vec!["-----BEGIN TEST KEY-----".to_string(), pem_body.clone(), "-----END TEST KEY-----".to_string(), "after".to_string()];
    let error_text = format!("upstream answered: Bearer {bearer_token}");
    let plain = Arc::new(ScriptedSource::new(sources::descriptor("test-plain", OutputKind::Text)).with_redactor(Redactor::none()).then(Scripted::Text(mixed.clone())));
    let worker = builder(&relay)
        .source(sources::text("test-mixed", mixed.clone()))
        .source(sources::lines("test-split", pem_lines))
        .source(sources::failing("test-failing", SourceError::Unavailable(error_text)))
        .source(plain)
        .source(sources::json(
            "test-json",
            // Each string is masked on its own. In the JSON text, the escapes `\n` and `\t` glue a letter to
            // the digest and the JWT, and neither rule would mask them there (M-WM52).
            serde_json::json!({ "note": format!("-----BEGIN TEST KEY-----\n{pem_body}"), "digest": format!("\n{hex}"), "jwt": format!("\t{jwt}") }),
        ))
        .build()
        .expect("builds");
    let (stop, task) = spawn(worker);
    let mut tunnel = relay.tunnel(WAIT).await;
    let no_secret = |what: &str, bytes: &[u8]| {
        let text = String::from_utf8_lossy(bytes);
        for s in &secrets {
            assert!(!text.contains(s.as_str()), "{what} holds a secret: {text}");
        }
    };

    tunnel.send(invoke(&rid(1), "test-mixed", "get", "{}", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(1), WAIT).await;
    let got = String::from_utf8(data(&c)).expect("text");
    no_secret("a text", got.as_bytes());
    for mask in ["[redacted:jwt]", "[redacted:dsn]", "[redacted:pem]", "[redacted:bearer]"] {
        assert!(got.contains(mask), "{mask} in {got}");
    }
    assert_eq!(got, Redactor::new().redact(&mixed), "the source's redactor (the default), applied whole");

    tunnel.send(invoke(&rid(2), "test-split", "get", "{}", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(2), WAIT).await;
    let got = String::from_utf8(data(&c)).expect("text");
    no_secret("a stream", got.as_bytes());
    assert!(got.contains("[redacted:pem]") && got.ends_with("after\n"), "{got:?}");

    tunnel.send(invoke(&rid(3), "test-failing", "get", "{}", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(3), WAIT).await;
    let error = last(&c).error.clone().expect("an error");
    assert_eq!(error.code, 14);
    no_secret("an error message", error.message.as_bytes());
    assert!(error.message.contains("[redacted:bearer]"), "{}", error.message);

    tunnel.send(invoke(&rid(4), "test-plain", "get", "{}", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(4), WAIT).await;
    assert_eq!(data(&c), mixed.as_bytes(), "Redactor::none() leaves the text as it is: the hook is the source's");

    tunnel.send(invoke(&rid(5), "test-json", "get", "{}", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(5), WAIT).await;
    let value: serde_json::Value = serde_json::from_slice(&data(&c)).expect("still JSON (A-M11)");
    no_secret("a JSON value", &data(&c));
    assert!(value["note"].as_str().is_some_and(|n| n.contains("[redacted:pem]")), "{value}");
    assert_eq!((value["digest"].as_str(), value["jwt"].as_str()), (Some("\n[redacted:hex64]"), Some("\t[redacted:jwt]")), "each string redacted on its own");
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T23.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_invokes_never_reach_the_source() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let source = sources::json("test-json", serde_json::json!({"ok": true}));
    let (stop, task) = spawn(builder(&relay).source(source.clone()).build().expect("builds"));
    let mut tunnel = relay.tunnel(WAIT).await;
    let big = format!(r#"{{"a":"{}"}}"#, "b".repeat(65_537 - 8));
    assert_eq!(big.len(), 65_537);
    let cases: [(&str, &str, &str, i32); 5] =
        [("test-other", "get", "{}", 5), ("test-json", "put", "{}", 5), ("test-json", "get", "[1]", 3), ("test-json", "get", "nul", 3), ("test-json", "get", &big, 3)];
    for (i, (source_name, op, params, want)) in cases.iter().enumerate() {
        tunnel.send(invoke(&rid(i), source_name, op, params, 30_000, (0, 0, 0))).await;
        let c = tunnel.call(&rid(i), WAIT).await;
        assert_eq!((c.len(), c[0].seq, c[0].data.len()), (1, 0, 0), "case {i}");
        assert_eq!(code(&c), Some(*want), "case {i}: {:?}", c[0].error);
    }
    let long_id = "r".repeat(65);
    tunnel.send(invoke(&long_id, "test-json", "get", "{}", 30_000, (0, 0, 0))).await;
    tunnel.send(invoke(&rid(9), "test-json", "get", "", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(9), WAIT).await;
    assert!(code(&c).is_none(), "{:?}", last(&c).error);
    assert_eq!(tunnel.seen(&long_id), 0, "a request id of 65 bytes gets no answer");
    let more = tunnel.drain(Duration::from_millis(300)).await;
    assert!(more.is_empty(), "nothing more for a refused call, nothing for the long id: {more:?}");
    let calls = source.calls();
    assert_eq!(calls.len(), 1, "only the call with empty params reached the source");
    assert_eq!(calls[0].params, serde_json::json!({}));
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T24.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicate_request_id_is_dropped() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let source = Arc::new(
        ScriptedSource::new(sources::descriptor("test-slow", OutputKind::Json))
            .then(Scripted::Delay(Duration::from_millis(300), Box::new(Scripted::Json(serde_json::json!({"first": true})))))
            .then(Scripted::Json(serde_json::json!({"second": true}))),
    );
    let (stop, task) = spawn(builder(&relay).source(source.clone()).build().expect("builds"));
    let mut tunnel = relay.tunnel(WAIT).await;
    tunnel.send(invoke(&rid(1), "test-slow", "get", "{}", 30_000, (0, 0, 0))).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    tunnel.send(invoke(&rid(1), "test-slow", "get", r#"{"again":1}"#, 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(1), WAIT).await;
    assert_eq!(data(&c), br#"{"first":true}"#.to_vec());
    assert!(tunnel.drain(Duration::from_millis(300)).await.is_empty(), "the duplicate gets no chunk");
    assert_eq!(source.calls().len(), 1);
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T25.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errors_and_panics_become_final_chunks() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let worker = builder(&relay)
        .source(sources::failing("test-failing", SourceError::Unavailable("backend down".into())))
        .source(sources::panicking("test-panic", "panic-text-with-private-data"))
        .source(Arc::new(PanickingSource { descriptor: sources::descriptor("test-sync-panic", OutputKind::Json) }))
        .source(sources::echo())
        .build()
        .expect("builds");
    let (stop, task) = spawn(worker);
    let mut tunnel = relay.tunnel(WAIT).await;
    tunnel.send(invoke(&rid(1), "test-failing", "get", "{}", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(1), WAIT).await;
    let e = last(&c).error.clone().expect("an error");
    assert_eq!((e.code, e.message.as_str()), (14, "backend down"));
    tunnel.send(invoke(&rid(2), "test-panic", "get", "{}", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(2), WAIT).await;
    let e = last(&c).error.clone().expect("an error");
    assert_eq!((e.code, e.message.as_str()), (13, "the source failed"));
    assert!(c.iter().all(|c| !String::from_utf8_lossy(&c.data).contains("panic-text")));
    tunnel.send(invoke(&rid(3), "echo", "echo", r#"{"text":"still here"}"#, 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(3), WAIT).await;
    assert_eq!(data(&c), br#"{"text":"still here"}"#.to_vec(), "the next call on the same tunnel answers");
    // A `call` that panics before it returns its future gets the same one final chunk (WM-R24, LD-WM10).
    tunnel.send(invoke(&rid(4), "test-sync-panic", "get", "{}", 30_000, (0, 0, 0))).await;
    let c = tunnel.call(&rid(4), WAIT).await;
    let e = last(&c).error.clone().expect("an error");
    assert_eq!((c.len(), e.code, e.message.as_str()), (1, 13, "the source failed"));
    tunnel.send(invoke(&rid(5), "echo", "echo", r#"{"text":"after"}"#, 30_000, (0, 0, 0))).await;
    assert_eq!(data(&tunnel.call(&rid(5), WAIT).await), br#"{"text":"after"}"#.to_vec());
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T26.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn frames_out_of_order_end_the_tunnel() {
    let t = quick();
    let mut relay = FakeRelay::start(&pki().relay_a);
    relay.script(&[Script::AfterProof, Script::Accept, Script::AfterProof]);
    let (stop, task) = spawn(builder(&relay).source(sources::echo()).build().expect("builds"));
    // An Invoke before AuthOk.
    let mut before = relay.tunnel(WAIT).await;
    before.send(invoke(&rid(1), "echo", "echo", r#"{"text":"x"}"#, 30_000, (0, 0, 0))).await;
    let sent = Instant::now();
    assert!(before.ended(WAIT).await, "the tunnel ends");
    // A second Challenge after AuthOk.
    let mut after = relay.tunnel(WAIT).await;
    let gap = relay.dials()[1].saturating_duration_since(sent);
    assert!(gap < t.refused_floor, "transient: {gap:?}");
    after.send(relay_frame::Msg::Challenge(ai_env_relay_proto::v1::Challenge { nonce: vec![0; 32], relay_id: "relay-test".into(), protocol: 1 })).await;
    assert!(after.ended(WAIT).await);
    // A frame with no arm before AuthOk.
    let mut unknown = relay.tunnel(WAIT).await;
    unknown.send_unknown().await;
    assert!(unknown.ended(WAIT).await);
    // After AuthOk, a frame with no arm is ignored.
    let mut ok = relay.tunnel(WAIT).await;
    assert!(ok.catalog.is_some());
    ok.send_unknown().await;
    ok.send(invoke(&rid(2), "echo", "echo", r#"{"text":"y"}"#, 30_000, (0, 0, 0))).await;
    let c = ok.call(&rid(2), WAIT).await;
    assert_eq!(data(&c), br#"{"text":"y"}"#.to_vec());
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T27.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_refuses_what_it_cannot_serve() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let refusal = |b: ai_env_worker::WorkerBuilder| b.build().err().expect("refused");
    let echo = || sources::echo();
    assert_eq!(refusal(Worker::builder().relay(common::endpoint(&relay)).signer(common::signer()).source(echo())), BuildError::MissingWorkerId);
    assert_eq!(refusal(builder(&relay).worker_id("A").source(echo())), BuildError::BadWorkerId("A".into()));
    assert_eq!(refusal(Worker::builder().worker_id("w1").signer(common::signer()).source(echo())), BuildError::MissingRelay);
    assert_eq!(refusal(Worker::builder().worker_id("w1").relay(common::endpoint(&relay)).source(echo())), BuildError::MissingSigner);
    assert_eq!(refusal(builder(&relay)), BuildError::NoSource);
    let mut many = builder(&relay);
    for i in 0..65 {
        many = many.source(Arc::new(EchoSource::named(format!("echo-{i}"))));
    }
    assert_eq!(refusal(many), BuildError::TooManySources);
    assert_eq!(refusal(builder(&relay).source(echo()).source(echo())), BuildError::DuplicateSource("echo".into()));
    let invalid = Arc::new(ScriptedSource::new(SourceDescriptor::new("test-invalid", "0.1.0", "No op.")));
    assert!(matches!(refusal(builder(&relay).source(invalid)), BuildError::Descriptor(_)));
    let mut wide = builder(&relay);
    for i in 0..20 {
        let properties: serde_json::Map<String, serde_json::Value> =
            (0..240).map(|p| (format!("field_{p:03}"), serde_json::json!({"type": "string", "description": "x".repeat(16)}))).collect();
        let schema = serde_json::json!({"type": "object", "properties": properties});
        assert!(schema.to_string().len() < 16_384);
        let d = SourceDescriptor::new(format!("test-wide-{i}"), "0.1.0", "A wide test source.").op(OpDescriptor::new("get", "Gets.").params_schema(schema));
        wide = wide.source(Arc::new(ScriptedSource::new(d)));
    }
    match refusal(wide) {
        BuildError::CatalogTooLarge(n) => assert!(n > wire::FRAME_MAX, "{n}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(refusal(builder(&relay).source(echo()).max_in_flight(0)), BuildError::BadLimit("max_in_flight is 1 to 256"));
    assert_eq!(refusal(builder(&relay).source(echo()).max_in_flight(257)), BuildError::BadLimit("max_in_flight is 1 to 256"));
    assert_eq!(refusal(builder(&relay).source(echo()).max_queued(4097)), BuildError::BadLimit("max_queued is 0 to 4096"));
    assert!(builder(&relay).source(echo()).max_in_flight(256).max_queued(4096).build().is_ok());
    let t = Tuning { backoff_min: Duration::from_secs(2), backoff_max: Duration::from_secs(1), refused_floor: Duration::from_secs(3), ..quick() };
    assert!(matches!(refusal(builder(&relay).source(echo()).tuning(t)), BuildError::BadTuning(_)));
    assert!(matches!(refusal(builder(&relay).source(echo()).tuning(Tuning { tick: Duration::ZERO, ..quick() })), BuildError::BadTuning(_)));
    let t = Tuning { refused_floor: Duration::from_millis(10), ..quick() };
    assert!(matches!(refusal(builder(&relay).source(echo()).tuning(t)), BuildError::BadTuning(_)));
    let bound: Arc<dyn Signer> = Arc::new(BoundSigner { key: key() });
    assert_eq!(
        refusal(builder(&relay).worker_id("w1").signer(bound.clone()).source(echo())),
        BuildError::SignerBoundTo { signer: "other".into(), worker: "w1".into() }
    );
    assert!(builder(&relay).worker_id("other").signer(bound).source(echo()).build().is_ok(), "the #[async_trait] signer builds under its own id");

    // `descriptor()`: once at build, never at a reconnect.
    let recording = RecordingSource::new("test-recording", None);
    let worker = builder(&relay).source(recording.clone()).build().expect("builds");
    assert_eq!(recording.descriptors.load(Ordering::SeqCst), 1);
    let (stop, task) = spawn(worker);
    let first = relay.tunnel(WAIT).await;
    let _ = first.close(wire::close::NORMAL, "drain").await;
    let second = relay.tunnel(WAIT).await;
    assert_eq!(second.catalog.as_ref().map(|c| c.sources.len()), Some(1));
    assert_eq!(recording.descriptors.load(Ordering::SeqCst), 1, "the cache serves every catalog");
    let _ = stop.send(());
    let _ = task.await;
}

/// WM-T28.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_returns_and_cancels() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let sleeper = sources::sleeper(2);
    let (stop, task) = spawn(builder(&relay).source(sleeper.clone()).build().expect("builds"));
    let mut tunnel = relay.tunnel(WAIT).await;
    for i in 0..2 {
        tunnel.send(invoke(&rid(i), "test-sleeper", "get", "{}", 60_000, (0, 0, 0))).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(sleeper.in_flight(), 2);
    let asked = Instant::now();
    let _ = stop.send(());
    let returned = tokio::time::timeout(Duration::from_secs(2), task).await.expect("within 2 s").expect("joined");
    assert_eq!(returned, Ok(()));
    assert!(asked.elapsed() < Duration::from_secs(2));
    assert_eq!(sleeper.cancelled(), 2, "both sources saw their cancel");
    assert!(tunnel.ended(Duration::from_secs(1)).await, "the relay saw the stream end");
    let dials = relay.dials().len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(relay.dials().len(), dials, "no dial follows");
}

/// WM-T29.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_reports_and_closes() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let worker = Arc::new(builder(&relay).source(sources::echo()).source(sources::sleeper(0)).build().expect("builds"));
    let checking = {
        let worker = worker.clone();
        tokio::spawn(async move { worker.check().await })
    };
    let mut tunnel = relay.tunnel(WAIT).await;
    tunnel.send(ping(1)).await;
    let report = checking.await.expect("joined").expect("accepted");
    assert_eq!(report.relay_id, fake_relay::RELAY_ID);
    assert_eq!(report.protocol, 1);
    assert_eq!(report.tunnel_id, fake_relay::TUNNEL_ID);
    assert_eq!(report.whitelist_version, fake_relay::WHITELIST_VERSION);
    assert_eq!(report.sources, 2);
    assert!(tunnel.ended(Duration::from_secs(3)).await, "the stream ends");

    let checking = {
        let worker = worker.clone();
        tokio::spawn(async move { worker.check().await })
    };
    let tunnel = relay.tunnel(WAIT).await;
    let _ = tunnel.close(wire::close::CATALOG_REFUSED, "source echo is outside the entry's globs").await;
    let refused = checking.await.expect("joined");
    assert_eq!(refused, Err(WorkerError::Refused { code: 4, reason: "source echo is outside the entry's globs".into() }));
}

/// WM-T30.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sleep_ends_the_tunnel() {
    let t = Tuning { backoff_min: Duration::from_millis(200), tick: Duration::from_millis(50), ..quick() };
    let offset_ms = Arc::new(AtomicI64::new(0));
    let clock = {
        let offset_ms = offset_ms.clone();
        Arc::new(move || {
            let off = offset_ms.load(Ordering::SeqCst);
            let now = SystemTime::now();
            if off >= 0 {
                now + Duration::from_millis(off as u64)
            } else {
                now - Duration::from_millis(off.unsigned_abs())
            }
        })
    };
    let mut relay = FakeRelay::start(&pki().relay_a);
    let worker = builder(&relay).source(sources::echo()).tuning(t.clone()).wall_clock(clock).build().expect("builds");
    let (stop, task) = spawn(worker);
    let mut tunnel = relay.tunnel(WAIT).await;
    let jump = |ms: i64| offset_ms.fetch_add(ms, Ordering::SeqCst);
    jump(t.sleep_jump.as_millis() as i64 - 1000);
    assert!(!tunnel.ended(Duration::from_millis(300)).await, "a jump of sleep_jump less a second ends nothing");
    jump(-40_000);
    assert!(!tunnel.ended(Duration::from_millis(300)).await, "a wall clock that goes back ends nothing");
    jump(t.sleep_jump.as_millis() as i64);
    assert!(tunnel.ended(Duration::from_secs(2)).await, "a sleep ends the tunnel");
    let ended = Instant::now();
    let _next = relay.tunnel(WAIT).await;
    let gap = relay.dials()[1].saturating_duration_since(ended);
    assert!(gap + Duration::from_millis(20) >= t.backoff_min, "the next dial comes after backoff_min: {gap:?}");
    let _ = stop.send(());
    let _ = task.await;
}

/// The fake's tunnels see a worker stop dialing once it is shut down, even mid-backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_during_a_backoff_dials_no_more() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    relay.script(&[Script::RefuseProof]);
    let (stop, task) = spawn(builder(&relay).source(sources::echo()).build().expect("builds"));
    let dials = relay.wait_dials(1, WAIT).await;
    assert_eq!(dials.len(), 1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = stop.send(());
    assert_eq!(tokio::time::timeout(Duration::from_secs(2), task).await.expect("in time").expect("joined"), Ok(()));
    assert!(relay.no_tunnel(Duration::from_millis(500)).await);
    assert_eq!(relay.dials().len(), 1);
}

/// A relay that sends while it reads nothing back fills the worker's outbound queue, then the frames waiting
/// for room (WM-R34); one more ends the tunnel (transient), every call is cancelled, and the worker dials again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_reads_nothing_back_is_left() {
    let mut relay = FakeRelay::start(&pki().relay_a);
    let (feed, fed) = mpsc::unbounded_channel();
    let blocked = RecordingSource::new("test-blocked", Some(StreamItems::Fed(fed)));
    let (stop, task) = spawn(builder(&relay).source(blocked.clone()).build().expect("builds"));
    let mut tunnel = relay.tunnel(WAIT).await;
    tunnel.send(invoke(&rid(1), "test-blocked", "get", "{}", 30_000, (16 << 20, 0, 256))).await;
    let _ = feed.send("c".repeat(12 << 20));
    assert!(matches!(tunnel.next(WAIT).await, Next::Frame(worker_frame::Msg::Chunk(_))), "the stream started");
    // The relay reads nothing from here: the call fills the worker's queue, then each pong waits for room,
    // up to `max_queued` (16) and 32 more of them. Far more pings than that, so a queue slow to fill changes
    // nothing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sender = tunnel.sender();
    for seq in 0..200 {
        sender.send(ping(seq)).await;
    }
    assert!(tunnel.ended(Duration::from_secs(10)).await, "the worker ends the tunnel");
    assert!(blocked.dropped.load(Ordering::SeqCst), "and drops its call");
    let _again = relay.tunnel(WAIT).await;
    let _ = stop.send(());
    let _ = task.await;
}

/// A relay older than this worker's protocol is a refusal (WM-R13, WM-R15).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_relay_is_refused() {
    let t = quick();
    let mut relay = FakeRelay::start(&pki().relay_a);
    relay.script(&[Script::OldProtocol]);
    let (stop, task) = spawn(builder(&relay).source(sources::echo()).build().expect("builds"));
    let _tunnel = relay.tunnel(Duration::from_secs(5)).await;
    let dials = relay.dials();
    assert_eq!(dials.len(), 2);
    assert!(dials[1].saturating_duration_since(dials[0]) >= t.refused_floor, "the refused floor");
    let _ = stop.send(());
    let _ = task.await;
}

