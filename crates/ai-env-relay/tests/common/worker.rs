//! The test worker: a `WorkerTunnel.Open` stream driven frame by frame, or served by a script that answers
//! `Invoke`s (echo, stream, silence) and records every frame the relay sends.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ai_env_relay_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use ai_env_relay_proto::v1::{
    relay_frame, worker_frame, AuthOk, AuthProof, Cancel, Catalog, Challenge, Chunk, Close, Error, Hello, Invoke, Pong, RelayFrame, SigAlg,
    SourceDescriptor, WorkerFrame,
};
use ai_env_worker::keys::SigningKey;
use tokio::sync::{mpsc, Notify};
use tonic::transport::Channel;

use super::rig::{Link, Rig};

/// The longest any single read waits (on tokio's clock) before the test fails.
pub const PATIENCE: Duration = Duration::from_secs(120);

/// A Hello of a seed's key.
pub fn hello(worker_id: &str, seed: u8) -> Hello {
    let key = SigningKey::from_seed(&[seed; 32]).unwrap().public_key();
    Hello { worker_id: worker_id.into(), alg: SigAlg::Ed25519 as i32, public_key: key.bytes().to_vec(), protocol: 1, sdk_version: "0.1.0".into() }
}

/// The proof of `hello` for `challenge`, signed with a seed's key.
pub fn proof(challenge: &Challenge, h: &Hello, seed: u8) -> AuthProof {
    let t = ai_env_source::wire::transcript(&challenge.relay_id, &challenge.nonce, &h.worker_id, h.alg as u32, &h.public_key, h.protocol);
    AuthProof { signature: SigningKey::from_seed(&[seed; 32]).unwrap().sign(&t).to_vec() }
}

/// One worker frame.
pub fn wf(msg: worker_frame::Msg) -> WorkerFrame {
    WorkerFrame { msg: Some(msg) }
}

/// A data chunk.
pub fn data(request_id: &str, seq: u64, bytes: Vec<u8>, last: bool) -> Chunk {
    Chunk { request_id: request_id.into(), seq, data: bytes, content_type: "application/json".into(), r#final: last, error: None, truncated: false }
}

/// An error chunk.
pub fn failure(request_id: &str, seq: u64, code: i32, message: &str) -> Chunk {
    Chunk { request_id: request_id.into(), seq, data: Vec::new(), content_type: String::new(), r#final: true, error: Some(Error { code, message: message.into() }), truncated: false }
}

/// A tunnel opened by hand.
pub struct TestWorker {
    pub out: mpsc::Sender<WorkerFrame>,
    pub inbound: tonic::Streaming<RelayFrame>,
    pub challenge: Challenge,
    pub channel: Channel,
    pub link: Option<Link>,
}

impl TestWorker {
    /// Opens a tunnel on a new connection and reads the Challenge, before sending anything.
    pub async fn open(rig: &Rig) -> TestWorker {
        let (channel, link) = rig.public_channel().await;
        let mut w = TestWorker::open_on(channel).await.expect("the relay answers Open");
        w.link = Some(link);
        w
    }

    /// Opens a tunnel on `channel` and reads its first frame, which must be the Challenge.
    pub async fn open_on(channel: Channel) -> Result<TestWorker, tonic::Status> {
        let (out, rx) = mpsc::channel(256);
        let mut client = WorkerTunnelClient::new(channel.clone()).max_decoding_message_size(1 << 20);
        let mut inbound = client.open(tokio_stream::wrappers::ReceiverStream::new(rx)).await?.into_inner();
        let first = tokio::time::timeout(PATIENCE, inbound.message()).await.expect("the Challenge in time")?;
        let challenge = match first.and_then(|f| f.msg) {
            Some(relay_frame::Msg::Challenge(c)) => c,
            other => panic!("the first frame is the Challenge, not {other:?}"),
        };
        Ok(TestWorker { out, inbound, challenge, channel, link: None })
    }

    /// Sends one frame.
    pub async fn send(&self, msg: worker_frame::Msg) {
        self.out.send(wf(msg)).await.expect("the request stream is open");
    }

    /// The next relay frame, or the stream's end (Ok(None)) or status.
    pub async fn next(&mut self) -> Result<Option<RelayFrame>, tonic::Status> {
        tokio::time::timeout(PATIENCE, self.inbound.message()).await.expect("a relay frame in time")
    }

    /// Every frame until the stream ends, and how it ended (status 0, or the status).
    pub async fn rest(&mut self) -> (Vec<RelayFrame>, Result<(), tonic::Status>) {
        let mut seen = Vec::new();
        loop {
            match self.next().await {
                Ok(Some(f)) => seen.push(f),
                Ok(None) => return (seen, Ok(())),
                Err(s) => return (seen, Err(s)),
            }
        }
    }

    /// The status the stream ends with, skipping frames (pings and the like).
    pub async fn end(&mut self) -> Result<Vec<RelayFrame>, tonic::Status> {
        let (seen, end) = self.rest().await;
        end.map(|()| seen)
    }

    /// The Close this tunnel gets (frames before it skipped), and that the stream then ends with status 0.
    pub async fn close(&mut self) -> Close {
        let frames = self.end().await.expect("a Close then status 0");
        frames
            .into_iter()
            .find_map(|f| match f.msg {
                Some(relay_frame::Msg::Close(c)) => Some(c),
                _ => None,
            })
            .expect("a Close frame")
    }

    /// Hello and AuthProof of `worker_id` with a seed's key; the AuthOk, or the status that refused it.
    pub async fn authenticate(&mut self, worker_id: &str, seed: u8) -> Result<AuthOk, tonic::Status> {
        let h = hello(worker_id, seed);
        let p = proof(&self.challenge, &h, seed);
        self.send(worker_frame::Msg::Hello(h)).await;
        self.send(worker_frame::Msg::AuthProof(p)).await;
        match self.next().await? {
            Some(RelayFrame { msg: Some(relay_frame::Msg::AuthOk(ok)) }) => Ok(ok),
            other => panic!("expected AuthOk, got {other:?}"),
        }
    }

    /// Sends a catalog.
    pub async fn register(&self, sources: Vec<SourceDescriptor>) {
        self.send(worker_frame::Msg::Catalog(Catalog { sources })).await;
    }

    /// Opens, authenticates and registers; returns once the relay routes the tunnel.
    pub async fn connect(rig: &Rig, worker_id: &str, seed: u8, sources: Vec<SourceDescriptor>) -> TestWorker {
        let before = rig.app.snapshot().sources_live;
        let n = sources.len() as u64;
        let mut w = TestWorker::open(rig).await;
        w.authenticate(worker_id, seed).await.expect("authenticated");
        w.register(sources).await;
        rig.until(PATIENCE, "the catalog installed", |r| r.app.snapshot().sources_live >= before + n).await;
        w
    }

    /// Serves the tunnel with `script` in a task; the handle records what the relay sent.
    pub fn serve(self, script: Script) -> Served {
        let log = Arc::new(Mutex::new(Recorded::default()));
        let changed = Arc::new(Notify::new());
        let TestWorker { out, mut inbound, channel, link, .. } = self;
        let task = {
            let (log, changed, out) = (Arc::clone(&log), Arc::clone(&changed), out.clone());
            tokio::spawn(async move {
                loop {
                    let next = inbound.message().await;
                    let msg = match next {
                        Ok(Some(f)) => f.msg,
                        Ok(None) => {
                            log.lock().unwrap().ended = Some(Ok(()));
                            changed.notify_waiters();
                            break;
                        }
                        Err(s) => {
                            log.lock().unwrap().ended = Some(Err(s.code()));
                            changed.notify_waiters();
                            break;
                        }
                    };
                    match msg {
                        Some(relay_frame::Msg::Ping(p)) => {
                            log.lock().unwrap().pings.push(p.seq);
                            if script.pong {
                                let _ = out.send(wf(worker_frame::Msg::Pong(Pong { seq: p.seq }))).await;
                            }
                        }
                        Some(relay_frame::Msg::Invoke(inv)) => {
                            log.lock().unwrap().invokes.push(inv.clone());
                            (script.on_invoke)(inv, out.clone());
                        }
                        Some(relay_frame::Msg::Cancel(c)) => log.lock().unwrap().cancels.push(c),
                        Some(relay_frame::Msg::Close(c)) => log.lock().unwrap().closes.push(c),
                        _ => {}
                    }
                    changed.notify_waiters();
                }
            })
        };
        Served { log, changed, out, channel, link, task }
    }
}

/// How a served worker answers.
pub struct Script {
    pub pong: bool,
    pub on_invoke: Box<dyn Fn(Invoke, mpsc::Sender<WorkerFrame>) + Send + Sync>,
}

impl Script {
    /// Answers every Invoke with one final chunk: `{"worker":<id>,"params":<params>}`.
    pub fn echo(worker_id: &str) -> Script {
        let id = worker_id.to_string();
        Script {
            pong: true,
            on_invoke: Box::new(move |inv, out| {
                let body = echo_body(&id, &inv.params_json);
                let rid = inv.request_id.clone();
                tokio::spawn(async move {
                    let _ = out.send(wf(worker_frame::Msg::Chunk(data(&rid, 0, body, true)))).await;
                });
            }),
        }
    }

    /// Never answers an Invoke (pings still answered).
    pub fn silent() -> Script {
        Script { pong: true, on_invoke: Box::new(|_, _| {}) }
    }

    /// Answers with whatever `f` sends.
    pub fn with(f: impl Fn(Invoke, mpsc::Sender<WorkerFrame>) + Send + Sync + 'static) -> Script {
        Script { pong: true, on_invoke: Box::new(f) }
    }
}

/// The echo body.
pub fn echo_body(worker_id: &str, params: &[u8]) -> Vec<u8> {
    let params: serde_json::Value = serde_json::from_slice(params).unwrap_or(serde_json::Value::Null);
    serde_json::to_vec(&serde_json::json!({ "worker": worker_id, "params": params })).unwrap()
}

/// What a served worker saw.
#[derive(Default)]
pub struct Recorded {
    pub invokes: Vec<Invoke>,
    pub cancels: Vec<Cancel>,
    pub closes: Vec<Close>,
    pub pings: Vec<u64>,
    pub ended: Option<Result<(), tonic::Code>>,
}

/// A served worker.
pub struct Served {
    pub log: Arc<Mutex<Recorded>>,
    changed: Arc<Notify>,
    pub out: mpsc::Sender<WorkerFrame>,
    pub channel: Channel,
    pub link: Option<Link>,
    pub task: tokio::task::JoinHandle<()>,
}

impl Served {
    /// Waits (on tokio's clock) until `f` holds of what it saw.
    pub async fn until(&self, what: &str, f: impl Fn(&Recorded) -> bool) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let notified = self.changed.notified();
            if f(&self.log.lock().unwrap()) {
                return;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                assert!(f(&self.log.lock().unwrap()), "timed out waiting for {what}");
                return;
            }
        }
    }

    /// Sends one frame.
    pub async fn send(&self, msg: worker_frame::Msg) {
        self.out.send(wf(msg)).await.expect("the request stream is open");
    }

    pub fn invokes(&self) -> Vec<Invoke> {
        self.log.lock().unwrap().invokes.clone()
    }

    pub fn cancels(&self) -> Vec<Cancel> {
        self.log.lock().unwrap().cancels.clone()
    }

    pub fn closes(&self) -> Vec<Close> {
        self.log.lock().unwrap().closes.clone()
    }

    /// Waits for the n-th Invoke and returns it.
    pub async fn invoke(&self, n: usize) -> Invoke {
        self.until(&format!("invoke {n}"), |r| r.invokes.len() > n).await;
        self.invokes()[n].clone()
    }

    /// Waits for a Close and returns it.
    pub async fn closed(&self) -> Close {
        self.until("a Close", |r| !r.closes.is_empty()).await;
        self.closes()[0].clone()
    }
}
