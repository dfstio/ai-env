//! One tunnel (WM-R13 to WM-R17, WM-R33): a new TLS connection under its own tonic `Channel` (LD-WM18), one
//! `WorkerTunnel.Open` stream with a bounded outbound queue, the handshake, then the frame loop, which owns
//! the calls (`calls::Calls`) and ends the tunnel in one of WM-R15's three ways.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ai_env_relay_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use ai_env_relay_proto::v1::{relay_frame, worker_frame, AuthProof, Close, Hello, Pong, RelayFrame, WorkerFrame};
use ai_env_source::{wire, Cancel, Code};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Streaming;

use crate::backoff::Class;
use crate::calls::{self, Calls};
use crate::endpoint::Failure;
use crate::signer::AuthChallenge;
use crate::worker::{CheckReport, Inner, WorkerError};

/// The outbound queue: at most 32 frames wait (WM-R13, WM-R34).
pub(crate) const OUTBOUND_FRAMES: usize = 32;
/// The largest relay frame this worker decodes (WM-R12).
const RELAY_FRAME_MAX: usize = 1 << 20;
/// `check` waits this long for a `Close` or the first `Ping` (WM-R33).
const CHECK_WAIT: Duration = Duration::from_secs(3);
/// After the worker ends its stream, this long for the relay's end before the connection is dropped.
const END_WAIT: Duration = Duration::from_millis(500);
/// The two clocks are read one after the other: the sleep check allows this much between the reads.
const CLOCK_SLACK: Duration = Duration::from_millis(1);

/// How and when a tunnel ended.
#[derive(Debug)]
pub(crate) struct End {
    pub(crate) class: Class,
    pub(crate) reason: String,
    /// What `check` reports; none for a shutdown.
    pub(crate) error: Option<WorkerError>,
    /// When `AuthOk` came, if it did (WM-R16's reset).
    pub(crate) authed_at: Option<Instant>,
    pub(crate) at: Instant,
    /// A sleep ended it (WM-R17).
    pub(crate) sleep: bool,
}

impl End {
    fn of(class: Class, error: Option<WorkerError>) -> End {
        let reason = error.as_ref().map_or_else(|| "shutdown".to_string(), ToString::to_string);
        End { class, reason, error, authed_at: None, at: Instant::now(), sleep: false }
    }

    fn shutdown() -> End {
        End::of(Class::Shutdown, None)
    }

    fn transient(error: WorkerError) -> End {
        End::of(Class::Transient, Some(error))
    }

    fn refused(error: WorkerError) -> End {
        End::of(Class::Refused, Some(error))
    }

    /// `Close`: `REVOKED`, `SUPERSEDED`, `PROTOCOL` and `CATALOG_REFUSED` are refusals; `NORMAL`,
    /// `PING_TIMEOUT`, `STALE` and any other code are transient (WM-R15, P-R16).
    fn of_close(c: Close) -> End {
        let refusal = matches!(c.code, wire::close::REVOKED | wire::close::SUPERSEDED | wire::close::PROTOCOL | wire::close::CATALOG_REFUSED);
        let error = WorkerError::Refused { code: c.code, reason: c.reason };
        if refusal {
            End::refused(error)
        } else {
            End::transient(error)
        }
    }

    /// A gRPC status: UNAUTHENTICATED is a refusal (P-R9); any other ends the stream as transient.
    fn of_status(status: &tonic::Status) -> End {
        match status.code() {
            tonic::Code::Unauthenticated => End::refused(WorkerError::Unauthenticated),
            _ => End::transient(WorkerError::Connect(format!("the stream ended: {}", status.message()))),
        }
    }

    fn sleep() -> End {
        End { sleep: true, ..End::transient(WorkerError::Timeout("a sleep: the wall clock ran ahead")) }
    }

    fn authed(mut self, at: Option<Instant>) -> End {
        self.authed_at = at;
        self
    }
}

/// A tunnel past its `AuthOk` and `Catalog`.
pub(crate) struct Established {
    channel: Channel,
    tx: mpsc::Sender<WorkerFrame>,
    inbound: Streaming<RelayFrame>,
    report: CheckReport,
    authed_at: Instant,
}

/// One tunnel, served until it ends (WM-R15); every call is cancelled before this returns (WM-R23).
pub(crate) async fn serve(inner: &Arc<Inner>, stop: &Cancel) -> End {
    let mut est = match establish(inner, stop).await {
        Ok(est) => est,
        Err(end) => return end,
    };
    tracing::info!(relay_id = %est.report.relay_id, tunnel_id = %est.report.tunnel_id, sources = est.report.sources, "the relay tunnel is up");
    let mut calls = Calls::new(inner.clone(), est.tx.clone());
    let end = frame_loop(inner, &mut est.inbound, &mut calls, stop).await;
    calls.end().await;
    let authed_at = est.authed_at;
    finish(est).await;
    end.authed(Some(authed_at))
}

/// WM-R33: one tunnel, then up to 3 s for a refusal or the first `Ping`, then the stream ends.
pub(crate) async fn check(inner: &Arc<Inner>) -> Result<CheckReport, WorkerError> {
    let stop = Cancel::new();
    let mut est = establish(inner, &stop).await.map_err(|end| end.error.unwrap_or(WorkerError::Timeout("shutdown")))?;
    let verdict = verdict(&mut est).await;
    let report = est.report.clone();
    finish(est).await;
    verdict.map(|()| report)
}

/// `check`'s wait after the catalog: a `Ping` (answered) accepts, a `Close` refuses; a call is answered
/// `UNAVAILABLE` (a check serves none); nothing within 3 s accepts.
async fn verdict(est: &mut Established) -> Result<(), WorkerError> {
    let until = Instant::now() + CHECK_WAIT;
    loop {
        let frame = match tokio::time::timeout_at(until, est.inbound.message()).await {
            Err(_) => return Ok(()),
            Ok(Err(status)) => return Err(End::of_status(&status).error.unwrap_or(WorkerError::Unauthenticated)),
            Ok(Ok(None)) => return Err(WorkerError::Protocol("the relay ended the stream without a close".into())),
            Ok(Ok(Some(frame))) => frame,
        };
        match frame.msg {
            Some(relay_frame::Msg::Ping(p)) => {
                let _ = est.tx.send(pong(p.seq)).await;
                return Ok(());
            }
            Some(relay_frame::Msg::Close(c)) => return Err(WorkerError::Refused { code: c.code, reason: c.reason }),
            Some(relay_frame::Msg::Invoke(inv)) => {
                if calls::valid_request_id(&inv.request_id) {
                    let _ = est.tx.send(calls::refusal(&inv.request_id, Code::Unavailable, "this worker is running check and serves no call")).await;
                }
            }
            Some(relay_frame::Msg::Challenge(_)) => return Err(WorkerError::Protocol("a second challenge".into())),
            Some(relay_frame::Msg::AuthOk(_)) => return Err(WorkerError::Protocol("a second auth_ok".into())),
            Some(relay_frame::Msg::Cancel(_)) | None => {}
        }
    }
}

/// The worker's end of a stream: no more frame from it (the relay sees the stream end), a short wait for
/// the relay's end, then the connection is dropped with its channel (LD-WM18).
async fn finish(est: Established) {
    let Established { channel, tx, mut inbound, .. } = est;
    drop(tx);
    let _ = tokio::time::timeout(END_WAIT, async { while let Ok(Some(_)) = inbound.message().await {} }).await;
    drop(inbound);
    drop(channel);
}

/// `fut` unless `stop` fires first (then a shutdown).
async fn until_stop<T>(stop: &Cancel, fut: impl std::future::Future<Output = Result<T, End>>) -> Result<T, End> {
    tokio::select! {
        biased;
        () = stop.cancelled() => Err(End::shutdown()),
        r = fut => r,
    }
}

/// A new connection and its own channel (WM-R12, WM-R13): the dial and TLS within `connect_timeout`, then
/// HTTP/2 over that one connection. The channel's connector hands out this connection once: tonic never
/// dials again behind the worker's back (A-M3).
async fn connect(inner: &Inner) -> Result<Channel, End> {
    let t = &inner.tuning;
    let tls = inner.endpoint.connect(t.connect_timeout).await.map_err(|f| match f {
        Failure::Dial(e) => End::transient(WorkerError::Connect(e)),
        Failure::Tls(e) => End::transient(WorkerError::Tls(e)),
        Failure::Timeout => End::transient(WorkerError::Timeout("connect")),
    })?;
    let slot = Arc::new(Mutex::new(Some(TokioIo::new(tls))));
    let connector = tower::service_fn(move |_: ai_env_relay_proto::tonic::codegen::http::Uri| {
        let io = slot.lock().ok().and_then(|mut s| s.take());
        async move { io.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "this tunnel's connection is gone")) }
    });
    let endpoint = Endpoint::from_shared(inner.endpoint.origin())
        .map_err(|e| End::transient(WorkerError::Connect(format!("the relay's origin: {e}"))))?
        .http2_keep_alive_interval(t.keepalive_interval)
        .keep_alive_timeout(t.keepalive_timeout)
        .keep_alive_while_idle(true);
    match tokio::time::timeout(t.connect_timeout, endpoint.connect_with_connector(connector)).await {
        Ok(Ok(channel)) => Ok(channel),
        Ok(Err(e)) => Err(End::transient(WorkerError::Connect(format!("HTTP/2: {e}")))),
        Err(_) => Err(End::transient(WorkerError::Timeout("connect"))),
    }
}

/// The arm of the next frame before `AuthOk`, within `budget`: the stream's end, a status, a frame with no
/// arm (WM-R14) and the budget's end each end the tunnel.
async fn handshake_frame(inbound: &mut Streaming<RelayFrame>, budget: Duration, what: &'static str) -> Result<relay_frame::Msg, End> {
    match tokio::time::timeout(budget, inbound.message()).await {
        Err(_) => Err(End::transient(WorkerError::Timeout(what))),
        Ok(Err(status)) => Err(End::of_status(&status)),
        Ok(Ok(None)) => Err(End::transient(WorkerError::Protocol(format!("the relay ended the stream before the {what}")))),
        Ok(Ok(Some(RelayFrame { msg: None }))) => Err(End::transient(WorkerError::Protocol(format!("a frame this worker does not know before the {what}")))),
        Ok(Ok(Some(RelayFrame { msg: Some(m) }))) => Ok(m),
    }
}

/// The name of a relay frame's arm, for errors.
fn arm(m: &relay_frame::Msg) -> &'static str {
    match m {
        relay_frame::Msg::Challenge(_) => "a challenge",
        relay_frame::Msg::AuthOk(_) => "an auth_ok",
        relay_frame::Msg::Invoke(_) => "an invoke",
        relay_frame::Msg::Cancel(_) => "a cancel",
        relay_frame::Msg::Ping(_) => "a ping",
        relay_frame::Msg::Close(_) => "a close",
    }
}

/// One frame into the outbound queue, during the handshake.
async fn send(tx: &mpsc::Sender<WorkerFrame>, msg: worker_frame::Msg) -> Result<(), End> {
    tx.send(WorkerFrame { msg: Some(msg) }).await.map_err(|_| End::transient(WorkerError::Connect("the stream closed during the handshake".into())))
}

/// WM-R13: Challenge, Hello, the signature, AuthProof, AuthOk, then the one Catalog.
async fn establish(inner: &Inner, stop: &Cancel) -> Result<Established, End> {
    let t = &inner.tuning;
    let channel = until_stop(stop, connect(inner)).await?;
    let mut client = WorkerTunnelClient::new(channel.clone()).max_decoding_message_size(RELAY_FRAME_MAX).max_encoding_message_size(wire::FRAME_MAX);
    let (tx, rx) = mpsc::channel(OUTBOUND_FRAMES);
    let open = async {
        match tokio::time::timeout(t.handshake_timeout, client.open(ReceiverStream::new(rx))).await {
            Err(_) => Err(End::transient(WorkerError::Timeout("open"))),
            Ok(Err(status)) => Err(End::of_status(&status)),
            Ok(Ok(response)) => Ok(response.into_inner()),
        }
    };
    let mut inbound = until_stop(stop, open).await?;

    let challenge = match until_stop(stop, handshake_frame(&mut inbound, t.handshake_timeout, "challenge")).await? {
        relay_frame::Msg::Challenge(c) => c,
        relay_frame::Msg::Close(c) => return Err(End::of_close(c)),
        other => return Err(End::transient(WorkerError::Protocol(format!("{} before the challenge", arm(&other))))),
    };
    if challenge.nonce.len() != wire::NONCE_LEN {
        return Err(End::transient(WorkerError::Handshake("the challenge's nonce is not 32 bytes")));
    }
    if !crate::globs::valid_relay_id(&challenge.relay_id) {
        return Err(End::transient(WorkerError::Handshake("the challenge's relay id is not a name")));
    }
    if challenge.protocol < crate::PROTOCOL {
        return Err(End::refused(WorkerError::Protocol(format!("the relay speaks protocol {}, older than this worker's {}", challenge.protocol, crate::PROTOCOL))));
    }
    if inner.endpoint.expected_relay_id().is_some_and(|want| want != challenge.relay_id) {
        return Err(End::transient(WorkerError::Handshake("the challenge names another relay than the expected one")));
    }

    let public_key = inner.signer.public_key();
    let hello = Hello {
        worker_id: inner.worker_id.clone(),
        alg: inner.signer.alg().wire() as i32,
        public_key: public_key.bytes().to_vec(),
        protocol: crate::PROTOCOL,
        sdk_version: crate::SDK_VERSION.to_string(),
    };
    send(&tx, worker_frame::Msg::Hello(hello)).await?;
    let auth = AuthChallenge { relay_id: challenge.relay_id.clone(), nonce: challenge.nonce.clone(), worker_id: inner.worker_id.clone(), protocol: crate::PROTOCOL };
    let sign = async {
        match tokio::time::timeout(t.handshake_timeout, inner.signer.sign_worker_auth(&auth)).await {
            Err(_) => Err(End::transient(WorkerError::Timeout("the signer"))),
            Ok(Err(e)) if e.is_refusal() => Err(End::refused(WorkerError::Signer(e.to_string()))),
            Ok(Err(e)) => Err(End::transient(WorkerError::Signer(e.to_string()))),
            Ok(Ok(signature)) => Ok(signature),
        }
    };
    let signature = until_stop(stop, sign).await?;
    send(&tx, worker_frame::Msg::AuthProof(AuthProof { signature: signature.to_vec() })).await?;

    let ok = match until_stop(stop, handshake_frame(&mut inbound, t.handshake_timeout, "auth_ok")).await? {
        relay_frame::Msg::AuthOk(ok) => ok,
        relay_frame::Msg::Close(c) => return Err(End::of_close(c)),
        other => return Err(End::transient(WorkerError::Protocol(format!("{} before the auth_ok", arm(&other))))),
    };
    let authed_at = Instant::now();
    if let Err(end) = until_stop(stop, async { tx.send(inner.catalog.clone()).await.map_err(|_| End::transient(WorkerError::Connect("the stream closed before the catalog".into()))) }).await {
        return Err(end.authed(Some(authed_at)));
    }
    let report = CheckReport {
        relay_id: challenge.relay_id,
        protocol: challenge.protocol,
        tunnel_id: ok.tunnel_id,
        whitelist_version: ok.whitelist_version,
        sources: inner.sources.len(),
    };
    Ok(Established { channel, tx, inbound, report, authed_at })
}

fn pong(seq: u64) -> WorkerFrame {
    WorkerFrame { msg: Some(worker_frame::Msg::Pong(Pong { seq })) }
}

/// After `AuthOk` (WM-R14, WM-R17): each frame, pings answered at once, the idle timer and the sleep check.
async fn frame_loop(inner: &Inner, inbound: &mut Streaming<RelayFrame>, calls: &mut Calls, stop: &Cancel) -> End {
    let t = &inner.tuning;
    let mut last_frame = Instant::now();
    let mut tick = tokio::time::interval_at(Instant::now() + t.tick, t.tick);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let (mut mono, mut wall) = (Instant::now(), (inner.wall)());
    loop {
        if calls.overflowed() {
            // WM-R34: the outbound queue and the frames waiting for room are full; the relay reads nothing back.
            return End::transient(WorkerError::Protocol("the relay reads nothing back: the worker's frames found no room".into()));
        }
        let idle_at = last_frame + t.idle_timeout;
        let queued = calls.next_queued_deadline();
        let queued_at = queued.unwrap_or(idle_at);
        tokio::select! {
            biased;
            () = stop.cancelled() => return End::shutdown(),
            Some(id) = calls.next_done() => calls.finished(&id),
            frame = inbound.message() => {
                last_frame = Instant::now();
                match frame {
                    Err(status) => return End::of_status(&status),
                    Ok(None) => return End::transient(WorkerError::Connect("the relay ended the stream".into())),
                    Ok(Some(RelayFrame { msg: None })) => tracing::debug!("ignored a relay frame this worker does not know"),
                    Ok(Some(RelayFrame { msg: Some(m) })) => match m {
                        relay_frame::Msg::Ping(p) => calls.send_now(pong(p.seq)),
                        relay_frame::Msg::Invoke(inv) => calls.invoke(inv, last_frame),
                        relay_frame::Msg::Cancel(c) => calls.cancel(&c.request_id),
                        relay_frame::Msg::Close(c) => return End::of_close(c),
                        relay_frame::Msg::Challenge(_) => return End::transient(WorkerError::Protocol("a second challenge".into())),
                        relay_frame::Msg::AuthOk(_) => return End::transient(WorkerError::Protocol("a second auth_ok".into())),
                    },
                }
            }
            () = tokio::time::sleep_until(idle_at) => return End::transient(WorkerError::Timeout("idle: no relay frame")),
            _ = tick.tick() => {
                let (now_mono, now_wall) = (Instant::now(), (inner.wall)());
                let ran = now_mono.saturating_duration_since(mono);
                // A wall clock that went back says nothing; one that ran `sleep_jump` ahead is a sleep.
                let slept = now_wall.duration_since(wall).is_ok_and(|w| w.saturating_sub(ran) + CLOCK_SLACK >= t.sleep_jump);
                (mono, wall) = (now_mono, now_wall);
                if slept {
                    return End::sleep();
                }
            }
            () = tokio::time::sleep_until(queued_at), if queued.is_some() => calls.expire_queued(Instant::now()),
        }
    }
}
