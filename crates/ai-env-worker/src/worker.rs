//! The worker: build, run, check (WM-R13 to WM-R34).

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ai_env_relay_proto::prost::Message;
use ai_env_relay_proto::v1::{worker_frame, Catalog, WorkerFrame};
use ai_env_source::{Cancel, DataSource, Redactor, SourceDescriptor};

use crate::backoff::{self, Backoff, Class};
use crate::endpoint::RelayEndpoint;
use crate::signer::Signer;
use crate::tunnel;

/// The most sources one worker serves (WM-R31).
const SOURCES_MAX: usize = 64;
/// `run_until` returns within this once its shutdown resolved (WM-R32).
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(2);

/// The runtime's timings (WM-R12 to WM-R17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuning {
    /// 10 s: TCP and TLS.
    pub connect_timeout: Duration,
    /// 10 s: each of the Challenge and the AuthOk.
    pub handshake_timeout: Duration,
    /// 15 s: HTTP/2 PING, while idle too.
    pub keepalive_interval: Duration,
    /// 10 s.
    pub keepalive_timeout: Duration,
    /// 75 s without any relay frame.
    pub idle_timeout: Duration,
    /// 1 s.
    pub backoff_min: Duration,
    /// 60 s.
    pub backoff_max: Duration,
    /// 30 s past AuthOk.
    pub reset_after: Duration,
    /// 60 s.
    pub refused_floor: Duration,
    /// 30 s of wall clock ahead of the monotonic clock.
    pub sleep_jump: Duration,
    /// 5 s.
    pub tick: Duration,
}

impl Default for Tuning {
    /// The values above.
    fn default() -> Self {
        Tuning {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(15),
            keepalive_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(75),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            reset_after: Duration::from_secs(30),
            refused_floor: Duration::from_secs(60),
            sleep_jump: Duration::from_secs(30),
            tick: Duration::from_secs(5),
        }
    }
}

/// One source as `build()` cached it: its descriptor and redactor are read once, for the worker's life
/// (WM-R31, P-R39).
pub(crate) struct SourceEntry {
    pub(crate) source: Arc<dyn DataSource>,
    pub(crate) descriptor: SourceDescriptor,
    pub(crate) redactor: Redactor,
}

/// What every tunnel of a worker shares.
pub(crate) struct Inner {
    pub(crate) worker_id: String,
    pub(crate) endpoint: RelayEndpoint,
    pub(crate) signer: Arc<dyn Signer>,
    pub(crate) sources: Vec<Arc<SourceEntry>>,
    pub(crate) by_name: HashMap<String, usize>,
    /// The one `Catalog` frame every tunnel sends after `AuthOk` (WM-R13).
    pub(crate) catalog: WorkerFrame,
    pub(crate) max_in_flight: usize,
    pub(crate) max_queued: usize,
    pub(crate) tuning: Tuning,
    pub(crate) wall: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

/// A built worker.
pub struct Worker {
    inner: Arc<Inner>,
}

/// The builder: `Worker::builder().worker_id(…).relay(…).signer(…).source(…).build()`.
pub struct WorkerBuilder {
    worker_id: Option<String>,
    relay: Option<RelayEndpoint>,
    signer: Option<Arc<dyn Signer>>,
    sources: Vec<Arc<dyn DataSource>>,
    max_in_flight: usize,
    max_queued: usize,
    tuning: Tuning,
    wall: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

impl Worker {
    /// A new builder.
    pub fn builder() -> WorkerBuilder {
        WorkerBuilder {
            worker_id: None,
            relay: None,
            signer: None,
            sources: Vec::new(),
            max_in_flight: 8,
            max_queued: 16,
            tuning: Tuning::default(),
            wall: Arc::new(SystemTime::now),
        }
    }

    /// Its worker id.
    pub fn worker_id(&self) -> &str {
        &self.inner.worker_id
    }

    /// Its signer's public key.
    pub fn public_key(&self) -> crate::keys::PublicKey {
        self.inner.signer.public_key()
    }

    /// Dials, serves and reconnects until `shutdown` resolves (WM-R32): then no new dial, every call
    /// cancelled and the outbound stream ended, within 2 s. It never returns `Err` today.
    pub async fn run_until<F: Future<Output = ()> + Send>(self, shutdown: F) -> Result<(), WorkerError> {
        let stop = Cancel::new();
        let run = run_loop(self.inner.clone(), stop.clone());
        tokio::pin!(run);
        tokio::pin!(shutdown);
        tokio::select! {
            () = &mut shutdown => {}
            () = &mut run => return Ok(()),
        }
        stop.cancel();
        if tokio::time::timeout(SHUTDOWN_BUDGET, run).await.is_err() {
            tracing::warn!("the worker's tunnel did not end within {} ms of the shutdown", SHUTDOWN_BUDGET.as_millis());
        }
        Ok(())
    }

    /// One dial, handshake and catalog, then up to 3 s for a `Close` (its refusal) or the first `Ping`
    /// (accepted); then the stream ends (WM-R33).
    pub async fn check(&self) -> Result<CheckReport, WorkerError> {
        tunnel::check(&self.inner).await
    }
}

/// Dial, serve, wait, again (WM-R15 to WM-R17), until `stop`.
async fn run_loop(inner: Arc<Inner>, stop: Cancel) {
    let mut backoff = Backoff::new(&inner.tuning);
    loop {
        let end = tunnel::serve(&inner, &stop).await;
        if end.class == Class::Shutdown || stop.is_cancelled() {
            return;
        }
        let lived = end.authed_at.map(|at| end.at.saturating_duration_since(at));
        let wait = backoff.after(end.class, lived, end.sleep, backoff::random_u32());
        let class = if end.class == Class::Refused { "refused" } else { "transient" };
        tracing::info!(class, reason = %end.reason, wait_ms = wait.as_millis() as u64, "the relay tunnel ended; the next dial waits");
        // The wait counts from the tunnel's end, its teardown included.
        tokio::select! {
            biased;
            () = stop.cancelled() => return,
            () = tokio::time::sleep_until(end.at + wait) => {}
        }
    }
}

impl WorkerBuilder {
    /// The worker id (WM-R1).
    pub fn worker_id(mut self, id: impl Into<String>) -> Self {
        self.worker_id = Some(id.into());
        self
    }

    /// The relay. Its endpoint needs `RelayEndpoint::ca_pem`: `build()` does not check it, and without it
    /// every dial fails as TLS (`check` says so).
    pub fn relay(mut self, endpoint: RelayEndpoint) -> Self {
        self.relay = Some(endpoint);
        self
    }

    /// The signer.
    pub fn signer(mut self, signer: Arc<dyn Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// One more source.
    pub fn source(mut self, source: Arc<dyn ai_env_source::DataSource>) -> Self {
        self.sources.push(source);
        self
    }

    /// 1..=256, default 8.
    pub fn max_in_flight(mut self, n: usize) -> Self {
        self.max_in_flight = n;
        self
    }

    /// 0..=4096, default 16.
    pub fn max_queued(mut self, n: usize) -> Self {
        self.max_queued = n;
        self
    }

    /// The timings.
    pub fn tuning(mut self, t: Tuning) -> Self {
        self.tuning = t;
        self
    }

    /// The wall clock the sleep check reads (default `SystemTime::now`); hidden, for tests.
    #[doc(hidden)]
    pub fn wall_clock(mut self, f: Arc<dyn Fn() -> SystemTime + Send + Sync>) -> Self {
        self.wall = f;
        self
    }

    /// The worker, or WM-R31's first refusal. Each source's `descriptor()` is called once, here, and cached
    /// for the worker's life: routing and every `Catalog` use the cache.
    pub fn build(self) -> Result<Worker, BuildError> {
        let worker_id = self.worker_id.ok_or(BuildError::MissingWorkerId)?;
        if !crate::globs::valid_id(&worker_id) {
            return Err(BuildError::BadWorkerId(worker_id));
        }
        let endpoint = self.relay.ok_or(BuildError::MissingRelay)?;
        let signer = self.signer.ok_or(BuildError::MissingSigner)?;
        if let Some(bound) = signer.bound_worker_id() {
            if bound != worker_id {
                return Err(BuildError::SignerBoundTo { signer: bound.to_string(), worker: worker_id });
            }
        }
        if self.sources.is_empty() {
            return Err(BuildError::NoSource);
        }
        if self.sources.len() > SOURCES_MAX {
            return Err(BuildError::TooManySources);
        }
        let mut sources = Vec::with_capacity(self.sources.len());
        let mut by_name = HashMap::new();
        for source in self.sources {
            let descriptor = source.descriptor();
            descriptor.validate().map_err(|e| BuildError::Descriptor(e.to_string()))?;
            if by_name.insert(descriptor.name.clone(), sources.len()).is_some() {
                return Err(BuildError::DuplicateSource(descriptor.name));
            }
            let redactor = source.redactor();
            sources.push(Arc::new(SourceEntry { source, descriptor, redactor }));
        }
        let catalog = Catalog { sources: sources.iter().map(|s| crate::map::descriptor(&s.descriptor)).collect() };
        let catalog = WorkerFrame { msg: Some(worker_frame::Msg::Catalog(catalog)) };
        let size = catalog.encoded_len();
        if size > ai_env_source::wire::FRAME_MAX {
            return Err(BuildError::CatalogTooLarge(size));
        }
        if !(1..=256).contains(&self.max_in_flight) {
            return Err(BuildError::BadLimit("max_in_flight is 1 to 256"));
        }
        if self.max_queued > 4096 {
            return Err(BuildError::BadLimit("max_queued is 0 to 4096"));
        }
        check_tuning(&self.tuning)?;
        let inner = Inner {
            worker_id,
            endpoint,
            signer,
            sources,
            by_name,
            catalog,
            max_in_flight: self.max_in_flight,
            max_queued: self.max_queued,
            tuning: self.tuning,
            wall: self.wall,
        };
        Ok(Worker { inner: Arc::new(inner) })
    }
}

/// No zero duration, `backoff_min <= backoff_max`, `refused_floor >= backoff_min` (WM-R31).
fn check_tuning(t: &Tuning) -> Result<(), BuildError> {
    let all = [
        t.connect_timeout,
        t.handshake_timeout,
        t.keepalive_interval,
        t.keepalive_timeout,
        t.idle_timeout,
        t.backoff_min,
        t.backoff_max,
        t.reset_after,
        t.refused_floor,
        t.sleep_jump,
        t.tick,
    ];
    if all.iter().any(Duration::is_zero) {
        return Err(BuildError::BadTuning("a duration is zero"));
    }
    if t.backoff_min > t.backoff_max {
        return Err(BuildError::BadTuning("backoff_min is over backoff_max"));
    }
    if t.refused_floor < t.backoff_min {
        return Err(BuildError::BadTuning("refused_floor is under backoff_min"));
    }
    Ok(())
}

/// What `check` saw (WM-R33).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// The `Challenge`'s relay id.
    pub relay_id: String,
    /// The `Challenge`'s protocol.
    pub protocol: u32,
    /// `AuthOk.tunnel_id`.
    pub tunnel_id: String,
    /// `AuthOk.whitelist_version` (a content hash: printed as 16 hex, review A-L8).
    pub whitelist_version: u64,
    /// The sources in the catalog.
    pub sources: usize,
}

/// `build()`'s refusals (WM-R31).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// No worker id.
    #[error("no worker id")]
    MissingWorkerId,
    /// A worker id WM-R1 refuses.
    #[error("bad worker id: {0}")]
    BadWorkerId(String),
    /// No relay.
    #[error("no relay")]
    MissingRelay,
    /// No signer.
    #[error("no signer")]
    MissingSigner,
    /// No source.
    #[error("no source")]
    NoSource,
    /// More than 64 sources.
    #[error("more than 64 sources")]
    TooManySources,
    /// A descriptor `validate` refuses.
    #[error("descriptor: {0}")]
    Descriptor(String),
    /// A source name twice.
    #[error("source {0} twice")]
    DuplicateSource(String),
    /// The encoded `Catalog` frame is over `wire::FRAME_MAX` (review A-M2): its size in bytes.
    #[error("the catalog is {0} bytes, over the relay's frame limit of 262144")]
    CatalogTooLarge(usize),
    /// A signer bound to another worker id.
    #[error("the signer signs for worker {signer}, not {worker}")]
    SignerBoundTo {
        /// The signer's worker id.
        signer: String,
        /// The builder's worker id.
        worker: String,
    },
    /// A tuning out of its rules.
    #[error("bad tuning: {0}")]
    BadTuning(&'static str),
    /// A limit out of its range.
    #[error("bad limit: {0}")]
    BadLimit(&'static str),
}

/// A tunnel's failure, for `check` and later use (WM-R32, WM-R33).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkerError {
    /// The dial failed.
    #[error("connect: {0}")]
    Connect(String),
    /// TLS failed.
    #[error("tls: {0}")]
    Tls(String),
    /// The handshake broke a rule.
    #[error("handshake: {0}")]
    Handshake(&'static str),
    /// The relay closed the tunnel.
    #[error("refused: close {code}: {reason}")]
    Refused {
        /// `Close.code`.
        code: u32,
        /// `Close.reason`.
        reason: String,
    },
    /// The relay answered UNAUTHENTICATED.
    #[error("unauthenticated")]
    Unauthenticated,
    /// A frame broke the protocol.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The signer failed.
    #[error("signer: {0}")]
    Signer(String),
    /// A budget passed.
    #[error("timeout: {0}")]
    Timeout(&'static str),
}
