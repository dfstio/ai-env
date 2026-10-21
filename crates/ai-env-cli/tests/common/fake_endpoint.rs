//! The tests' MicroVM endpoint for `/agent` (plan S6 D4, W4): listens on
//! 127.0.0.1, checks each upgrade's `x-aws-proxy-auth` against the
//! file-backed fake's state (`FakeState::endpoint_check`, which also resumes
//! a SUSPENDED VM with auto-resume), can answer scripted 403/429 (with and
//! without `Retry-After`)/502, cut sockets (after a while, or before a
//! given frame reaches the client), hold a request a while (a slow upgrade),
//! until the test releases it, or while it posts `/resume` like the
//! platform, and otherwise forwards the connection to a native or Docker
//! shim with the `x-aws-proxy-*` headers stripped (the platform strips them
//! too). Every attempt is recorded with the status the client got. Its own
//! thread runs a current-thread runtime, so sync and async tests use it
//! alike. Shared by `tests/shim_bridge_local.rs`, `tests/vm/exec_cli.rs` and `tests/docker_exec.rs` (`#[path]`),
//! and by the remote rig as `common::fake_endpoint` (S8, `tests/common/remote.rs`).
//!
//! Opt-in (S7, [`FakeEndpoint::start_platform`]): the endpoint also plays the
//! platform's hook client for the shim, so a test no longer posts the hooks
//! itself. Auto-run: a VM's first request that passes the check is preceded
//! by `/run` with the payload its RunMicrovm carried (from the fake's
//! `specs`). The hook bridge: as that VM moves in the fake's state, the shim
//! gets `/suspend`, `/resume` and `/terminate`, in the order the fake
//! recorded the calls — so a suspend and a resume between two looks still
//! reach the shim, as the platform posts each before the VM moves on — then
//! whatever moved without a call (an auto-resume by the check, a test's own
//! edit). The fake's rules are mirrored (a suspend only from running, a
//! resume only from suspended), so a call the fake refused for the VM's state
//! is no move. A terminate is replayed only when the VM is terminating or
//! gone at that look (one that took effect never reverts), so one refused by
//! a scripted failure is never posted. A suspend or resume refused by a
//! scripted failure looks like one undone since (the fake records each call
//! before its failure): it is still posted, and the look at the state that
//! follows posts the move back, so the shim gets both hooks. Before a request
//! is checked, every hook the fake's state owes any VM has been answered (one
//! look for all VMs: a request to one VM also waits for another's hooks,
//! which the platform never does); between requests the bridge looks every
//! [`BRIDGE_TICK`] (a test can stop that, [`FakeEndpoint::ticking`]). One
//! shim stands for one VM: a second VM's `/run` gets the shim's 409.
//!
//! Per VM (S10, [`FakeEndpoint::start_per_vm`]): each VM gets listeners of
//! its own, a shim and a disk, built by the test's [`VmFactory`] at the VM's
//! first request that passes the check (on a blocking thread: the factory
//! may block on its own runtime), its `/run` posted to its own hooks. A
//! checked request then goes by its VM and its port (8080 to that VM's app
//! listener, 9418 to its code listener, any other the proxy's 502), every
//! hook to that VM's hooks, and every attempt records its VM. With the fake's
//! `enforce_wall` the bridge also plays the platform's wall: a VM past it in
//! the bridge's copy of the state is ended by one locked look
//! (`FileFakeMicrovmApi::settled`), so its `/terminate` goes out at that
//! tick, as nothing else may look at a quiet VM.
//!
//! Per-port routing (S8, [`FakeEndpoint::start_routed`]): after the token
//! check, a request goes to the upstream its `x-aws-proxy-port` names (the
//! shim's app port for 8080, its code port for 9418); a port with no route
//! answers 502 `BAD_GATEWAY`, as the proxy does when nothing listens there,
//! and is recorded like any other. Every attempt records its port, and
//! [`FakeEndpoint::script_port`] scripts one port's requests (a hold, a 5xx,
//! a cut mid-body). A request's body goes up as it comes, while the answer's
//! head is awaited (a `PUT /seed` is read whole before its 201). One request
//! per connection: one that does not upgrade goes up with `Connection:
//! close`, so a client's pooled connection never carries a second request
//! past the check, the script and the record.
#![allow(dead_code)]

use ai_env_cli::bridge::api::{AuthToken, Call, FakeState, VmState, TOKEN_HEADER};
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use ai_env_cli::wire::redact::Secret;
use ai_env_cli::wire::workspace::{APP_PORT, CODE_PORT};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Largest request or response head read.
const HEAD_MAX: usize = 64 * 1024;
/// How long a head, an upstream connect or a hook's post may take.
const STEP_LIMIT: Duration = Duration::from_secs(10);
/// How long the shim's answer head to a `/transcript/pull` may take: it
/// answers once the pull is done, and a 64 MiB chat takes 9 to 14 s in a
/// debug build on a loaded Mac.
const PULL_HEAD_LIMIT: Duration = Duration::from_secs(60);
/// The runtime hooks' path (the shim's `hooks::PREFIX`; this file also builds without the `shim` feature).
const HOOKS_PREFIX: &str = "/aws/lambda-microvms/runtime/v1";
/// How often the hook bridge reads the fake's state for VMs that moved.
const BRIDGE_TICK: Duration = Duration::from_millis(10);

/// What the endpoint does with one connection (the script's next entry, or `Forward`).
#[derive(Debug, Clone)]
pub enum Action {
    /// The proxy's token and state check, then the upstream.
    Forward,
    /// This answer, before any check; the upstream is never reached.
    Respond { status: u16, headers: Vec<(String, String)>, body: String },
    /// `Forward`, then both sides are cut `after` the upstream answered.
    ForwardThenCut { after: Duration },
    /// `Forward` until the upstream sends bytes holding `text` (for example
    /// `"t":"spawned"`): both sides are cut instead, so the client never gets them.
    ForwardUntil { text: String },
    /// The check, then `POST /resume` to the shim's hooks port (the platform's
    /// auto-resume holds the request meanwhile), then `Forward`. For tests
    /// without [`FakeEndpoint::start_platform`], whose endpoint posts that
    /// `/resume` itself.
    HoldThenResume { hooks: SocketAddr },
    /// `Forward` once the request was held `by` (a slow upgrade).
    Delay { by: Duration },
    /// `Forward` once the test called [`FakeEndpoint::release`] (a redial held back meanwhile).
    Held,
    /// `Forward`, then both sides are cut once `bytes` of the request's body
    /// (what the client sends past its head) went up: an upload cut mid-body.
    /// The client gets no answer (status 0).
    CutRequestAfter { bytes: u64 },
    /// `Forward`, then both sides are cut once `bytes` of the answer's body
    /// (past its head) reached the client: a download cut mid-body.
    CutResponseAfter { bytes: u64 },
}

impl Action {
    /// `Respond` with an empty body.
    #[must_use]
    pub fn status(status: u16, headers: &[(&str, &str)]) -> Action {
        Action::Respond { status, headers: headers.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect(), body: String::new() }
    }
}

/// One connection as the endpoint saw it.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub at: Instant,
    /// The status the client got (101: upgraded); 0 when it got none.
    pub status: u16,
    pub path: String,
    /// How many platform hooks had been posted, each answer awaited, when
    /// the endpoint let this request on (counted under the platform's lock,
    /// so none slips in between); for a request answered before that, how
    /// many by then. 0 without the platform.
    pub hooks: usize,
    /// The request's `x-aws-proxy-port`; 0 when it named none (or no head came).
    pub port: u16,
    /// The VM the check named (S10); `None` when the request was answered
    /// before the check or refused by it.
    pub vm: Option<String>,
}

/// One fake VM's listeners (S10, [`FakeEndpoint::start_per_vm`]): its
/// runtime hooks, its app port's and its code port's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmRoutes {
    pub hooks: SocketAddr,
    pub app: SocketAddr,
    pub code: SocketAddr,
}

/// Builds a VM's shim and disk at its auto-run (`enter`), run under
/// `spawn_blocking`: its listeners, or why there are none (its requests then
/// get the proxy's 502, and its next one asks again).
pub type VmFactory = Arc<dyn Fn(&str) -> std::io::Result<VmRoutes> + Send + Sync>;

/// One runtime hook the endpoint posted to a shim as the platform
/// ([`FakeEndpoint::start_platform`], [`FakeEndpoint::start_per_vm`]):
/// auto-run's `run`, the hook bridge's `suspend`, `resume` and `terminate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub vm: String,
    pub name: &'static str,
    /// The shim's answer; 0 when none came within the step limit.
    pub status: u16,
}

/// What the shim was last told about a VM it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Told {
    Running,
    Suspended,
    Terminated,
}

impl Told {
    /// Move to `to`: the hook that tells the shim so, if any (a VM told it
    /// ended is told nothing more).
    fn step(&mut self, to: Told) -> Option<&'static str> {
        let hook = match (*self, to) {
            (Told::Running, Told::Suspended) => "suspend",
            (Told::Suspended, Told::Running) => "resume",
            (Told::Running | Told::Suspended, Told::Terminated) => "terminate",
            _ => return None,
        };
        *self = to;
        Some(hook)
    }
}

/// One VM the platform's hook client ran: what its shim was told since, and
/// where that shim's hooks listen.
struct Ran {
    told: Told,
    hooks: SocketAddr,
}

/// The platform's hook client: the one shim's hooks (`None` per VM, S10:
/// each VM's come with its routes), the VMs it ran, and how far the fake's
/// recorded calls were read.
struct Platform {
    shim: Option<SocketAddr>,
    vms: BTreeMap<String, Ran>,
    replayed: usize,
}

impl Platform {
    fn new(shim: Option<SocketAddr>) -> Platform {
        Platform { shim, vms: BTreeMap::new(), replayed: 0 }
    }

    /// The hooks `st` owes the shims, in order, each with where its VM's
    /// hooks listen: each suspend, resume and terminate the fake recorded for
    /// a VM it ran since the last look (a terminate only if the VM is
    /// terminating or gone now: the fake records a call before its scripted
    /// failure), then what moved without a call. Each VM's told state is
    /// moved along.
    fn owed(&mut self, st: &FakeState) -> Vec<(String, &'static str, SocketAddr)> {
        let mut out = Vec::new();
        // A test that cleared the calls: nothing left to replay; the states below still count.
        let from = self.replayed.min(st.calls.len());
        for call in &st.calls[from..] {
            let (vm, to) = match call {
                Call::Suspend(vm) => (vm, Told::Suspended),
                Call::Resume(vm) => (vm, Told::Running),
                Call::Terminate(vm) if st.vms.get(vm).is_none_or(|v| v.state.is_terminal()) => (vm, Told::Terminated),
                _ => continue,
            };
            if let Some(ran) = self.vms.get_mut(vm) {
                if let Some(hook) = ran.told.step(to) {
                    out.push((vm.clone(), hook, ran.hooks));
                }
            }
        }
        self.replayed = st.calls.len();
        for (vm, ran) in &mut self.vms {
            let now = match st.vms.get(vm).map(|v| &v.state) {
                Some(VmState::Running) => Told::Running,
                Some(VmState::Suspending | VmState::Suspended) => Told::Suspended,
                Some(s) if s.is_terminal() => Told::Terminated,
                None => Told::Terminated,
                Some(_) => continue,
            };
            if let Some(hook) = ran.told.step(now) {
                out.push((vm.clone(), hook, ran.hooks));
            }
        }
        out
    }
}

/// Told before each platform hook is posted: the VM and the hook's name.
type BeforeHook = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Where a checked request goes.
enum Upstream {
    /// Every port to one listener ([`FakeEndpoint::start`]).
    One(SocketAddr),
    /// Each port to its own listener; any other port has none (502).
    Ports(BTreeMap<u16, SocketAddr>),
    /// S10: each VM's own listeners, built by `factory` at its first request.
    PerVm { routes: Mutex<BTreeMap<String, VmRoutes>>, factory: VmFactory },
}

impl Upstream {
    /// Where a checked request for `vm` to `port` goes; `None`: nothing
    /// listens there (the proxy's 502).
    fn route(&self, vm: &str, port: u16) -> Option<SocketAddr> {
        match self {
            Upstream::One(addr) => Some(*addr),
            Upstream::Ports(routes) => routes.get(&port).copied(),
            Upstream::PerVm { routes, .. } => {
                let r = routes.lock().unwrap().get(vm).copied()?;
                match port {
                    APP_PORT => Some(r.app),
                    CODE_PORT => Some(r.code),
                    _ => None,
                }
            }
        }
    }
}

struct Shared {
    fake: PathBuf,
    upstream: Upstream,
    script: Mutex<VecDeque<Action>>,
    /// Per port: actions for that port's next requests, taken before [`Shared::script`]'s.
    port_scripts: Mutex<BTreeMap<u16, VecDeque<Action>>>,
    attempts: Mutex<Vec<Attempt>>,
    /// Bumped by [`FakeEndpoint::cut_all`]: every forwarded connection ends.
    cut: tokio::sync::watch::Sender<u64>,
    /// Set by [`FakeEndpoint::release`]: `Held` requests go on.
    released: tokio::sync::watch::Sender<bool>,
    resumes: Mutex<u32>,
    /// Connections accepted (an attempt is recorded only once it is answered).
    accepted: Mutex<u32>,
    /// Requests a `Held` action took, held now or let go since.
    held: Mutex<u32>,
    /// The platform's hook client, when asked for ([`FakeEndpoint::start_platform`]).
    platform: Option<tokio::sync::Mutex<Platform>>,
    /// Every hook the platform's part posted, in order.
    hooks: Mutex<Vec<Hook>>,
    before_hook: Mutex<Option<BeforeHook>>,
    /// Whether the hook bridge looks between requests too ([`FakeEndpoint::ticking`]).
    ticking: AtomicBool,
}

/// The endpoint; stopped (every connection dropped) when dropped.
pub struct FakeEndpoint {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeEndpoint {
    /// Listen on 127.0.0.1 (a free port) in front of `upstream`, checking
    /// tokens against the file-backed fake at `fake`.
    #[must_use]
    pub fn start(fake: &Path, upstream: SocketAddr) -> FakeEndpoint {
        FakeEndpoint::launch(fake, Upstream::One(upstream), None)
    }

    /// [`FakeEndpoint::start`], also the platform's hook client for the shim
    /// whose hooks listen at `hooks` (see the module doc): auto-run and the
    /// hook bridge, each hook recorded ([`FakeEndpoint::hooks`]).
    #[must_use]
    pub fn start_platform(fake: &Path, upstream: SocketAddr, hooks: SocketAddr) -> FakeEndpoint {
        FakeEndpoint::launch(fake, Upstream::One(upstream), Some(Platform::new(Some(hooks))))
    }

    /// The S8 endpoint: [`FakeEndpoint::start`] with a request routed, once
    /// its token passed the check, by its `x-aws-proxy-port` to that port's
    /// listener in `routes` (`(8080, app)`, `(9418, code)`); any other port
    /// answers 502 `BAD_GATEWAY` and is recorded. With `hooks`, also the
    /// platform's hook client for that shim ([`FakeEndpoint::start_platform`]).
    #[must_use]
    pub fn start_routed(fake: &Path, routes: &[(u16, SocketAddr)], hooks: Option<SocketAddr>) -> FakeEndpoint {
        FakeEndpoint::launch(fake, Upstream::Ports(routes.iter().copied().collect()), hooks.map(|h| Platform::new(Some(h))))
    }

    /// The S10 endpoint (the module doc's "Per VM"): each VM gets its own
    /// listeners from `factory` at its first request that passes the check,
    /// its `/run` on its own hooks; a request then goes by its VM and its
    /// port (8080 to the VM's app listener, 9418 to its code listener, any
    /// other 502 `BAD_GATEWAY`), and the platform's hook client posts each
    /// VM's hooks to that VM's listener.
    #[must_use]
    pub fn start_per_vm(fake: &Path, factory: VmFactory) -> FakeEndpoint {
        FakeEndpoint::launch(fake, Upstream::PerVm { routes: Mutex::new(BTreeMap::new()), factory }, Some(Platform::new(None)))
    }

    fn launch(fake: &Path, upstream: Upstream, platform: Option<Platform>) -> FakeEndpoint {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the fake endpoint");
        listener.set_nonblocking(true).expect("nonblocking listener");
        let addr = listener.local_addr().expect("the endpoint's address");
        let shared = Arc::new(Shared {
            fake: fake.to_path_buf(),
            upstream,
            script: Mutex::new(VecDeque::new()),
            port_scripts: Mutex::new(BTreeMap::new()),
            attempts: Mutex::new(Vec::new()),
            cut: tokio::sync::watch::channel(0).0,
            released: tokio::sync::watch::channel(false).0,
            resumes: Mutex::new(0),
            accepted: Mutex::new(0),
            held: Mutex::new(0),
            platform: platform.map(tokio::sync::Mutex::new),
            hooks: Mutex::new(Vec::new()),
            before_hook: Mutex::new(None),
            ticking: AtomicBool::new(true),
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let s = shared.clone();
        let thread = std::thread::Builder::new()
            .name("fake-endpoint".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("the endpoint's runtime");
                rt.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).expect("a tokio listener");
                    let accept = async {
                        while let Ok((client, _)) = listener.accept().await {
                            let _ = client.set_nodelay(true);
                            *s.accepted.lock().unwrap() += 1;
                            tokio::spawn(serve(client, s.clone()));
                        }
                    };
                    // The hook bridge between requests: the VMs that moved while nothing was dialed.
                    let bridge = async {
                        let Some(platform) = &s.platform else { return std::future::pending().await };
                        loop {
                            tokio::time::sleep(BRIDGE_TICK).await;
                            // Read under the lock: `ticking(false)` returns only once no look is under way.
                            let mut p = platform.lock().await;
                            if s.ticking.load(Ordering::SeqCst) {
                                sync(&s, &mut p).await;
                            }
                        }
                    };
                    tokio::select! {
                        () = accept => {}
                        () = bridge => {}
                        _ = stopped => {}
                    }
                });
                rt.shutdown_background();
            })
            .expect("the endpoint's thread");
        FakeEndpoint { addr, shared, stop: Some(stop), thread: Some(thread) }
    }

    /// Queue `actions` for the next connections, in order.
    pub fn script(&self, actions: impl IntoIterator<Item = Action>) {
        self.shared.script.lock().unwrap().extend(actions);
    }

    /// Queue `actions` for the next requests whose `x-aws-proxy-port` is
    /// `port`, in order: another port's requests never take them, and they
    /// go before what [`FakeEndpoint::script`] queued.
    pub fn script_port(&self, port: u16, actions: impl IntoIterator<Item = Action>) {
        self.shared.port_scripts.lock().unwrap().entry(port).or_default().extend(actions);
    }

    /// Drop what [`FakeEndpoint::script_port`] queued for `port` that no
    /// request took yet (S10, phase 4b V-6: a VM unreachable for one chat
    /// until it gave up, then reachable again): that port's next requests
    /// take [`FakeEndpoint::script`]'s actions again, else `Forward`.
    pub fn unscript_port(&self, port: u16) {
        self.shared.port_scripts.lock().unwrap().remove(&port);
    }

    /// Every connection so far, in order.
    #[must_use]
    pub fn attempts(&self) -> Vec<Attempt> {
        self.shared.attempts.lock().unwrap().clone()
    }

    /// Cut every forwarded connection now (no Close on either side).
    pub fn cut_all(&self) {
        self.shared.cut.send_modify(|n| *n += 1);
    }

    /// Let every `Held` request go on, now and from now on.
    pub fn release(&self) {
        self.shared.released.send_modify(|r| *r = true);
    }

    /// How many `POST /resume` the endpoint sent to a shim and saw answered 200.
    #[must_use]
    pub fn resumes(&self) -> u32 {
        *self.shared.resumes.lock().unwrap()
    }

    /// How many connections were accepted (answered or not yet).
    #[must_use]
    pub fn accepted(&self) -> u32 {
        *self.shared.accepted.lock().unwrap()
    }

    /// How many requests a `Held` action took (held now, or let go since):
    /// unlike [`FakeEndpoint::accepted`], only the requests scripted to wait.
    #[must_use]
    pub fn held(&self) -> u32 {
        *self.shared.held.lock().unwrap()
    }

    /// Every hook posted as the platform ([`FakeEndpoint::start_platform`]), in order.
    #[must_use]
    pub fn hooks(&self) -> Vec<Hook> {
        self.shared.hooks.lock().unwrap().clone()
    }

    /// The listeners the factory built for `vm` ([`FakeEndpoint::start_per_vm`]);
    /// `None` before its first request, and on an endpoint of one shim.
    #[must_use]
    pub fn routes_of(&self, vm: &str) -> Option<VmRoutes> {
        match &self.shared.upstream {
            Upstream::PerVm { routes, .. } => routes.lock().unwrap().get(vm).copied(),
            Upstream::One(_) | Upstream::Ports(_) => None,
        }
    }

    /// Call `f(vm, hook)` on the endpoint's thread just before each platform
    /// hook is posted: what the shim holds at that moment is what that hook
    /// finds.
    pub fn before_hook(&self, f: impl Fn(&str, &str) + Send + Sync + 'static) {
        *self.shared.before_hook.lock().unwrap() = Some(Arc::new(f));
    }

    /// Whether the hook bridge also looks at the fake's state between
    /// requests (every [`BRIDGE_TICK`], from the start). Off, a VM's hooks go
    /// out only as a request comes in, before its check: what a test of that
    /// order needs. Returns once no look is under way; call it from a thread
    /// outside any runtime.
    pub fn ticking(&self, on: bool) {
        self.shared.ticking.store(on, Ordering::SeqCst);
        if let Some(p) = &self.shared.platform {
            drop(p.blocking_lock());
        }
    }
}

impl Drop for FakeEndpoint {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A parsed request head.
struct Head {
    raw: Vec<u8>,
    path: String,
    /// Lowercased name → value, in order.
    headers: Vec<(String, String)>,
    /// Bytes read past the head (forwarded as they are).
    rest: Vec<u8>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The `x-aws-proxy-port` the request names; 0 for none.
    fn port(&self) -> u16 {
        self.header("x-aws-proxy-port").and_then(|p| p.parse().ok()).unwrap_or(0)
    }

    /// The head with every `x-aws-proxy-*` header removed (as the platform
    /// forwards it); a request that does not upgrade also has its
    /// `Connection` headers replaced by `Connection: close` (one request per
    /// connection).
    fn stripped(&self) -> Vec<u8> {
        let upgrade = self.header("upgrade").is_some();
        let text = String::from_utf8_lossy(&self.raw);
        let mut out = String::new();
        for line in text.split("\r\n") {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("x-aws-proxy-") || (!upgrade && lower.starts_with("connection:")) {
                continue;
            }
            out.push_str(line);
            out.push_str("\r\n");
        }
        // The split leaves the head's final empty pair; keep exactly one blank line.
        while out.ends_with("\r\n\r\n\r\n") {
            out.truncate(out.len() - 2);
        }
        if !upgrade {
            out.truncate(out.len() - 2);
            out.push_str("Connection: close\r\n\r\n");
        }
        out.into_bytes()
    }
}

/// Read up to the end of a head (`\r\n\r\n`), at most [`HEAD_MAX`] bytes.
async fn read_head(s: &mut (impl AsyncRead + Unpin)) -> Option<(Vec<u8>, Vec<u8>)> {
    read_head_within(s, STEP_LIMIT).await
}

/// [`read_head`], each read allowed `limit`.
async fn read_head_within(s: &mut (impl AsyncRead + Unpin), limit: Duration) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Some((buf, rest));
        }
        if buf.len() > HEAD_MAX {
            return None;
        }
        match tokio::time::timeout(limit, s.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn parse(raw: Vec<u8>, rest: Vec<u8>) -> Head {
    let text = String::from_utf8_lossy(&raw).into_owned();
    let mut lines = text.split("\r\n");
    let path = lines.next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or_default().to_string();
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    Head { raw, path, headers, rest }
}

fn record(shared: &Shared, status: u16, path: &str, port: u16, hooks: usize, vm: Option<&str>) {
    shared.attempts.lock().unwrap().push(Attempt { at: Instant::now(), status, path: path.to_string(), hooks, port, vm: vm.map(str::to_string) });
}

/// The action for a request to `port`: that port's script first, then the
/// shared one, else `Forward`.
fn next_action(shared: &Shared, port: u16) -> Action {
    if let Some(action) = shared.port_scripts.lock().unwrap().get_mut(&port).and_then(VecDeque::pop_front) {
        return action;
    }
    shared.script.lock().unwrap().pop_front().unwrap_or(Action::Forward)
}

/// How many platform hooks were posted so far (each answer awaited).
fn posted(shared: &Shared) -> usize {
    shared.hooks.lock().unwrap().len()
}

/// `HTTP/1.1 <status>` with `headers` and `body`, then close.
async fn answer(client: &mut TcpStream, status: u16, headers: &[(String, String)], body: &str) {
    let reason = http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason()).unwrap_or("Status");
    let mut text = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in headers {
        text.push_str(&format!("{k}: {v}\r\n"));
    }
    text.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()));
    let _ = client.write_all(text.as_bytes()).await;
    let _ = client.shutdown().await;
}

/// The proxy's check through the fake's state: the VM the request is for,
/// or `Err((status, x-aws-proxy-error))` when it refuses.
async fn check(shared: &Shared, head: &Head) -> Result<String, (u16, String)> {
    let host = head.header("host").unwrap_or_default().to_string();
    let value = head.header("x-aws-proxy-auth").unwrap_or_default().to_string();
    let port: u16 = head.header("x-aws-proxy-port").and_then(|p| p.parse().ok()).unwrap_or(0);
    let fake = shared.fake.clone();
    let checked = tokio::task::spawn_blocking(move || {
        let token = AuthToken { headers: BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new(value))]), port, expires_at_unix: 0 };
        FileFakeMicrovmApi::open(&fake).and_then(|api| api.with(|s| Ok(s.endpoint_check(&host, &token, port))))
    })
    .await
    .expect("the check ran");
    match checked {
        Ok(Ok(vm)) => Ok(vm),
        Ok(Err(refusal)) => Err((refusal.status, refusal.proxy_error.unwrap_or_default())),
        Err(e) => Err((500, format!("fake state: {e}"))),
    }
}

/// `POST <HOOKS_PREFIX>/<hook>` with `body` to `hooks`: the status of the
/// answer, 0 when none came within [`STEP_LIMIT`].
async fn post_hook(hooks: SocketAddr, hook: &str, body: &str) -> u16 {
    let run = async {
        let mut s = TcpStream::connect(hooks).await.ok()?;
        let req = format!("POST {HOOKS_PREFIX}/{hook} HTTP/1.1\r\nHost: {hooks}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        s.write_all(req.as_bytes()).await.ok()?;
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.ok()?;
        String::from_utf8_lossy(&out).split_whitespace().nth(1).and_then(|c| c.parse().ok())
    };
    tokio::time::timeout(STEP_LIMIT, run).await.ok().flatten().unwrap_or(0)
}

/// `POST /aws/lambda-microvms/runtime/v1/resume` to `hooks`; whether it answered 200.
async fn post_resume(hooks: SocketAddr) -> bool {
    post_hook(hooks, "resume", "{}").await == 200
}

/// The fake's state as last saved, or `None` when it cannot be read. The
/// file is replaced atomically, so a read needs no lock (and, unlike
/// `FileFakeMicrovmApi::with`, writes nothing back).
async fn read_state(fake: &Path) -> Option<FakeState> {
    let fake = fake.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::read_to_string(&fake).ok().and_then(|text| serde_json::from_str(&text).ok())).await.ok().flatten()
}

/// The `runHookPayload` RunMicrovm carried for `vm` (`None`: the VM was
/// put in the fake's state without a run).
fn run_payload(st: &FakeState, vm: &str) -> Option<String> {
    let token = st.tokens.iter().find(|(_, id)| id.as_str() == vm).map(|(token, _)| token)?;
    st.specs.iter().find(|s| &s.client_token == token).map(|s| s.run_hook_payload.clone())
}

/// Post `hook` for `vm` as the platform: the test's [`FakeEndpoint::before_hook`]
/// first, then the post, its answer recorded.
async fn post_platform_hook(shared: &Shared, hooks: SocketAddr, vm: &str, hook: &'static str, body: &str) {
    let before = shared.before_hook.lock().unwrap().clone();
    if let Some(f) = before {
        f(vm, hook);
    }
    let status = post_hook(hooks, hook, body).await;
    if hook == "resume" && status == 200 {
        *shared.resumes.lock().unwrap() += 1;
    }
    shared.hooks.lock().unwrap().push(Hook { vm: vm.to_string(), name: hook, status });
}

/// The hook bridge: post every hook the fake's state owes the shims
/// ([`Platform::owed`]), in order, each answered before the next. With the
/// wall asked for (S10, `FakeState::enforce_wall`), a VM past it in this
/// copy is first ended by one locked look ([`settle_locked`]), so its
/// `/terminate` is among them.
async fn sync(shared: &Shared, p: &mut Platform) {
    let Some(mut st) = read_state(&shared.fake).await else { return };
    if st.wall_due() {
        if let Some(looked) = settle_locked(&shared.fake).await {
            st = looked;
        }
    }
    for (vm, hook, hooks) in p.owed(&st) {
        post_platform_hook(shared, hooks, &vm, hook, "{}").await;
    }
}

/// One look at the fake's state under its lock, saved
/// (`FileFakeMicrovmApi::settled`): the state after it, `None` when it
/// cannot be read.
async fn settle_locked(fake: &Path) -> Option<FakeState> {
    let fake = fake.to_path_buf();
    tokio::task::spawn_blocking(move || FileFakeMicrovmApi::open(&fake).and_then(|api| api.settled()).ok()).await.ok().flatten()
}

/// A request for `vm` passed the check. Auto-run: a VM the platform never
/// ran gets `/run` first, with the payload its RunMicrovm carried, on the
/// one shim, or (S10, per VM) on the listeners the factory builds for it
/// now. A VM whose shim was told it is suspended was just resumed by the
/// check (the platform's auto-resume): `/resume` goes first, as the
/// platform's hold posts it before the request goes on.
async fn enter(shared: &Shared, p: &mut Platform, vm: &str) {
    if let Some(ran) = p.vms.get_mut(vm) {
        if let Some(hook) = ran.told.step(Told::Running) {
            let hooks = ran.hooks;
            post_platform_hook(shared, hooks, vm, hook, "{}").await;
        }
        return;
    }
    let Some(hooks) = hooks_for(shared, p, vm).await else { return };
    let payload = read_state(&shared.fake).await.and_then(|st| run_payload(&st, vm));
    let body = serde_json::json!({ "microvmId": vm, "runHookPayload": payload }).to_string();
    p.vms.insert(vm.to_string(), Ran { told: Told::Running, hooks });
    post_platform_hook(shared, hooks, vm, "run", &body).await;
}

/// Where the shim of `vm`, which the platform never ran, listens for its
/// hooks: the one shim's, or (S10, per VM) the listeners the factory builds
/// for it now, kept for its requests. `None` when the factory failed: said
/// on stderr, the VM's requests get the proxy's 502 until a later one finds
/// its listeners built.
async fn hooks_for(shared: &Shared, p: &Platform, vm: &str) -> Option<SocketAddr> {
    let Upstream::PerVm { routes, factory } = &shared.upstream else { return p.shim };
    let built = routes.lock().unwrap().get(vm).copied();
    if let Some(r) = built {
        return Some(r.hooks);
    }
    let (factory, id) = (factory.clone(), vm.to_string());
    match tokio::task::spawn_blocking(move || factory(&id)).await {
        Ok(Ok(r)) => {
            routes.lock().unwrap().insert(vm.to_string(), r);
            Some(r.hooks)
        }
        Ok(Err(e)) => {
            eprintln!("fake endpoint: no listeners for {vm}: {e}");
            None
        }
        Err(e) => {
            eprintln!("fake endpoint: building the listeners of {vm} failed: {e}");
            None
        }
    }
}

/// How a forwarded request ends besides both sides' own end ([`Action`]).
#[derive(Default)]
struct Cuts {
    /// `ForwardThenCut`: this long after the answer's head.
    after: Option<Duration>,
    /// `ForwardUntil`: before the answer's bytes that hold it; either side's end ends both.
    until: Option<String>,
    /// `CutRequestAfter`: once this much of the request's body went up.
    request_bytes: Option<u64>,
    /// `CutResponseAfter`: once this much of the answer's body came back.
    response_bytes: Option<u64>,
}

async fn serve(mut client: TcpStream, shared: Arc<Shared>) {
    let Some((raw, rest)) = read_head(&mut client).await else {
        record(&shared, 0, "", 0, posted(&shared), None);
        return;
    };
    let head = parse(raw, rest);
    let port = head.port();
    let action = next_action(&shared, port);
    let mut cuts = Cuts::default();
    match action {
        Action::Respond { status, headers, body } => {
            record(&shared, status, &head.path, port, posted(&shared), None);
            answer(&mut client, status, &headers, &body).await;
            return;
        }
        Action::ForwardThenCut { after } => cuts.after = Some(after),
        Action::ForwardUntil { ref text } => cuts.until = Some(text.clone()),
        Action::Delay { by } => tokio::time::sleep(by).await,
        Action::Held => {
            *shared.held.lock().unwrap() += 1;
            let _ = shared.released.subscribe().wait_for(|r| *r).await;
        }
        Action::CutRequestAfter { bytes } => cuts.request_bytes = Some(bytes),
        Action::CutResponseAfter { bytes } => cuts.response_bytes = Some(bytes),
        Action::Forward | Action::HoldThenResume { .. } => {}
    }
    // As the platform, but in one look for every VM (the module doc): the hooks the fake's state owes the shims go
    // before the check, and its auto-resume or a VM's first request before the request goes on.
    let mut platform = match &shared.platform {
        Some(p) => Some(p.lock().await),
        None => None,
    };
    if let Some(p) = platform.as_deref_mut() {
        sync(&shared, p).await;
    }
    let vm = match check(&shared, &head).await {
        Ok(vm) => vm,
        Err((status, proxy_error)) => {
            record(&shared, status, &head.path, port, posted(&shared), None);
            answer(&mut client, status, &[("x-aws-proxy-error".into(), proxy_error)], "").await;
            return;
        }
    };
    if let Some(p) = platform.as_deref_mut() {
        enter(&shared, p, &vm).await;
    }
    let answered = posted(&shared);
    drop(platform);
    if let Action::HoldThenResume { hooks } = action {
        if post_resume(hooks).await {
            *shared.resumes.lock().unwrap() += 1;
        }
    }
    // A port nothing listens on, or a listener that is gone: the proxy's 502.
    let connected = match shared.upstream.route(&vm, port) {
        Some(target) => tokio::time::timeout(STEP_LIMIT, TcpStream::connect(target)).await.ok().and_then(Result::ok),
        None => None,
    };
    let Some(mut upstream) = connected else {
        record(&shared, 502, &head.path, port, answered, Some(&vm));
        answer(&mut client, 502, &[("x-aws-proxy-error".into(), "BAD_GATEWAY".into())], "").await;
        return;
    };
    let _ = upstream.set_nodelay(true);
    forward(&mut client, &mut upstream, &head, &shared, (port, answered, &vm), &cuts).await;
    // Dropping both streams cuts the connection on both sides.
}

/// Forward one checked request (`at`: its port, the hooks answered before
/// it went on, and its VM) to `upstream`: its head, stripped, and its body
/// as it comes while the answer's head is awaited; that head back (its
/// status is the attempt's); then both ways until both sides ended
/// (`until`: until either did) or a cut: one of `cuts`, or
/// [`FakeEndpoint::cut_all`] once the answer's head was back.
async fn forward(client: &mut TcpStream, upstream: &mut TcpStream, head: &Head, shared: &Shared, at: (u16, usize, &str), cuts: &Cuts) {
    let (port, answered, vm) = at;
    let vm = Some(vm);
    let path = head.path.as_str();
    let mut up_left = cuts.request_bytes;
    let rest = match up_left {
        Some(n) => &head.rest[..head.rest.len().min(usize::try_from(n).unwrap_or(usize::MAX))],
        None => &head.rest[..],
    };
    let mut sent = head.stripped();
    sent.extend_from_slice(rest);
    if upstream.write_all(&sent).await.is_err() {
        record(shared, 0, path, port, answered, vm);
        return;
    }
    if let Some(left) = up_left.as_mut() {
        *left -= rest.len() as u64;
        if *left == 0 {
            record(shared, 0, path, port, answered, vm);
            return;
        }
    }
    let either = cuts.until.is_some();
    let (mut from_client, mut to_client) = client.split();
    let (mut from_upstream, mut to_upstream) = upstream.split();
    let mut up = std::pin::pin!(pump(&mut from_client, &mut to_upstream, up_left, None));
    let mut up_end = None;
    // The upstream's answer head goes back first: its status is the attempt's.
    let reply = {
        let limit = if path.starts_with("/transcript/pull") { PULL_HEAD_LIMIT } else { STEP_LIMIT };
        let mut reply = std::pin::pin!(read_head_within(&mut from_upstream, limit));
        loop {
            tokio::select! {
                h = &mut reply => break h,
                e = &mut up, if up_end.is_none() => {
                    if e == End::Cut {
                        record(shared, 0, path, port, answered, vm);
                        return;
                    }
                    up_end = Some(e);
                }
            }
        }
    };
    let Some((reply, more)) = reply else {
        record(shared, 0, path, port, answered, vm);
        return;
    };
    let status = String::from_utf8_lossy(&reply).split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    record(shared, status, path, port, answered, vm);
    let mut down_left = cuts.response_bytes;
    let more = match down_left {
        Some(n) => &more[..more.len().min(usize::try_from(n).unwrap_or(usize::MAX))],
        None => &more[..],
    };
    if to_client.write_all(&reply).await.is_err() || to_client.write_all(more).await.is_err() {
        return;
    }
    if let Some(left) = down_left.as_mut() {
        *left -= more.len() as u64;
        if *left == 0 {
            return;
        }
    }
    let mut cut = shared.cut.subscribe();
    let mut timer = std::pin::pin!(async {
        match cuts.after {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    });
    let mut down = std::pin::pin!(pump(&mut from_upstream, &mut to_client, down_left, cuts.until.as_deref().map(str::as_bytes)));
    let mut down_end = None;
    loop {
        let ended = [up_end, down_end];
        if ended.contains(&Some(End::Cut)) || ended.iter().all(Option::is_some) || (either && ended.iter().any(Option::is_some)) {
            return;
        }
        tokio::select! {
            e = &mut up, if up_end.is_none() => up_end = Some(e),
            e = &mut down, if down_end.is_none() => down_end = Some(e),
            () = &mut timer => return,
            _ = cut.changed() => return,
        }
    }
}

/// How one direction of a forwarded connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// Its source ended; the other side's write half was shut down.
    Eof,
    /// A cut: a byte limit reached, the `until` text seen, or a read or write failed.
    Cut,
}

/// Copy `from` to `to` until `from` ends ([`End::Eof`], `to` shut down, as
/// `copy_bidirectional` does) or a cut ([`End::Cut`]): `limit` bytes went
/// (no more of that read is written), `from` sent bytes holding `until` (none
/// of that read is written, as for a text split across two reads), or a
/// read or write failed.
async fn pump(from: &mut (impl AsyncRead + Unpin), to: &mut (impl AsyncWrite + Unpin), mut limit: Option<u64>, until: Option<&[u8]>) -> End {
    let mut buf = vec![0u8; 64 * 1024];
    // What came last, for an `until` split across two reads.
    let mut seen = Vec::new();
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) => {
                let _ = to.shutdown().await;
                return End::Eof;
            }
            Ok(n) => n,
            Err(_) => return End::Cut,
        };
        if let Some(text) = until.filter(|t| !t.is_empty()) {
            seen.extend_from_slice(&buf[..n]);
            if seen.windows(text.len()).any(|w| w == text) {
                return End::Cut;
            }
            seen.drain(..seen.len().saturating_sub(text.len()));
        }
        let take = limit.map_or(n, |l| n.min(usize::try_from(l).unwrap_or(usize::MAX)));
        if to.write_all(&buf[..take]).await.is_err() {
            return End::Cut;
        }
        if let Some(l) = limit.as_mut() {
            *l -= take as u64;
            if *l == 0 {
                return End::Cut;
            }
        }
    }
}
