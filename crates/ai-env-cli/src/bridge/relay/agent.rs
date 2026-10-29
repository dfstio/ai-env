//! `ai-env relay agent` (S13, WM-R38 to WM-R40, WM-R58; LD-WM2, LD-WM12, LD-WM13): this Mac's signing agent,
//! like ssh-agent. It unseals this Mac's two relay keys once (one Touch ID), then answers on a 0600 Unix socket,
//! `state/relay-agent.sock`, in `ai_env_worker::agent`'s line protocol (one request per connection):
//!
//! - `status`: its pid, its end, its worker id, both public keys and its counts;
//! - `sign_worker_auth`: the handshake of a worker on this Mac (its `AgentSigner`), for this agent's worker id
//!   and worker key only; the agent builds the transcript itself (§P's `wire::transcript`), never signing bytes
//!   it is handed;
//! - `mint_session`: a VM session token for a remote spawn (`relay::mint`), only for a VM this Mac's registry
//!   holds as a live vpc VM whose egress gate passed, only for a grant `bridge.toml` names (read at each
//!   request), at most 8 h and never past the VM's wall.
//!
//! It answers only its own uid (the peer's credentials), at most 16 connections at once, one request within
//! 5 s each. Its life is measured on the wall clock (Darwin's `Instant` stops while the Mac sleeps): 1 to 24 h,
//! checked every 30 s and at each request; at its end, or at SIGINT, SIGTERM or SIGHUP, it stops accepting,
//! removes the socket only if it is still the one it bound (device and inode), drops both keys and exits 0.
//! One stderr line per signature, mint and refusal; never a nonce, a signature or a token.
//!
//! This file is the only place a Unix listener is bound (`make lint`).
use super::cli::{audit, runtime};
use super::keys::{read_notes, relay_cfg, unseal, MacKeys};
use crate::bridge::audit::event::RELAY_AGENT;
use crate::bridge::config::{BridgeConfig, Paths, RelayCfg};
use crate::bridge::registry::ensure_private_dir;
use crate::bridge::signals;
use crate::bridge::vm::lock::{try_lock_exclusive, FlockGuard};
use crate::bridge::vm::registry::{read_row, RowStatus, GATE_PASSED};
use crate::errors::{CliError, Result};
use crate::store::Keystore;
use crate::wire::time::{rfc3339_utc, unix_now};
use ai_env_worker::agent::{decode_request, encode_response, AgentStatus, MintRequest, Request, Response, SignRequest, IO_TIMEOUT, REQUEST_MAX};
use ai_env_worker::globs::{valid_relay_id, valid_uuid};
use ai_env_worker::keys::Alg;
use ai_env_worker::session::{self, SessionClaims, SESSION_AUD, SESSION_MAX_S};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

/// The most connections served at once (WM-R39); the next is answered `busy`.
pub(crate) const MAX_CONNECTIONS: usize = 16;
/// How often the wall clock is checked against the agent's end besides each request (WM-R40).
const EXPIRY_CHECK: Duration = Duration::from_secs(30);
/// The longest socket path a `sockaddr_un` holds on macOS, its terminating NUL aside.
const SOCKET_PATH_MAX: usize = 103;
/// The least a minted token lives (WM-R39): a shorter `exp` asked is `bad_request`.
const MINT_MIN_S: u64 = 60;

/// The wall clock the agent's life and its tokens are measured on (the tests' seam).
pub(crate) trait Clock {
    fn now_unix(&self) -> u64;
}

/// `SystemTime::now`.
pub(crate) struct WallClock;

impl Clock for WallClock {
    fn now_unix(&self) -> u64 {
        unix_now()
    }
}

/// What the agent serves with.
pub(crate) struct AgentState {
    pub(crate) keys: MacKeys,
    /// The agent's end, unix seconds on [`AgentState::clock`].
    pub(crate) until: u64,
    /// The bridge root: VM rows and `bridge.toml` are read at each mint.
    pub(crate) paths: Paths,
    /// The socket bound, and its device and inode then: removed at the end only while they still are.
    pub(crate) socket: PathBuf,
    pub(crate) bound: (u64, u64),
    pub(crate) clock: Arc<dyn Clock + Send + Sync>,
    /// The one uid answered (WM-R39, WM-R58): the agent's effective uid ([`cmd_agent`]; the tests' seam).
    pub(crate) euid: u32,
}

/// How the agent ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// A stop signal (or the caller's stop).
    Stopped,
    /// The wall clock passed its end.
    Expired,
}

impl End {
    pub(crate) fn word(self) -> &'static str {
        match self {
            End::Stopped => "stopped",
            End::Expired => "expired",
        }
    }
}

/// [`serve`]'s result: how it ended and its counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) end: End,
    pub(crate) signed: u64,
    pub(crate) minted: u64,
}

/// Whether a peer of uid `uid` is answered by an agent running as `euid` (WM-R39, WM-R58): only its own.
pub(crate) fn peer_ok(uid: u32, euid: u32) -> bool {
    uid == euid
}

/// The effective uid of this process.
fn euid() -> u32 {
    // SAFETY: geteuid(2) has no failure mode and touches no memory.
    unsafe { libc::geteuid() }
}

/// WM-R38's checks before any Touch ID, in order: `state/` made a private 0700 directory; the socket path under
/// 104 bytes; `state/relay-agent.lock` taken without waiting (another agent: exit 1 naming its pid and end, as
/// its `status` answers, `unknown` when none does); a leftover socket at the path removed, anything else there
/// exit 1. The lock, held for the agent's life.
pub(crate) fn prepare_socket(paths: &Paths) -> Result<FlockGuard> {
    ensure_private_dir(&paths.root.join("state"))?;
    let socket = paths.relay_agent_socket();
    let n = socket.as_os_str().len();
    if n > SOCKET_PATH_MAX {
        return Err(CliError::Msg(format!("{} is {n} bytes, over the {SOCKET_PATH_MAX} a Unix socket path may hold: set AI_ENV_BRIDGE_DIR to a shorter directory", socket.display())));
    }
    let Some(lock) = try_lock_exclusive(&paths.relay_agent_lock())? else {
        let (pid, until) = match runtime().ok().and_then(|rt| rt.block_on(ai_env_worker::agent::request(&socket, &Request::Status, Duration::from_secs(1))).ok()) {
            Some(Response::Status(s)) => (s.pid.to_string(), rfc3339_utc(s.until)),
            _ => ("unknown".to_string(), "unknown".to_string()),
        };
        return Err(CliError::Msg(format!("another relay agent runs (pid {pid}, until {until})")));
    };
    match std::fs::symlink_metadata(&socket) {
        Ok(m) if std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()) => {
            std::fs::remove_file(&socket).map_err(|e| CliError::Msg(format!("cannot remove the leftover socket {}: {e}", socket.display())))?;
        }
        Ok(_) => return Err(CliError::Msg(format!("{} exists and is not a socket: move it away", socket.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(CliError::Msg(format!("cannot inspect {}: {e}", socket.display()))),
    }
    Ok(lock)
}

/// Bind `socket` with the umask `0o077`, then chmod it 0600 (WM-R38): the listener, and the socket's device and
/// inode as bound. The umask is the whole process's, so [`cmd_agent`] binds before its runtime's threads start.
pub(crate) fn bind(socket: &Path) -> Result<(std::os::unix::net::UnixListener, (u64, u64))> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    // The lib's own unit tests bind beside other tests that create files, where a process-wide umask would narrow
    // their modes; the 0700 state directory keeps every other user out of the socket's window before the chmod.
    // SAFETY: umask(2) swaps this process's file-creation mask and cannot fail; the old one is put back at once.
    let old = (!cfg!(test)).then(|| unsafe { libc::umask(0o077) });
    let bound = std::os::unix::net::UnixListener::bind(socket);
    if let Some(old) = old {
        // SAFETY: as above.
        unsafe { libc::umask(old) };
    }
    let listener = bound.map_err(|e| CliError::Msg(format!("cannot listen on {}: {e}", socket.display())))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).map_err(|e| CliError::Msg(format!("cannot chmod {}: {e}", socket.display())))?;
    let meta = std::fs::symlink_metadata(socket).map_err(|e| CliError::Msg(format!("cannot inspect {}: {e}", socket.display())))?;
    listener.set_nonblocking(true).map_err(|e| CliError::Msg(format!("{}: {e}", socket.display())))?;
    Ok((listener, (meta.dev(), meta.ino())))
}

/// `ai-env relay agent [--hours N]` (WM-R38 to WM-R40).
pub fn cmd_agent(store: &Keystore, hours: Option<u32>) -> Result<()> {
    if let Some(h) = hours.filter(|h| !(1..=RelayCfg::AGENT_HOURS_MAX).contains(h)) {
        return Err(CliError::Usage(format!("relay agent: --hours {h} is outside 1..={}", RelayCfg::AGENT_HOURS_MAX)));
    }
    let paths = Paths::resolve()?;
    let relay = relay_cfg(&paths)?;
    let hours = hours.unwrap_or(relay.agent_hours);
    // Before any listener could replace them: a stop signal ignored at start stays ignored.
    signals::note_dispositions();
    let lock = prepare_socket(&paths)?;
    let notes = read_notes(&paths)?;
    if notes.worker_id != relay.worker_id {
        return Err(CliError::Msg(format!("credentials/relay-worker.env was sealed for worker {}, but [relay].worker_id is {}", notes.worker_id, relay.worker_id)));
    }
    let keys = unseal(store, &paths)?;
    // Bound before the runtime's threads exist: the umask `bind` sets is the whole process's (WM-R38).
    let socket = paths.relay_agent_socket();
    let (std_listener, bound) = bind(&socket)?;
    let (rt, mut stops, listener) = match start_runtime(std_listener) {
        Ok(started) => started,
        Err(e) => {
            remove_if_ours(&socket, bound);
            return Err(e);
        }
    };
    let until = unix_now() + u64::from(hours) * 3600;
    audit(&paths, RELAY_AGENT, &[("outcome", "started".to_string()), ("hours", hours.to_string())]);
    signals::say(&format!(
        "relay agent: worker {} (fp {}), session key fp {}; socket {}; until {} ({hours} h); Ctrl-C stops it",
        keys.worker_id,
        keys.worker.public_key().fingerprint(),
        keys.session.public_key().fingerprint(),
        socket.display(),
        rfc3339_utc(until)
    ));
    let state = AgentState { keys, until, paths: paths.clone(), socket, bound, clock: Arc::new(WallClock), euid: euid() };
    let out = rt.block_on(serve(state, listener, async move {
        stops.next().await;
    }));
    // The runtime first (WM-R40): a connection task still running shares the keys, which go with it, so they
    // are dropped before the row and the line say so.
    drop(rt);
    let pairs = [("outcome", out.end.word().to_string()), ("hours", hours.to_string()), ("signed", out.signed.to_string()), ("minted", out.minted.to_string())];
    audit(&paths, RELAY_AGENT, &pairs);
    signals::say(&format!("relay agent: {} ({} signed, {} minted); its keys are dropped", out.end.word(), out.signed, out.minted));
    drop(lock);
    Ok(())
}

/// The agent's runtime, its stop signals, and `listener` registered with it.
fn start_runtime(listener: std::os::unix::net::UnixListener) -> Result<(tokio::runtime::Runtime, signals::Stops, tokio::net::UnixListener)> {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("ai-env-relay-agent").enable_all().build().map_err(|e| CliError::Msg(format!("relay agent: cannot start the async runtime: {e}")))?;
    let stops = rt.block_on(async { signals::Stops::take() })?;
    let listener = rt.block_on(async { tokio::net::UnixListener::from_std(listener) }).map_err(|e| CliError::Msg(format!("relay agent: {e}")))?;
    Ok((rt, stops, listener))
}

/// The agent's shared state, its counts beside it.
struct Shared {
    keys: MacKeys,
    until: u64,
    paths: Paths,
    clock: Arc<dyn Clock + Send + Sync>,
    euid: u32,
    signed: AtomicU64,
    minted: AtomicU64,
    active: AtomicUsize,
}

impl Shared {
    fn expired(&self) -> bool {
        self.clock.now_unix() > self.until
    }

    /// One refusal: its line on stderr, its answer.
    fn refuse(op: &str, code: &str, message: impl Into<String>) -> Response {
        signals::say(&format!("relay agent: refused {op}: {code}"));
        Response::Refused { error: code.to_string(), message: message.into() }
    }

    fn answer(&self, req: Request) -> Response {
        match req {
            Request::Status => Response::Status(AgentStatus {
                pid: std::process::id(),
                until: self.until,
                worker_id: self.keys.worker_id.clone(),
                worker_key: self.keys.worker.public_key(),
                session_key: self.keys.session.public_key(),
                signed: self.signed.load(Ordering::SeqCst),
                minted: self.minted.load(Ordering::SeqCst),
            }),
            Request::SignWorkerAuth(s) => self.sign(&s),
            Request::MintSession(m) => self.mint(&m),
        }
    }

    /// WM-R39's `sign_worker_auth`: this agent's worker id and key only, then the transcript it builds itself.
    fn sign(&self, s: &SignRequest) -> Response {
        const OP: &str = "sign_worker_auth";
        if s.worker_id != self.keys.worker_id {
            return Shared::refuse(OP, "wrong_worker", format!("this agent signs for worker {} only", self.keys.worker_id));
        }
        if s.alg != Alg::Ed25519 || s.public_key != self.keys.worker.public_key() {
            return Shared::refuse(OP, "wrong_key", format!("this agent holds the worker key fp {} only", self.keys.worker.public_key().fingerprint()));
        }
        if s.protocol < 1 {
            return Shared::refuse(OP, "unsupported", format!("protocol {} is not one this agent signs", s.protocol));
        }
        if s.nonce.len() != ai_env_worker::ai_env_source::wire::NONCE_LEN || !valid_relay_id(&s.relay_id) {
            return Shared::refuse(OP, "bad_request", "a nonce of 32 bytes and a relay id are needed");
        }
        let key = self.keys.worker.public_key();
        let transcript = ai_env_worker::ai_env_source::wire::transcript(&s.relay_id, &s.nonce, &s.worker_id, s.alg.wire() as u32, key.bytes(), s.protocol);
        let signature = self.keys.worker.sign(&transcript);
        self.signed.fetch_add(1, Ordering::SeqCst);
        signals::say(&format!("relay agent: signed the handshake of worker {} for relay {}", s.worker_id, s.relay_id));
        Response::Signed { signature }
    }

    /// WM-R39's `mint_session` (LD-WM12): a live vpc VM of this Mac whose gate passed, a grant `bridge.toml`
    /// names now, uuids, at least a minute; `exp` clamped to 8 h and to the VM's wall.
    fn mint(&self, m: &MintRequest) -> Response {
        const OP: &str = "mint_session";
        let now = self.clock.now_unix();
        let row = match read_row(&self.paths, &m.vm_id) {
            Ok(Some(row)) => row,
            _ => return Shared::refuse(OP, "unknown_vm", "no live vpc VM of this Mac passed its egress gate under that id"),
        };
        let live = !matches!(row.status, RowStatus::Pending | RowStatus::Terminated) && row.egress == "vpc" && row.egress_gate.as_deref() == Some(GATE_PASSED) && row.wall_deadline.is_none_or(|w| w > now);
        if !live {
            return Shared::refuse(OP, "unknown_vm", "no live vpc VM of this Mac passed its egress gate under that id");
        }
        let cfg = BridgeConfig::load(&self.paths).ok().flatten().unwrap_or_default();
        let named = std::iter::once(cfg.relay.grant.as_str()).chain(cfg.workspace_overrides.iter().filter_map(|w| w.relay_grant.as_deref()));
        let grants: Vec<&str> = named.filter(|g| !g.is_empty()).collect();
        if !grants.contains(&m.grant_id.as_str()) {
            return Shared::refuse(OP, "unknown_grant", "bridge.toml names no such grant ([relay].grant, [[workspace]].relay_grant)");
        }
        if !valid_uuid(&m.session_id) || m.chat_id.as_deref().is_some_and(|c| !valid_uuid(c)) || m.exp < now + MINT_MIN_S {
            return Shared::refuse(OP, "bad_request", "session_id and chat_id are uuids, and exp is at least a minute ahead");
        }
        let mut exp = m.exp.min(now + SESSION_MAX_S);
        if let Some(wall) = row.wall_deadline {
            exp = exp.min(wall);
        }
        let worker = self.keys.worker_id.clone();
        let claims = SessionClaims { kid: worker.clone(), aud: SESSION_AUD.to_string(), caller_id: worker, session_id: m.session_id.clone(), chat_id: m.chat_id.clone(), grant_id: m.grant_id.clone(), vm_id: m.vm_id.clone(), iat: now, exp };
        match session::mint(&self.keys.session, &claims, now) {
            Ok(token) => {
                self.minted.fetch_add(1, Ordering::SeqCst);
                signals::say(&format!("relay agent: minted a session token for {} (spawn {}, grant {}, until {})", m.vm_id, m.session_id, m.grant_id, rfc3339_utc(exp)));
                Response::Minted { token, exp }
            }
            Err(e) => Shared::refuse(OP, "bad_request", format!("the token's claims are refused ({e})")),
        }
    }

    /// One connection (WM-R39): the peer's uid first (another is closed with no answer), then one line within
    /// 5 s, the clock against the agent's end, the request.
    async fn connection(&self, stream: tokio::net::UnixStream, expire: &tokio::sync::watch::Sender<bool>) {
        let Ok(cred) = stream.peer_cred() else { return };
        if !peer_ok(cred.uid(), self.euid) {
            return;
        }
        let (read, mut write) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(read.take(REQUEST_MAX as u64));
        let mut line = Vec::new();
        match tokio::time::timeout(IO_TIMEOUT, reader.read_until(b'\n', &mut line)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => return,
        }
        let response = if self.expired() {
            let _ = expire.send(true);
            Shared::refuse("request", "expired", format!("this agent ended at {}", rfc3339_utc(self.until)))
        } else if !line.ends_with(b"\n") {
            Shared::refuse("request", "bad_request", format!("a request is one line of at most {REQUEST_MAX} bytes"))
        } else {
            match decode_request(&line) {
                Ok(req) => self.answer(req),
                Err(e) => Shared::refuse("request", "bad_request", e.to_string()),
            }
        };
        let _ = tokio::time::timeout(IO_TIMEOUT, write.write_all(&encode_response(&response))).await;
        let _ = write.shutdown().await;
    }

    /// The connection past [`MAX_CONNECTIONS`]: answered `busy` (its own uid only) and closed.
    async fn busy(&self, mut stream: tokio::net::UnixStream) {
        if stream.peer_cred().is_ok_and(|c| peer_ok(c.uid(), self.euid)) {
            let busy = Shared::refuse("request", "busy", format!("this agent serves {MAX_CONNECTIONS} connections at once"));
            let _ = tokio::time::timeout(IO_TIMEOUT, stream.write_all(&encode_response(&busy))).await;
            let _ = stream.shutdown().await;
        }
    }
}

/// Serve `listener` until `stop` resolves or the wall clock passes `state.until` (WM-R39, WM-R40); then stop
/// accepting and remove the socket if it is still the one bound. The keys go with `state`.
pub(crate) async fn serve(state: AgentState, listener: tokio::net::UnixListener, stop: impl std::future::Future<Output = ()>) -> Outcome {
    let AgentState { keys, until, paths, socket, bound, clock, euid } = state;
    let shared = Arc::new(Shared { keys, until, paths, clock, euid, signed: AtomicU64::new(0), minted: AtomicU64::new(0), active: AtomicUsize::new(0) });
    let (expire_tx, mut expired) = tokio::sync::watch::channel(false);
    let expire_tx = Arc::new(expire_tx);
    let mut tick = tokio::time::interval(EXPIRY_CHECK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(stop);
    let end = loop {
        tokio::select! {
            () = &mut stop => break End::Stopped,
            _ = expired.changed() => break End::Expired,
            _ = tick.tick() => {
                if shared.expired() {
                    break End::Expired;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let s = Arc::clone(&shared);
                    if s.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                        s.active.fetch_sub(1, Ordering::SeqCst);
                        tokio::spawn(async move { s.busy(stream).await });
                        continue;
                    }
                    let tx = Arc::clone(&expire_tx);
                    tokio::spawn(async move {
                        s.connection(stream, &tx).await;
                        s.active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) => {
                    tracing::warn!("relay agent: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
        }
    };
    drop(listener);
    remove_if_ours(&socket, bound);
    Outcome { end, signed: shared.signed.load(Ordering::SeqCst), minted: shared.minted.load(Ordering::SeqCst) }
}

/// Remove `socket` only if it is still the one bound (its device and inode): a path replaced meanwhile is left.
fn remove_if_ours(socket: &Path, bound: (u64, u64)) {
    use std::os::unix::fs::MetadataExt as _;
    if std::fs::symlink_metadata(socket).is_ok_and(|m| (m.dev(), m.ino()) == bound) {
        let _ = std::fs::remove_file(socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::vm::registry::{write_row, VmRow};
    use ai_env_worker::agent::request;
    use ai_env_worker::keys::{PublicKey, SigningKey};
    use ai_env_worker::session::SignerKey;
    use std::sync::atomic::AtomicU64;

    const VM: &str = "microvm-0199a1b2-0000-7000-8000-000000000001";
    const SPAWN: &str = "0199a1b2-0000-7000-8000-000000000002";

    /// The tests' wall clock, moved by hand.
    struct TestClock(AtomicU64);

    impl Clock for TestClock {
        fn now_unix(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn sha256(b: &[u8]) -> String {
        use sha2::Digest as _;
        hex(&sha2::Sha256::digest(b))
    }

    /// A bridge root under /tmp (socket paths stay short) with `[relay] grant = "default"` and worker `worker-a`.
    fn root() -> (tempfile::TempDir, Paths) {
        let t = tempfile::Builder::new().prefix("aer").tempdir_in("/tmp").unwrap();
        let paths = Paths::from_root_and_env(t.path().join("b"), None);
        std::fs::create_dir_all(&paths.root).unwrap();
        std::fs::write(&paths.config, "[relay]\nworker_id = \"worker-a\"\ngrant = \"default\"\n").unwrap();
        (t, paths)
    }

    fn row(id: &str, egress: &str, gate: &str, status: RowStatus, wall: Option<u64>) -> VmRow {
        VmRow { id: id.into(), status, egress: egress.into(), egress_gate: Some(gate.into()), wall_deadline: wall, client_token: "0199a1b2-0000-7000-8000-0000000000a1".into(), ..VmRow::default() }
    }

    fn keys() -> MacKeys {
        MacKeys { worker_id: "worker-a".into(), worker: SigningKey::from_seed(&[1; 32]).unwrap(), session: SigningKey::from_seed(&[7; 32]).unwrap() }
    }

    /// The agent on `paths`' socket, its clock at `now`, its end `until`, answering this process's uid: the task,
    /// the clock, the socket, its stop.
    async fn start(paths: &Paths, now: u64, until: u64) -> (tokio::task::JoinHandle<Outcome>, Arc<TestClock>, PathBuf, tokio::sync::oneshot::Sender<()>) {
        start_as(paths, now, until, euid()).await
    }

    /// [`start`] with the uid the agent answers.
    async fn start_as(paths: &Paths, now: u64, until: u64, uid: u32) -> (tokio::task::JoinHandle<Outcome>, Arc<TestClock>, PathBuf, tokio::sync::oneshot::Sender<()>) {
        let socket = paths.relay_agent_socket();
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let (std_listener, bound) = bind(&socket).unwrap();
        let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
        let clock = Arc::new(TestClock(AtomicU64::new(now)));
        let state = AgentState { keys: keys(), until, paths: paths.clone(), socket: socket.clone(), bound, clock: Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>, euid: uid };
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve(state, listener, async move {
            let _ = rx.await;
        }));
        (task, clock, socket, tx)
    }

    async fn ask(socket: &Path, req: Request) -> Response {
        request(socket, &req, Duration::from_secs(5)).await.unwrap()
    }

    fn mint_req(vm: &str, grant: &str, exp: u64) -> Request {
        Request::MintSession(MintRequest { vm_id: vm.into(), session_id: SPAWN.into(), chat_id: None, grant_id: grant.into(), exp })
    }

    fn refused(r: &Response) -> &str {
        match r {
            Response::Refused { error, .. } => error,
            other => panic!("not a refusal: {other:?}"),
        }
    }

    /// WM-T37: an `AgentSigner` on the socket signs WM-T10's challenge with its known digest; another worker id
    /// is `wrong_worker`, another key `wrong_key`; a mint for the gated vpc VM answers a token `session::verify`
    /// takes, with the request's `exp`, clamped to 8 h and to the VM's wall; 30 s is `bad_request`; another VM,
    /// an internet one, one whose gate did not pass and a terminated one are `unknown_vm`; another grant is
    /// `unknown_grant`; `status` names both keys and the counts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_agent_signs_its_own_and_mints_bounded_tokens() {
        let (_t, paths) = root();
        let now = unix_now();
        write_row(&paths, &row(VM, "vpc", GATE_PASSED, RowStatus::Running, Some(now + 36_000))).unwrap();
        let (task, _clock, socket, stop) = start(&paths, now, now + 3600).await;
        // The worker's signer through the agent.
        let signer = ai_env_worker::signer::AgentSigner::connect(Some(socket.clone())).await.unwrap();
        use ai_env_worker::signer::Signer as _;
        assert_eq!(signer.bound_worker_id(), Some("worker-a"));
        assert_eq!(signer.public_key(), SigningKey::from_seed(&[1; 32]).unwrap().public_key());
        let challenge = ai_env_worker::signer::AuthChallenge { relay_id: "relay-test".into(), nonce: (0..32).collect(), worker_id: "worker-a".into(), protocol: 1 };
        let sig = signer.sign_worker_auth(&challenge).await.unwrap();
        assert_eq!(sha256(&sig), "b94fb69e27d782f3ba07b9bc73d443590a46f8b9126a092fe2cb854b175200a6", "WM-T10's vector");
        let worker_key = SigningKey::from_seed(&[1; 32]).unwrap().public_key();
        let sign = |worker_id: &str, key: PublicKey| Request::SignWorkerAuth(SignRequest { worker_id: worker_id.into(), relay_id: "relay-test".into(), nonce: vec![9; 32], alg: Alg::Ed25519, public_key: key, protocol: 1 });
        assert_eq!(refused(&ask(&socket, sign("other", worker_key)).await), "wrong_worker");
        assert_eq!(refused(&ask(&socket, sign("worker-a", SigningKey::from_seed(&[2; 32]).unwrap().public_key())).await), "wrong_key");
        // A token for the gated VM, verified with the session key.
        let session_key = SigningKey::from_seed(&[7; 32]).unwrap().public_key();
        let lookup = |kid: &str| (kid == "worker-a").then_some(SignerKey { public_key: session_key, not_after: now + 86_400 });
        let Response::Minted { token, exp } = ask(&socket, mint_req(VM, "default", now + 3600)).await else { panic!("no token") };
        assert_eq!(exp, now + 3600, "the request's exp");
        let v = session::verify(&token, now, &lookup).unwrap();
        assert_eq!((v.claims.vm_id.as_str(), v.claims.session_id.as_str(), v.claims.grant_id.as_str(), v.claims.kid.as_str(), v.claims.exp), (VM, SPAWN, "default", "worker-a", now + 3600));
        let Response::Status(st) = ask(&socket, Request::Status).await else { panic!("no status") };
        assert_eq!((st.worker_id.as_str(), st.worker_key, st.session_key, st.signed, st.minted), ("worker-a", worker_key, session_key, 1, 1));
        let Response::Minted { exp, .. } = ask(&socket, mint_req(VM, "default", now + 9 * 3600)).await else { panic!("no token") };
        assert_eq!(exp, now + 28_800, "at most 8 h");
        write_row(&paths, &row(VM, "vpc", GATE_PASSED, RowStatus::Running, Some(now + 3600))).unwrap();
        let Response::Minted { exp, .. } = ask(&socket, mint_req(VM, "default", now + 2 * 3600)).await else { panic!("no token") };
        assert_eq!(exp, now + 3600, "never past the VM's wall");
        assert_eq!(refused(&ask(&socket, mint_req(VM, "default", now + 30)).await), "bad_request", "under a minute");
        for (id, egress, gate, status) in [
            ("microvm-0199a1b2-0000-7000-8000-000000000009", "", "", RowStatus::Running),
            ("microvm-0199a1b2-0000-7000-8000-00000000000a", "internet", GATE_PASSED, RowStatus::Running),
            ("microvm-0199a1b2-0000-7000-8000-00000000000b", "vpc", "pending", RowStatus::Running),
            ("microvm-0199a1b2-0000-7000-8000-00000000000c", "vpc", GATE_PASSED, RowStatus::Terminated),
        ] {
            if !egress.is_empty() {
                write_row(&paths, &row(id, egress, gate, status, Some(now + 36_000))).unwrap();
            }
            assert_eq!(refused(&ask(&socket, mint_req(id, "default", now + 3600)).await), "unknown_vm", "{id} {egress} {gate} {status:?}");
        }
        assert_eq!(refused(&ask(&socket, mint_req(VM, "other", now + 3600)).await), "unknown_grant");
        stop.send(()).unwrap();
        let out = task.await.unwrap();
        assert_eq!(out, Outcome { end: End::Stopped, signed: 1, minted: 3 });
        assert!(!socket.exists(), "the socket goes with the agent");
    }

    /// WM-T38: the lock refuses a second agent (naming the first's pid); a leftover socket is replaced; a regular
    /// file is refused and left; a 104-byte socket path is refused before anything else; the socket is 0600; the
    /// peer check answers its own uid only (an agent answering another uid answers and mints nothing, `busy`
    /// included); the 17th connection is `busy`; a request over 4096 bytes `bad_request`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_agent_guards_its_socket() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_t, paths) = root();
        let socket = paths.relay_agent_socket();
        // A leftover socket (a crashed agent's) is removed; a regular file is refused and left as it is.
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        assert!(socket.exists());
        let lock = tokio::task::spawn_blocking({
            let p = paths.clone();
            move || prepare_socket(&p)
        })
        .await
        .unwrap()
        .unwrap();
        assert!(!socket.exists(), "the leftover socket is removed");
        drop(lock);
        std::fs::write(&socket, "not a socket").unwrap();
        let e = tokio::task::spawn_blocking({
            let p = paths.clone();
            move || prepare_socket(&p)
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().ends_with("exists and is not a socket: move it away"), "{e}");
        assert_eq!(std::fs::read_to_string(&socket).unwrap(), "not a socket", "left as it is");
        std::fs::remove_file(&socket).unwrap();
        // A running agent holds the lock: a second one names its pid.
        let now = unix_now();
        let held = tokio::task::spawn_blocking({
            let p = paths.clone();
            move || prepare_socket(&p)
        })
        .await
        .unwrap()
        .unwrap();
        let (task, _clock, socket, stop) = start(&paths, now, now + 3600).await;
        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the socket is 0600");
        let e = tokio::task::spawn_blocking({
            let p = paths.clone();
            move || prepare_socket(&p)
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().starts_with(&format!("another relay agent runs (pid {}, until ", std::process::id())), "{e}");
        // The peer check, as a rule and where it runs (M-WM36): an agent answering another uid (this one's plus
        // one) closes a status and a mint request unanswered and mints nothing; its `busy` answer is as silent.
        assert!(peer_ok(501, 501) && !peer_ok(502, 501) && !peer_ok(0, 501));
        let (_t2, other) = root();
        write_row(&other, &row(VM, "vpc", GATE_PASSED, RowStatus::Running, Some(now + 36_000))).unwrap();
        let (stranger, _clock2, socket2, stop2) = start_as(&other, now, now + 3600, euid().wrapping_add(1)).await;
        for req in [Request::Status, mint_req(VM, "default", now + 3600)] {
            let mut s = tokio::net::UnixStream::connect(&socket2).await.unwrap();
            let _ = s.write_all(&ai_env_worker::agent::encode_request(&req)).await;
            let mut answer = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut answer)).await.expect("closed at once");
            assert!(answer.is_empty(), "{req:?}: no answer to another uid: {}", String::from_utf8_lossy(&answer));
        }
        stop2.send(()).unwrap();
        assert_eq!(stranger.await.unwrap(), Outcome { end: End::Stopped, signed: 0, minted: 0 }, "nothing minted for another uid");
        let shared = |uid: u32| Shared { keys: keys(), until: now + 3600, paths: paths.clone(), clock: Arc::new(TestClock(AtomicU64::new(now))), euid: uid, signed: AtomicU64::new(0), minted: AtomicU64::new(0), active: AtomicUsize::new(0) };
        for (uid, answered) in [(euid(), true), (euid().wrapping_add(1), false)] {
            let (ours, mut theirs) = tokio::net::UnixStream::pair().unwrap();
            shared(uid).busy(ours).await;
            let mut answer = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(3), theirs.read_to_end(&mut answer)).await.expect("closed");
            if answered {
                assert_eq!(refused(&ai_env_worker::agent::decode_response(&answer).unwrap()), "busy");
            } else {
                assert!(answer.is_empty(), "busy answers another uid nothing: {}", String::from_utf8_lossy(&answer));
            }
        }
        // 16 connections at once; the 17th is busy.
        let mut held_open = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            held_open.push(tokio::net::UnixStream::connect(&socket).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut seventeenth = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), seventeenth.read_to_end(&mut answer)).await.unwrap().unwrap();
        assert_eq!(refused(&ai_env_worker::agent::decode_response(&answer).unwrap()), "busy");
        drop(held_open);
        tokio::time::sleep(Duration::from_millis(200)).await;
        // A request over 4096 bytes.
        let mut long = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let mut line = vec![b' '; REQUEST_MAX];
        line.push(b'\n');
        long.write_all(&line).await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), long.read_to_end(&mut answer)).await.unwrap().unwrap();
        assert_eq!(refused(&ai_env_worker::agent::decode_response(&answer).unwrap()), "bad_request");
        stop.send(()).unwrap();
        task.await.unwrap();
        drop(held);
        // A socket path of 104 bytes is refused before anything else.
        let t = tempfile::Builder::new().prefix("aer").tempdir_in("/tmp").unwrap();
        let tail = "/state/relay-agent.sock".len();
        let pad = 104 - tail - t.path().as_os_str().len() - 1;
        let long_root = t.path().join("p".repeat(pad));
        let long_paths = Paths::from_root_and_env(long_root, None);
        assert_eq!(long_paths.relay_agent_socket().as_os_str().len(), 104);
        let e = prepare_socket(&long_paths).unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("is 104 bytes, over the 103 a Unix socket path may hold: set AI_ENV_BRIDGE_DIR to a shorter directory"), "{e}");
        assert!(!long_paths.relay_agent_lock().exists(), "refused before the lock");
    }

    /// WM-T39: the agent's life is the wall clock's: with the clock seam past its end and the monotonic clock
    /// still, the next request is answered `expired`, `serve` returns `expired` and the socket is gone; a path
    /// replaced meanwhile by another file is left alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_agent_ends_by_the_wall_clock() {
        let (_t, paths) = root();
        let now = unix_now();
        let (task, clock, socket, _stop) = start(&paths, now, now + 3600).await;
        assert!(matches!(ask(&socket, Request::Status).await, Response::Status(_)));
        clock.0.store(now + 3601, Ordering::SeqCst);
        assert_eq!(refused(&ask(&socket, Request::Status).await), "expired");
        let out = tokio::time::timeout(Duration::from_secs(5), task).await.expect("serve ends").unwrap();
        assert_eq!(out.end, End::Expired);
        assert!(!socket.exists(), "the socket is gone");
        // The path replaced by another file meanwhile: left alone when the agent ends.
        let (task, _clock, socket, stop) = start(&paths, now, now + 3600).await;
        std::fs::remove_file(&socket).unwrap();
        std::fs::write(&socket, "someone else's").unwrap();
        assert!(tokio::net::UnixStream::connect(&socket).await.is_err(), "nothing listens at a regular file");
        stop.send(()).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), task).await.expect("serve ends").unwrap();
        assert_eq!(out.end, End::Stopped);
        assert_eq!(std::fs::read_to_string(&socket).unwrap(), "someone else's", "left alone");
    }
}
