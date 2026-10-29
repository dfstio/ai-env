//! `ai-env-relay-client serve` (V-R15 to V-R19, V-R22 to V-R28): one per relay spawn, as `ai-env-net`. It refuses
//! root, reads its session from fd 3 once, makes its socket in a directory only it may write, and serves one request
//! per connection to the spawn's processes alone (the agent's uid, the leader among their ancestors), at most
//! [`MAX_CONNS`] at once. It ends on SIGTERM or when its leader is gone. Its lines are §V-vm.3.8's alone: never the
//! token, the CA, a parameter, a result, a source or an op name.
use crate::dial::RelayLink;
use crate::local::{Answer, Code, Request, DEADLINE_CAP_MS, DEFAULT_MAX_BYTES, LOCAL_V, REQUEST_MAX};
use crate::peer::{admit, alive, parent_of};
use crate::session::{read_fd, Session};
use std::future::Future;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

/// Connections served at once; the next one is answered `busy`.
pub const MAX_CONNS: usize = 8;
/// A connection's request line must arrive within this.
pub const REQUEST_WAIT: Duration = Duration::from_secs(10);
/// How often the leader's life is checked.
pub const LEADER_POLL: Duration = Duration::from_secs(2);

/// `ai-env-relay-client serve`'s arguments (the shim's `relay::client_args`).
#[derive(clap::Args, Debug, Clone)]
pub struct ServeArgs {
    /// The relay spawn's leader (its claude): every peer descends from it, and the client ends when it is gone
    #[arg(long)]
    pub leader: u32,
    /// The socket to serve, in a directory the client owns and only it may write
    #[arg(long, value_name = "PATH")]
    pub socket: PathBuf,
    /// The agent's uid: the only peer uid admitted
    #[arg(long)]
    pub agent_uid: u32,
    /// Drop the relay channel after this long without a call (tests)
    #[arg(long, value_name = "MS", hide = true, default_value_t = 60_000)]
    pub channel_idle_ms: u64,
}

/// What the accept loop needs of the arguments.
pub struct ServeOpts {
    pub leader: u32,
    pub socket: PathBuf,
    pub agent_uid: u32,
}

/// One client line on stderr.
fn say(text: &str) {
    crate::line(&format!("ai-env-relay-client: {text}"));
}

/// `refused: <what>` and exit 2 (V-R15 to V-R17): nothing was served.
fn refused(what: &str) -> ExitCode {
    say(&format!("refused: {what}"));
    ExitCode::from(2)
}

/// The binary's `serve`: V-R15 to V-R17, then [`serve_on`] until SIGTERM or the leader is gone; the exit code (0 at
/// those ends, 2 for a refusal, 1 for a bind or runtime error).
pub fn main_serve(args: ServeArgs) -> ExitCode {
    // SAFETY: geteuid never fails.
    let euid = unsafe { libc::geteuid() };
    if let Err(what) = check_identity(euid) {
        return refused(what);
    }
    // No core dump and no ptrace by the same uid before the token is read (LD-V15).
    #[cfg(target_os = "linux")]
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) only clears this process's dumpable flag.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong);
    }
    let bytes = match read_fd(3) {
        Ok(b) => b,
        Err(e) if e.raw_os_error() == Some(libc::EBADF) => return refused("fd 3 is not open (the shim hands the session on fd 3)"),
        Err(e) => return refused(&format!("fd 3 cannot be read: {}", e.kind())),
    };
    let session = match Session::parse(&bytes) {
        Ok(s) => s,
        Err(e) => return refused(&format!("session {}", e.field())),
    };
    drop(bytes);
    let link = match RelayLink::new(&session, Duration::from_millis(args.channel_idle_ms)) {
        Ok(l) => l,
        Err(f) => return refused(&format!("session {}", link_field(&f))),
    };
    let ready = format!("ready leader={} socket={} relay={} name={} ca={}", args.leader, args.socket.display(), session.addr, session.server_name, session.ca_fingerprint());
    // The token's one copy is the link's metadata value from here (V-R16).
    drop(session);
    if let Err(why) = check_socket_dir(&args.socket, euid) {
        return refused(&format!("socket {why}"));
    }
    match std::fs::symlink_metadata(&args.socket) {
        // An earlier client's socket (one that was killed leaves it): bind over it.
        Ok(m) if m.file_type().is_socket() => {
            if let Err(e) = std::fs::remove_file(&args.socket) {
                return refused(&format!("socket {} cannot be replaced: {}", args.socket.display(), e.kind()));
            }
        }
        Ok(_) => return refused(&format!("socket {} exists and is not a socket", args.socket.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return refused(&format!("socket {}: {}", args.socket.display(), e.kind())),
    }
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            say(&format!("exit (error: cannot start the runtime: {e})"));
            return ExitCode::from(1);
        }
    };
    let code = rt.block_on(async move {
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                say(&format!("exit (error: cannot handle SIGTERM: {e})"));
                return ExitCode::from(1);
            }
        };
        let listener = match UnixListener::bind(&args.socket) {
            Ok(l) => l,
            Err(e) => {
                say(&format!("exit (error: bind {}: {e})", args.socket.display()));
                return ExitCode::from(1);
            }
        };
        // The 0750 directory is the gate (the agent's group may enter it): the socket itself is open.
        if let Err(e) = std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o666)) {
            say(&format!("exit (error: chmod {}: {e})", args.socket.display()));
            let _ = std::fs::remove_file(&args.socket);
            return ExitCode::from(1);
        }
        say(&ready);
        let why: Arc<Mutex<&'static str>> = Arc::new(Mutex::new("term"));
        let set = why.clone();
        let leader = args.leader;
        let stop = async move {
            let end = tokio::select! {
                _ = term.recv() => "term",
                () = leader_gone(leader) => "leader gone",
            };
            *set.lock().unwrap_or_else(PoisonError::into_inner) = end;
        };
        serve_on(listener, ServeOpts { leader, socket: args.socket.clone(), agent_uid: args.agent_uid }, Arc::new(link), stop).await;
        let end = *why.lock().unwrap_or_else(PoisonError::into_inner);
        say(&format!("exit ({end})"));
        ExitCode::SUCCESS
    });
    rt.shutdown_background();
    code
}

/// The session field a link refused (V-R16): the one its failure's message starts with ([`RelayLink::new`]).
fn link_field(f: &crate::dial::Failure) -> &'static str {
    ["token", "server_name"].into_iter().find(|field| f.message.starts_with(&format!("{field}: "))).unwrap_or("ca_der_b64")
}

/// Resolves once `kill(<leader>, 0)` fails with ESRCH, polled every [`LEADER_POLL`] (V-R27).
async fn leader_gone(leader: u32) {
    while alive(leader) {
        tokio::time::sleep(LEADER_POLL).await;
    }
}

/// The accept loop over a bound listener (the tests' and the lead's integration): each connection on its own task,
/// at most [`MAX_CONNS`]; when `stop` resolves it stops accepting, drops its calls and unlinks its socket (when it is
/// still a socket).
pub async fn serve_on(listener: UnixListener, opts: ServeOpts, link: Arc<RelayLink>, stop: impl Future<Output = ()>) {
    let opts = Arc::new(opts);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNS));
    let mut conns = tokio::task::JoinSet::new();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            () = &mut stop => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => match slots.clone().try_acquire_owned() {
                    Ok(permit) => {
                        conns.spawn(connection(stream, opts.clone(), link.clone(), permit));
                    }
                    Err(_) => {
                        say(&format!("busy ({MAX_CONNS} connections)"));
                        conns.spawn(async move {
                            let mut stream = stream;
                            let _ = write_answer(&mut stream, &Answer::error(Code::Busy, format!("{MAX_CONNS} calls in flight"))).await;
                        });
                    }
                },
                // Out of descriptors and the like: the next accept may work.
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    conns.shutdown().await;
    drop(listener);
    if std::fs::symlink_metadata(&opts.socket).is_ok_and(|m| m.file_type().is_socket()) {
        let _ = std::fs::remove_file(&opts.socket);
    }
}

/// An answer line must be taken within this, as the request line must arrive: a peer that stops reading frees its
/// slot then.
const ANSWER_WAIT: Duration = REQUEST_WAIT;

/// A listener at `path` for the MCP server's tests (`src/mcp.rs`): the crate makes its listeners in this file alone
/// (`make lint`), tests' included.
#[cfg(test)]
pub(crate) fn test_listener(path: &Path) -> std::io::Result<UnixListener> {
    UnixListener::bind(path)
}

/// One answer line, then the connection's end, within [`ANSWER_WAIT`].
async fn write_answer<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, answer: &Answer) -> std::io::Result<()> {
    write_answer_within(w, answer, ANSWER_WAIT).await
}

/// One answer line, then the connection's end, within `wait`: else `TimedOut`, and the caller drops the connection.
async fn write_answer_within<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, answer: &Answer, wait: Duration) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(answer).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let write = async {
        w.write_all(&line).await?;
        w.shutdown().await
    };
    tokio::time::timeout(wait, write).await.map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

/// One connection (V-R18, V-R19, V-R22 to V-R25): the peer, one request line within [`REQUEST_WAIT`], its answer.
async fn connection(mut stream: UnixStream, opts: Arc<ServeOpts>, link: Arc<RelayLink>, _slot: tokio::sync::OwnedSemaphorePermit) {
    let (uid, pid) = match stream.peer_cred() {
        Ok(c) => (Some(c.uid()), c.pid().and_then(|p| u32::try_from(p).ok())),
        Err(_) => (None, None),
    };
    let verdict = match uid {
        Some(uid) => admit(uid, pid, opts.agent_uid, opts.leader, parent_of),
        None => Err(crate::peer::Refusal::NoPid),
    };
    if let Err(r) = verdict {
        say(&format!("refused peer pid={} uid={} ({})", pid.map_or_else(|| "-".to_string(), |p| p.to_string()), uid.map_or_else(|| "-".to_string(), |u| u.to_string()), r.why()));
        let _ = write_answer(&mut stream, &Answer::error(Code::ForbiddenPeer, r.message())).await;
        return;
    }
    let (mut rd, mut wr) = stream.into_split();
    let (line, extra) = match tokio::time::timeout(REQUEST_WAIT, read_line(&mut rd)).await {
        Err(_) => {
            let _ = write_answer(&mut wr, &Answer::error(Code::BadRequest, format!("no request line within {} s", REQUEST_WAIT.as_secs()))).await;
            return;
        }
        Ok(Err(why)) => {
            let _ = write_answer(&mut wr, &Answer::error(Code::BadRequest, why)).await;
            return;
        }
        Ok(Ok(l)) => l,
    };
    let request = match serde_json::from_slice::<Request>(&line) {
        Ok(Request::Catalog { v, .. } | Request::Call { v, .. }) if v != LOCAL_V => Err(format!("v is {v} (this client speaks {LOCAL_V})")),
        Ok(r) => Ok(r),
        Err(_) => Err("not a request line (one JSON object: kind catalog or call, v 1)".to_string()),
    };
    let request = match request {
        Ok(r) => r,
        Err(why) => {
            let _ = write_answer(&mut wr, &Answer::error(Code::BadRequest, why)).await;
            return;
        }
    };
    // V-R24: EOF or any byte from the peer while the request runs drops it.
    let gone = Arc::new(AtomicBool::new(false));
    let cancel = {
        let gone = gone.clone();
        async move {
            if !extra {
                let mut byte = [0u8; 1];
                let _ = rd.read(&mut byte).await;
            }
            gone.store(true, Ordering::SeqCst);
        }
    };
    let started = Instant::now();
    let ms = || started.elapsed().as_millis();
    match request {
        Request::Catalog { source, .. } => {
            let answer = tokio::select! {
                r = link.catalog(source.as_deref()) => Some(r),
                () = cancel => None,
            };
            match answer {
                None => say(&format!("catalog outcome=cancelled sources=0 truncated=false ms={}", ms())),
                Some(Ok((sources, truncated))) => {
                    say(&format!("catalog outcome=ok sources={} truncated={truncated} ms={}", sources.len(), ms()));
                    let _ = write_answer(&mut wr, &Answer::Catalog { v: LOCAL_V, sources, truncated }).await;
                }
                Some(Err(f)) => {
                    say(&format!("catalog outcome={} sources=0 truncated=false ms={}", f.code.word(), ms()));
                    let _ = write_answer(&mut wr, &Answer::error(f.code, f.message)).await;
                }
            }
        }
        Request::Call { source, op, params, max_bytes, deadline_ms, .. } => {
            let params = match params {
                serde_json::Value::Null => serde_json::Value::Object(serde_json::Map::new()),
                p @ serde_json::Value::Object(_) => p,
                _ => {
                    say(&format!("call - outcome=bad_request bytes=0 truncated=false ms={}", ms()));
                    let _ = write_answer(&mut wr, &Answer::error(Code::BadRequest, "params must be a JSON object")).await;
                    return;
                }
            };
            let deadline = match deadline_ms {
                Some(d) if d > DEADLINE_CAP_MS => {
                    say(&format!("call - outcome=bad_request bytes=0 truncated=false ms={}", ms()));
                    let _ = write_answer(&mut wr, &Answer::error(Code::BadRequest, format!("deadline_ms is {d} (at most {DEADLINE_CAP_MS})"))).await;
                    return;
                }
                d => d.unwrap_or(0),
            };
            let r = link.call(&source, &op, &params, max_bytes.unwrap_or(DEFAULT_MAX_BYTES), deadline, cancel).await;
            match r {
                // `<request_id|->`: the relay's id when it named the call (its status, its stream's head, its error
                // chunk), `-` when it never did or not with a canonical UUID (`log_id`); a caller that went away gets
                // `cancelled` and no answer.
                Err(f) => {
                    let caller_gone = gone.load(Ordering::SeqCst);
                    let outcome = if caller_gone { "cancelled" } else { f.code.word() };
                    say(&format!("call {} outcome={outcome} bytes=0 truncated=false ms={}", log_id(f.request_id.as_deref().unwrap_or_default()), ms()));
                    if !caller_gone {
                        let _ = write_answer(&mut wr, &Answer::error(f.code, f.message)).await;
                    }
                }
                Ok(out) => {
                    let bytes = u64::try_from(out.data.len()).unwrap_or(u64::MAX);
                    say(&format!("call {} outcome=ok bytes={bytes} truncated={} ms={}", log_id(&out.request_id), out.truncated, ms()));
                    let body = crate::convert::body_of_output(&out.content_type, &out.data, out.truncated);
                    let answer = Answer::Result { v: LOCAL_V, request_id: out.request_id, content_type: out.content_type, truncated: out.truncated, bytes, limit: out.limit, body };
                    let _ = write_answer(&mut wr, &answer).await;
                }
            }
        }
    }
}

/// A request id for a line: the relay's UUID (R-30) as it sent it when it is in the canonical lowercase `8-4-4-4-12`
/// hex form (WM-R2's `valid_uuid`), else `-` (relay text never forges a line).
fn log_id(id: &str) -> String {
    let uuid = id.len() == 36
        && id.bytes().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        });
    if uuid {
        id.to_string()
    } else {
        "-".to_string()
    }
}

/// The request line (without its newline, at most [`REQUEST_MAX`] bytes), and whether bytes followed it.
async fn read_line(rd: &mut tokio::net::unix::OwnedReadHalf) -> Result<(Vec<u8>, bool), String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = rd.read(&mut chunk).await.map_err(|e| format!("the request could not be read: {}", e.kind()))?;
        if n == 0 {
            return Err("the connection ended before a request line".to_string());
        }
        let from = buf.len();
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf[from..].iter().position(|b| *b == b'\n').map(|i| from + i) {
            if i > REQUEST_MAX {
                break;
            }
            let extra = buf.len() > i + 1;
            buf.truncate(i);
            return Ok((buf, extra));
        }
        if buf.len() > REQUEST_MAX {
            break;
        }
    }
    Err(format!("the request line is over {REQUEST_MAX} bytes"))
}

/// The client never runs as root (LD-V15: the shim always drops it to `ai-env-net`).
pub fn check_identity(euid: u32) -> Result<(), &'static str> {
    if euid == 0 {
        return Err("runs as root");
    }
    Ok(())
}

/// V-R17: `socket` absolute, its directory a real directory (never a symlink) owned by `euid` and writable by nobody
/// else. The message names the path and what is wrong, never a value.
pub fn check_socket_dir(socket: &Path, euid: u32) -> Result<(), String> {
    if !socket.is_absolute() {
        return Err(format!("{} is not absolute", socket.display()));
    }
    let Some(dir) = socket.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return Err(format!("{} has no directory", socket.display()));
    };
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {}", dir.display(), e.kind()))?;
    if m.file_type().is_symlink() {
        return Err(format!("{} is a symlink", dir.display()));
    }
    if !m.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if m.uid() != euid {
        return Err(format!("{} is owned by uid {}, not this client's {euid}", dir.display(), m.uid()));
    }
    let mode = m.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(format!("{} is mode {mode:04o}: writable by others", dir.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// euid 0 is refused, any other accepted.
    #[test]
    fn check_identity_refuses_root() {
        assert_eq!(check_identity(0), Err("runs as root"));
        assert_eq!(check_identity(999), Ok(()));
        assert_eq!(check_identity(1000), Ok(()));
    }

    /// A 0770 or 0757 directory, another owner's, a symlink or a relative path is refused; a 0750 own directory
    /// accepted.
    #[test]
    fn check_socket_dir_refuses_a_shared_dir() {
        let t = tempfile::tempdir().unwrap();
        // SAFETY: geteuid never fails.
        let me = unsafe { libc::geteuid() };
        let dir = t.path().join("relay");
        std::fs::create_dir(&dir).unwrap();
        let sock = dir.join("42.sock");
        let set = |mode: u32| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        set(0o750);
        assert_eq!(check_socket_dir(&sock, me), Ok(()));
        for mode in [0o770, 0o757, 0o777] {
            set(mode);
            let e = check_socket_dir(&sock, me).unwrap_err();
            assert!(e.contains("writable by others") && e.contains(&format!("{mode:04o}")), "{mode:o}: {e}");
        }
        set(0o750);
        let e = check_socket_dir(&sock, me + 1).unwrap_err();
        assert!(e.contains("is owned by uid"), "{e}");
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(check_socket_dir(&link.join("42.sock"), me).unwrap_err().contains("is a symlink"));
        assert!(check_socket_dir(Path::new("relay/42.sock"), me).unwrap_err().contains("not absolute"));
        assert!(check_socket_dir(&t.path().join("missing/42.sock"), me).is_err());
        std::fs::write(t.path().join("file"), "").unwrap();
        assert!(check_socket_dir(&t.path().join("file/42.sock"), me).unwrap_err().contains("not a directory"));
    }

    /// A relay's request id reaches a line as it is when it is a canonical UUID, anything else as `-`: a line break,
    /// 36 characters that are no UUID, upper-case hex, a hyphen out of place, a character past the 36th. Kills M-V67.
    #[test]
    fn a_log_id_is_the_uuid_or_a_dash() {
        assert_eq!(log_id("0199a1b2-0000-7000-8000-00000000000a"), "0199a1b2-0000-7000-8000-00000000000a");
        assert_eq!(log_id(""), "-");
        assert_eq!(log_id("x\nai-env-relay-client: forged"), "-");
        assert_eq!(log_id(&"a".repeat(65)), "-");
        assert_eq!(log_id(&"a".repeat(36)), "-");
        assert_eq!(log_id("0199A1B2-0000-7000-8000-00000000000A"), "-");
        assert_eq!(log_id("0199a1b20-000-7000-8000-00000000000a"), "-");
        assert_eq!(log_id("0199a1b2-0000-7000-8000-00000000000g"), "-");
        assert_eq!(log_id("0199a1b2-0000-7000-8000-00000000000a0"), "-");
    }

    /// An answer its peer never reads is given up after its wait (`TimedOut`), so the slot is freed; one that is read
    /// arrives whole, its line then EOF. Control.
    #[tokio::test]
    async fn an_answer_nobody_reads_is_given_up_after_its_wait() {
        let answer = Answer::error(Code::Internal, "x".repeat(4096));
        let (mut ours, _theirs) = tokio::io::duplex(64);
        let r = tokio::time::timeout(Duration::from_secs(5), write_answer_within(&mut ours, &answer, Duration::from_millis(100))).await;
        assert_eq!(r.expect("given up within its wait, not hung").unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        let (mut ours, mut theirs) = tokio::io::duplex(64);
        let (written, read) = tokio::join!(write_answer_within(&mut ours, &answer, Duration::from_secs(5)), async {
            let mut got = Vec::new();
            theirs.read_to_end(&mut got).await.map(|_| got)
        });
        written.unwrap();
        assert_eq!(read.unwrap(), [serde_json::to_vec(&answer).unwrap(), b"\n".to_vec()].concat());
    }

    /// A link's failure names its session field: `token: …` and `server_name: …` as theirs, the CA's otherwise
    /// (`refused: session <field>`, V-R16). Control.
    #[test]
    fn a_link_failure_names_its_session_field() {
        let f = |m: &str| crate::dial::Failure::new(Code::BadRequest, m);
        assert_eq!(link_field(&f("token: not a metadata value")), "token");
        assert_eq!(link_field(&f("server_name: not an IPv4 address or a DNS name")), "server_name");
        assert_eq!(link_field(&f("ca_der_b64: the relay CA is not a certificate: x")), "ca_der_b64");
        assert_eq!(link_field(&f("tokenish")), "ca_der_b64");
    }
}
