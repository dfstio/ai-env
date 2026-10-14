//! S8 (wave 2, W6): the Mac's way into a container with no route out.
//! Docker publishes no port of a container on `--network none` (its
//! loopback alone) or on an internal network only, and the pinned claude
//! only ever runs in such a container (never with a route to the
//! internet). A [`Tunnel`]
//! listens on 127.0.0.1 on the Mac and carries each connection it accepts
//! into the container through a `docker exec -i` of its own, as root: bash
//! there opens `/dev/tcp/127.0.0.1/<port>`, two `cat`s copy the bytes both
//! ways, and the first side to end ends both. The shim sees a local root
//! client with a live socket row, which its peer guard admits as it admits
//! the platform (and refuses the agent's). Every connection the tunnel made
//! inside is counted ([`Tunnel::connects`]), so a test can hold the
//! container's own TCP counters to exactly those: a connection anything else
//! there made (the claude under test) shows. Included by
//! `tests/docker_exec.rs` with `#[path]`.

use std::io::{Read, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// What one connection runs in the container (`$1` the port): the
/// connect, then `c` on stderr (counted), then the two copies. stdin is
/// taken through fd 4 (bash gives a background job /dev/null for a stdin it
/// does not redirect); `wait -n` returns at the first copy's end, and the
/// other is ended with it, so the socket closes as soon as either side
/// closed theirs.
const SCRIPT: &str = "exec 3<>\"/dev/tcp/127.0.0.1/$1\" || exit 7
printf c >&2
exec 4<&0
cat <&3 & r=$!
cat <&4 >&3 & w=$!
wait -n
kill \"$r\" \"$w\" 2>/dev/null
wait
exit 0";

/// How often a carried connection looks whether its `docker exec` ended,
/// and the acceptor for a new connection.
const POLL: Duration = Duration::from_millis(5);

struct Shared {
    container: String,
    port: u16,
    stop: AtomicBool,
    connects: AtomicU32,
    sessions: Mutex<Vec<JoinHandle<()>>>,
}

/// A port of the container on 127.0.0.1 of the Mac (the module doc). Its
/// threads and the `docker exec` of every connection still carried end when
/// it is dropped; drop it after the container, whose removal ends what runs
/// inside.
pub struct Tunnel {
    /// Where the Mac connects.
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    acceptor: Option<JoinHandle<()>>,
}

impl Tunnel {
    /// Carry connections to `port` of `container` (its name or id).
    #[must_use]
    pub fn open(container: &str, port: u16) -> Tunnel {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a tunnel");
        listener.set_nonblocking(true).expect("a nonblocking tunnel listener");
        let addr = listener.local_addr().expect("the tunnel's address");
        let shared = Arc::new(Shared { container: container.to_string(), port, stop: AtomicBool::new(false), connects: AtomicU32::new(0), sessions: Mutex::new(Vec::new()) });
        let s = shared.clone();
        let acceptor = std::thread::Builder::new().name(format!("tunnel-{port}")).spawn(move || accept(&listener, &s)).expect("the tunnel's thread");
        Tunnel { addr, shared, acceptor: Some(acceptor) }
    }

    /// The connections the tunnel made inside the container so far: each
    /// one an active open there that was not refused (the shim took it).
    #[must_use]
    pub fn connects(&self) -> u32 {
        self.shared.connects.load(Ordering::SeqCst)
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.acceptor.take() {
            let _ = t.join();
        }
        let sessions = std::mem::take(&mut *self.shared.sessions.lock().unwrap());
        for t in sessions {
            let _ = t.join();
        }
    }
}

fn accept(listener: &TcpListener, s: &Arc<Shared>) {
    while !s.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let shared = s.clone();
                let carried = std::thread::Builder::new().name(format!("tunnel-{}-conn", s.port)).spawn(move || carry(stream, &shared)).expect("a tunnel connection's thread");
                s.sessions.lock().unwrap().push(carried);
            }
            Err(_) => std::thread::sleep(POLL),
        }
    }
}

/// One connection, to its end: its `docker exec`, a thread each way and
/// one for the mark on stderr. Once the exec ended (either side closed,
/// or the tunnel stops: then it is killed) the Mac's socket is shut both
/// ways, which ends the copy still reading it.
fn carry(stream: TcpStream, s: &Arc<Shared>) {
    // macOS hands the listener's nonblocking flag on to an accepted socket.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    let port = s.port.to_string();
    let spawned = Command::new("docker")
        .args(["exec", "-i", "-u", "0", &s.container, "bash", "-c", SCRIPT, "tunnel", &port])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let Ok(mut child) = spawned else {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    };
    let (Some(mut stdin), Some(mut stdout), Some(mut stderr), Ok(mut from), Ok(mut to)) = (child.stdin.take(), child.stdout.take(), child.stderr.take(), stream.try_clone(), stream.try_clone()) else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = stream.shutdown(Shutdown::Both);
        return;
    };
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut from, &mut stdin);
        // stdin dropped: the copy into the container's socket ends.
    });
    let down = std::thread::spawn(move || {
        let _ = std::io::copy(&mut stdout, &mut to);
        let _ = to.flush();
        let _ = to.shutdown(Shutdown::Write);
    });
    // The mark comes first on stderr; a failed connect's error (bash's own,
    // `tunnel: line 1: …`) comes instead, and is read away.
    let shared = s.clone();
    let rest = std::thread::spawn(move || {
        let mut mark = [0u8; 1];
        if matches!(stderr.read(&mut mark), Ok(1)) && mark == *b"c" {
            shared.connects.fetch_add(1, Ordering::SeqCst);
        }
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
    });
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) if s.stop.load(Ordering::SeqCst) => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            Ok(None) => std::thread::sleep(POLL),
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    for t in [up, down, rest] {
        let _ = t.join();
    }
}
