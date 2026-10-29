//! S13 (plans/s13-contracts.md §V-vm): a spawn's relay session in the VM. The shim starts the spawn's relay client
//! (`ai-env-relay-client serve …`) as `ai-env-net` right after the spawn's leader, its session JSON on fd 3 alone
//! (`childproc::spawn_relay_client`), and ends it with its leader. The client serves `<SOCKET_DIR>/<leader>.sock` to
//! that spawn's processes. Not S11's claude relay (`claudebin::relay`).
//!
//! The shim keeps no copy of the session (VC-2): the request's `RelaySpawn` and the payload are dropped (zeroized)
//! before `spawned` goes out, and a client is never restarted (V-R9). Its lines are §V-vm.3.8's: never the token,
//! `ca_der_b64` or the session JSON.
use crate::shim::health::ShimOpts;
use crate::shim::spawn::log;
use crate::wire::frame::SpawnId;
use crate::wire::relay::{socket_path, RelaySpawn, RUN_DIR, SOCKET_DIR};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The relay is built (S13): `relay_v1` can be named (the S9-to-S11 served-flag pattern; `true` from V's wave 1).
pub const SERVED: bool = true;

/// A client's stderr line is cut at this many characters in the shim's log.
const LINE_CHARS: usize = 300;
/// A client's stderr line is read up to this many bytes; the rest of it is dropped.
const LINE_BYTES: usize = 4096;

/// What the spawn manager needs to start relay clients: `SpawnOpts.relay`, set exactly when the shim names `relay_v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOpts {
    /// The client program (`ShimOpts.relay_client`).
    pub client: PathBuf,
    /// The MCP config claude is given (`ShimOpts.relay_mcp_config`).
    pub mcp_config: PathBuf,
    /// `wire::relay::RUN_DIR` and `SOCKET_DIR`, under `--fs-root` when set.
    pub run_dir: PathBuf,
    pub socket_dir: PathBuf,
    /// `ai-env-net` (`NET_UID`, `NET_GID`) when the shim is root; `None` natively (the client runs as the shim's uid).
    pub net: Option<(u32, u32)>,
    /// The agent's uid and gid (`--uid`, `--gid`): the client's `--agent-uid`, the socket directory's group.
    pub agent: (u32, u32),
}

/// `Some` when [`SERVED`], the shim is root or has `--fs-root`, and both files are regular files now (V-R6: a link
/// to a file counts, which only native tests use).
#[must_use]
pub fn opts_for(opts: &ShimOpts) -> Option<RelayOpts> {
    let root = nix::unistd::geteuid().is_root();
    if !SERVED || !(root || opts.fs_root.is_some()) {
        return None;
    }
    let file = |p: &Path| std::fs::metadata(p).is_ok_and(|m| m.is_file());
    if !file(&opts.relay_client) || !file(&opts.relay_mcp_config) {
        return None;
    }
    let vm = |path: &str| match &opts.fs_root {
        Some(r) => r.join(path.trim_start_matches('/')),
        None => PathBuf::from(path),
    };
    Some(RelayOpts {
        client: opts.relay_client.clone(),
        mcp_config: opts.relay_mcp_config.clone(),
        run_dir: vm(RUN_DIR),
        socket_dir: vm(SOCKET_DIR),
        net: root.then_some((opts.net_uid, opts.net_gid)),
        agent: (opts.uid, opts.gid),
    })
}

/// One directory as the relay wants it: made when missing; reset (one log line) when it has another mode or owner;
/// refused when a symlink or a non-directory stands there. `owner` `None`: the shim's own (natively; no chown).
fn ensure_dir(path: &Path, mode: u32, owner: Option<(u32, u32)>) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(format!("{} is a symlink", path.display())),
        Ok(m) if !m.is_dir() => Err(format!("{} is not a directory", path.display())),
        Ok(m) => {
            let (was_mode, was_owner) = (m.mode() & 0o7777, (m.uid(), m.gid()));
            let wrong_owner = owner.filter(|o| *o != was_owner);
            if was_mode == mode && wrong_owner.is_none() {
                return Ok(());
            }
            if let Some((uid, gid)) = wrong_owner {
                std::os::unix::fs::lchown(path, Some(uid), Some(gid)).map_err(|e| format!("{}: chown: {e}", path.display()))?;
            }
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("{}: chmod: {e}", path.display()))?;
            let owner_text = owner.map_or_else(String::new, |(u, g)| format!(" {u}:{g}"));
            log(&format!("ai-env: relay dir {} reset to {mode:04o}{owner_text} (it was {was_mode:04o} {}:{})", path.display(), was_owner.0, was_owner.1));
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).map_err(|e| format!("{}: mkdir: {e}", path.display()))?;
            if let Some((uid, gid)) = owner {
                std::os::unix::fs::lchown(path, Some(uid), Some(gid)).map_err(|e| format!("{}: chown: {e}", path.display()))?;
            }
            // The umask may have taken bits off: the mode is set, not asked for.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("{}: chmod: {e}", path.display()))
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// [`RelayOpts::run_dir`] and [`RelayOpts::socket_dir`] with their owners and modes (V-R10): the run dir 0755 (root's
/// when root), the socket dir 0750 `NET_UID:<agent gid>` when root (natively the shim's own). The shim never writes
/// inside the socket dir but to unlink a client's socket.
pub(crate) fn prepare_dir(o: &RelayOpts) -> Result<(), String> {
    // The VM's `/run` is always there; under `--fs-root` (native tests) it may not be yet.
    if let Some(parent) = o.run_dir.parent().filter(|p| !p.exists()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: mkdir: {e}", parent.display()))?;
    }
    ensure_dir(&o.run_dir, 0o755, o.net.map(|_| (0, 0)))?;
    ensure_dir(&o.socket_dir, 0o750, o.net.map(|(uid, _)| (uid, o.agent.1)))
}

/// `["serve", "--leader", "<leader>", "--socket", "<socket_dir>/<leader>.sock", "--agent-uid", "<uid>"]`.
pub(crate) fn client_args(o: &RelayOpts, leader: u32) -> Vec<String> {
    vec![
        "serve".to_string(),
        "--leader".to_string(),
        leader.to_string(),
        "--socket".to_string(),
        socket_path(&o.socket_dir, leader).to_string_lossy().into_owned(),
        "--agent-uid".to_string(),
        o.agent.0.to_string(),
    ]
}

/// A started client: its pid (it leads its own group) and whether its watcher reaped it.
#[derive(Debug, Clone)]
pub(crate) struct RelayClient {
    pub(crate) pid: u32,
    ended: Arc<AtomicBool>,
}

impl RelayClient {
    /// `killpg(pid, sig)`, only while the watcher has not reaped it.
    pub(crate) fn signal(&self, sig: i32) {
        if !self.ended.load(Ordering::SeqCst) {
            crate::shim::spawn::killpg(self.pid, sig);
        }
    }

    /// Whether its watcher saw it end (the shim's stops wait for it).
    pub(crate) fn ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}

/// [`prepare_dir`], then the client (V-R8) and its watcher (V-R12); its log line. The error names the step.
pub(crate) fn start(o: &RelayOpts, id: &SpawnId, leader: u32, relay: &RelaySpawn) -> Result<RelayClient, String> {
    prepare_dir(o)?;
    let socket = socket_path(&o.socket_dir, leader);
    let mut child = {
        // The payload (the token is in it) lives only until the pipe holds it (zeroized on drop).
        let session = relay.session();
        crate::shim::childproc::spawn_relay_client(&o.client, &client_args(o, leader), o.net, &session).map_err(|e| format!("{}: {e}", o.client.display()))?
    };
    let Some(pid) = child.id() else {
        return Err(format!("{} exited before it was registered", o.client.display()));
    };
    // SAFETY: geteuid never fails.
    let uid = o.net.map_or_else(|| unsafe { libc::geteuid() }, |(u, _)| u);
    log(&format!("ai-env: relay {id} client pid={pid} uid={uid} socket={}", socket.display()));
    let ended = Arc::new(AtomicBool::new(false));
    let stderr = child.stderr.take();
    tokio::spawn(watch(id.clone(), child, pid, stderr, ended.clone(), socket));
    Ok(RelayClient { pid, ended })
}

/// One stderr line of the client for the shim's log: scrubbed (`wire::redact::scrub`), control characters dropped,
/// at most [`LINE_CHARS`] characters.
fn client_line(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    crate::wire::redact::scrub(&text).chars().filter(|c| !c.is_control()).take(LINE_CHARS).collect()
}

/// V-R12: the client's stderr to EOF, each line logged; then it is reaped (its death seen first without reaping, so
/// no signal ever reaches a reused pid), `ended` set, `client ended` logged, and its socket unlinked when it is still
/// a socket.
async fn watch(id: SpawnId, mut child: tokio::process::Child, pid: u32, stderr: Option<tokio::process::ChildStderr>, ended: Arc<AtomicBool>, socket: PathBuf) {
    use tokio::io::AsyncBufReadExt as _;
    if let Some(err) = stderr {
        let mut r = tokio::io::BufReader::new(err);
        let mut line: Vec<u8> = Vec::new();
        while let Ok(buf) = r.fill_buf().await {
            if buf.is_empty() {
                if !line.is_empty() {
                    log(&format!("ai-env: relay {id} {}", client_line(&line)));
                }
                break;
            }
            let (take, done) = buf.iter().position(|b| *b == b'\n').map_or((buf.len(), false), |i| (i + 1, true));
            let room = LINE_BYTES.saturating_sub(line.len());
            line.extend_from_slice(&buf[..(if done { take - 1 } else { take }).min(room)]);
            r.consume(take);
            if done {
                log(&format!("ai-env: relay {id} {}", client_line(&line)));
                line.clear();
            }
        }
    }
    if let Ok(p) = libc::pid_t::try_from(pid) {
        let _ = tokio::task::spawn_blocking(move || crate::shim::spawn::wait_exited(p)).await;
    }
    ended.store(true, Ordering::SeqCst);
    let (code, signal) = match child.wait().await {
        Ok(s) => (s.code(), std::os::unix::process::ExitStatusExt::signal(&s)),
        Err(_) => (None, None),
    };
    let word = |v: Option<i32>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
    log(&format!("ai-env: relay {id} client ended code={} signal={}", word(code), word(signal)));
    if std::fs::symlink_metadata(&socket).is_ok_and(|m| m.file_type().is_socket()) {
        let _ = std::fs::remove_file(&socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts_in(root: &Path) -> RelayOpts {
        RelayOpts { client: root.join("client"), mcp_config: root.join("relay-mcp.json"), run_dir: root.join("run/ai-env"), socket_dir: root.join("run/ai-env/relay"), net: None, agent: (1000, 1000) }
    }

    /// The client's argv after its program: `serve`, the leader, its socket under the socket dir, the agent's uid.
    /// Control.
    #[test]
    fn the_client_args_name_the_leader_its_socket_and_the_agent() {
        let o = RelayOpts { socket_dir: PathBuf::from(SOCKET_DIR), ..opts_in(Path::new("/x")) };
        assert_eq!(client_args(&o, 4242), ["serve", "--leader", "4242", "--socket", "/run/ai-env/relay/4242.sock", "--agent-uid", "1000"]);
    }

    /// A line of the client's stderr: scrubbed, one line, at most 300 characters. Control.
    #[test]
    fn a_client_line_is_scrubbed_and_cut() {
        assert_eq!(client_line(b"ai-env-relay-client: ready leader=1"), "ai-env-relay-client: ready leader=1");
        assert_eq!(client_line("x\r\u{1b}[2Ky".as_bytes()), "x[2Ky");
        assert_eq!(client_line(&[b'a'; 400]).len(), LINE_CHARS);
        let shown = client_line(format!("token={}", "Q".repeat(40)).as_bytes());
        assert!(!shown.contains(&"Q".repeat(40)), "{shown}");
    }

    /// A missing directory is made with its mode; one with another mode is reset; a symlink or a file is refused,
    /// naming the path. Control (the spawn's test proves it through `start`).
    #[test]
    fn ensure_dir_makes_resets_or_refuses() {
        let t = tempfile::tempdir().unwrap();
        let o = opts_in(t.path());
        prepare_dir(&o).unwrap();
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().mode() & 0o7777;
        assert_eq!((mode(&o.run_dir), mode(&o.socket_dir)), (0o755, 0o750));
        std::fs::set_permissions(&o.socket_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        prepare_dir(&o).unwrap();
        assert_eq!(mode(&o.socket_dir), 0o750);
        std::fs::remove_dir(&o.socket_dir).unwrap();
        std::fs::write(&o.socket_dir, "").unwrap();
        assert!(prepare_dir(&o).unwrap_err().contains("is not a directory"));
    }
}
