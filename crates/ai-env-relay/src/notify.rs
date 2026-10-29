//! sd_notify datagrams and the watchdog interval (R-69 to R-71, D-5). The unit is `Type=notify` with
//! `WatchdogSec=30`: READY once both faces are bound, a ping every third of the watchdog period, STOPPING at a stop.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Duration;

/// The systemd notifier.
pub struct Notifier {
    socket: Option<PathBuf>,
}

impl Notifier {
    /// NOTIFY_SOCKET (a path, or `@name` on Linux); the variable is never unset.
    pub fn from_env() -> Notifier {
        let socket = std::env::var_os("NOTIFY_SOCKET").filter(|v| !v.is_empty()).map(PathBuf::from);
        Notifier { socket }
    }

    /// A notifier on this socket.
    pub fn with_socket(path: PathBuf) -> Notifier {
        Notifier { socket: Some(path) }
    }

    /// A notifier that sends nothing.
    pub fn disabled() -> Notifier {
        Notifier { socket: None }
    }

    /// `READY=1\nSTATUS=<status>\n`.
    pub fn ready(&self, status: &str) {
        self.send(&format!("READY=1\nSTATUS={status}\n"));
    }

    /// `WATCHDOG=1\n`.
    pub fn watchdog(&self) {
        self.send("WATCHDOG=1\n");
    }

    /// `STOPPING=1\n`.
    pub fn stopping(&self) {
        self.send("STOPPING=1\n");
    }

    /// `STATUS=<status>\n`.
    pub fn status(&self, status: &str) {
        self.send(&format!("STATUS={status}\n"));
    }

    /// One datagram; a failure is logged and never stops the relay (systemd's watchdog notices a silent one).
    fn send(&self, msg: &str) {
        let Some(path) = &self.socket else { return };
        let sent = UnixDatagram::unbound().and_then(|sock| send_to(&sock, msg.as_bytes(), path));
        if let Err(e) = sent {
            tracing::debug!("sd_notify: {e}");
        }
    }
}

#[cfg(target_os = "linux")]
fn send_to(sock: &UnixDatagram, msg: &[u8], path: &std::path::Path) -> std::io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
        return sock.send_to_addr(msg, &addr).map(drop);
    }
    sock.send_to(msg, path).map(drop)
}

#[cfg(not(target_os = "linux"))]
fn send_to(sock: &UnixDatagram, msg: &[u8], path: &std::path::Path) -> std::io::Result<()> {
    sock.send_to(msg, path).map(drop)
}

/// A third of WATCHDOG_USEC when WATCHDOG_PID is `own_pid` or absent; None otherwise.
pub fn watchdog_interval(usec: Option<&str>, pid: Option<&str>, own_pid: u32) -> Option<Duration> {
    let usec: u64 = usec?.trim().parse().ok()?;
    if let Some(pid) = pid {
        if pid.trim().parse::<u32>().ok() != Some(own_pid) {
            return None;
        }
    }
    // Never a zero period (0 to 2 µs): `tokio::time::interval` panics on one.
    Some(Duration::from_micros(usec / 3)).filter(|every| !every.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit 27.
    #[test]
    fn notify_writes_systemd_datagrams() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let server = UnixDatagram::bind(&path).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let n = Notifier::with_socket(path.clone());
        let mut buf = [0u8; 256];
        let mut next = || {
            let len = server.recv(&mut buf).unwrap();
            String::from_utf8(buf[..len].to_vec()).unwrap()
        };
        n.ready("x");
        assert_eq!(next(), "READY=1\nSTATUS=x\n");
        n.watchdog();
        assert_eq!(next(), "WATCHDOG=1\n");
        n.stopping();
        assert_eq!(next(), "STOPPING=1\n");
        n.status("tunnels=1");
        assert_eq!(next(), "STATUS=tunnels=1\n");
        Notifier::disabled().ready("y");
        server.set_nonblocking(true).unwrap();
        assert!(server.recv(&mut buf).is_err(), "a disabled notifier sends nothing");

        let me = std::process::id();
        let own = me.to_string();
        assert_eq!(watchdog_interval(Some("30000000"), Some(&own), me), Some(Duration::from_secs(10)));
        assert_eq!(watchdog_interval(Some("30000000"), Some(&(me + 1).to_string()), me), None);
        assert_eq!(watchdog_interval(Some("30000000"), None, me), Some(Duration::from_secs(10)));
        assert_eq!(watchdog_interval(None, Some(&own), me), None);
        // A third that rounds to nothing is no interval: `tokio::time::interval` panics on a zero period.
        for usec in ["0", "2"] {
            assert_eq!(watchdog_interval(Some(usec), None, me), None, "{usec}");
        }
        assert_eq!(watchdog_interval(Some("3"), None, me), Some(Duration::from_micros(1)));
    }
}
