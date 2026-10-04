//! The capability-free peer guard (plan S6 D1). The platform POSTs every hook
//! from 127.0.0.1 (measured S3–S5), so a source address cannot tell the
//! platform from the agent. Socket ownership can: for a client in this VM's
//! network namespace, `/proc/net/tcp` (and `tcp6`, where v4-mapped clients
//! appear) lists the client's own end with the uid that created the socket
//! and its inode. The guard admits a local client only when that row is
//! found, its inode is not 0 (an orphaned or TIME_WAIT socket shows uid 0 and
//! inode 0: a uid-1000 client that sent and closed before the lookup would
//! otherwise pass as root) and its uid is not the agent's (`--uid`). Every
//! agent process runs under NO_NEW_PRIVS, so no setuid binary or file
//! capability gives it another uid, and a socket's owner is fixed at
//! creation. A client whose address is not one of ours and whose socket has
//! no row here is remote (the endpoint proxy outside the VM) and passes.
//!
//! Locality is evaluated per request, never cached: the image snapshot is
//! taken before the VM's address exists. Any refusal is HTTP 403
//! `forbidden_peer`; every decision is logged with the row's facts.
//!
//! Linux only: off Linux there is no `/proc/net/tcp`, so peer mode and
//! `--agent-guard on` are startup errors (fail closed).
use crate::shim::health::ShimState;
use crate::wire::frame::{ListenerInfo, LISTENERS_MAX};
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::serve::IncomingStream;
use axum::Json;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;

/// What a refusal reads of the request body before answering (an answer
/// over unread request bytes makes the kernel send RST and the caller may
/// lose it).
pub const DRAIN_MAX: usize = 64 * 1024;

/// Read and drop the body of `req`, at most [`DRAIN_MAX`]: every answer
/// that does not read the body itself comes after this. A larger body can
/// still be reset.
pub async fn drain(req: Request) {
    let _ = axum::body::to_bytes(req.into_body(), DRAIN_MAX).await;
}

/// `--agent-guard`: the guard on the app (8080) and code (9418) ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AgentGuard {
    /// Refuse local clients owned by the agent uid (or orphaned) with 403
    On,
    /// Log what the guard would decide, refuse nothing
    Log,
    /// No lookup
    Off,
}

impl AgentGuard {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            AgentGuard::On => "on",
            AgentGuard::Log => "log",
            AgentGuard::Off => "off",
        }
    }

    /// The default: `on` on a [`guard_host`] (the image), else `off`
    /// (native tests on the Mac).
    #[must_use]
    pub fn default_for_host() -> AgentGuard {
        if guard_host() {
            AgentGuard::On
        } else {
            AgentGuard::Off
        }
    }
}

/// Where the guard works and is expected: Linux (`/proc/net/tcp`) as root,
/// the shim of the image. Native runs are neither.
#[must_use]
pub fn guard_host() -> bool {
    cfg!(target_os = "linux") && nix::unistd::geteuid().is_root()
}

/// Both ends of an accepted connection: the `ConnectInfo` of every router
/// (serve with `into_make_service_with_connect_info::<Peer>()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub peer: SocketAddr,
    pub local: SocketAddr,
}

impl Connected<IncomingStream<'_, TcpListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        let peer = *stream.remote_addr();
        let local = stream.io().local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        Peer { peer, local }
    }
}

/// One row of `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// `st`: 01 ESTABLISHED, 06 TIME_WAIT, 0A LISTEN, …
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

/// `st` of a listening socket.
pub const TCP_LISTEN: u8 = 0x0A;

/// What the guard found about one connection's client end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerFacts {
    /// The client's address is loopback or one of this namespace's, or its
    /// own socket is in this namespace (its row was found).
    pub local: bool,
    /// The client's own row (`local` = the client, `remote` = us), and the
    /// file it was found in (4 = `tcp`, 6 = `tcp6`).
    pub row: Option<(u8, TcpRow)>,
}

impl PeerFacts {
    /// A connection the guard knows nothing about (a router served without
    /// `ConnectInfo`): local and without a row, so it is refused (fail closed).
    pub const UNKNOWN: PeerFacts = PeerFacts { local: true, row: None };
}

/// The guard's decision on one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Admit,
    /// Refused, with the reason logged: `agent_uid`, `orphaned` (inode 0) or `no_row`.
    Refuse(&'static str),
}

impl Decision {
    /// The log's `decision=` value: `admit`, `refuse:<reason>`, or
    /// `would-refuse:<reason>` when the policy only logs.
    #[must_use]
    pub fn shown(self, enforcing: bool) -> String {
        match self {
            Decision::Admit => "admit".into(),
            Decision::Refuse(r) if enforcing => format!("refuse:{r}"),
            Decision::Refuse(r) => format!("would-refuse:{r}"),
        }
    }
}

/// Pure: a non-local client passes; a local one only with a found row whose
/// inode is not 0 and whose uid is not `agent_uid`.
#[must_use]
pub fn decide(facts: &PeerFacts, agent_uid: u32) -> Decision {
    if !facts.local {
        return Decision::Admit;
    }
    match facts.row {
        None => Decision::Refuse("no_row"),
        Some((_, r)) if r.inode == 0 => Decision::Refuse("orphaned"),
        Some((_, r)) if r.uid == agent_uid => Decision::Refuse("agent_uid"),
        Some(_) => Decision::Admit,
    }
}

/// `addr` in the kernel's `/proc/net/tcp` notation: `0100007F:1F90` (v4) or
/// 32 hex digits (v6). The kernel prints each 32-bit word of the address,
/// which is stored in network byte order, as a host-order integer (`%08X`):
/// the word's native-endian bytes are the address bytes. The port is printed
/// after `ntohs`.
fn parse_addr(field: &str) -> Option<SocketAddr> {
    let (ip, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |s: &str| u32::from_str_radix(s, 16).ok().map(u32::to_ne_bytes);
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(ip)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(ip.get(i * 8..i * 8 + 8)?)?);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Every row of one `/proc/net/tcp` or `tcp6` text (header skipped; a line
/// that does not parse is ignored).
#[must_use]
pub fn parse_proc_net_tcp(text: &str) -> Vec<TcpRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            // sl local rem st tx:rx tr:when retrnsmt uid timeout inode …
            if f.len() < 10 {
                return None;
            }
            Some(TcpRow { local: parse_addr(f[1])?, remote: parse_addr(f[2])?, state: u8::from_str_radix(f[3], 16).ok()?, uid: f[7].parse().ok()?, inode: f[9].parse().ok()? })
        })
        .collect()
}

/// `ip` as `/proc/net/tcp6` shows an IPv4 peer of an AF_INET6 socket.
#[must_use]
pub fn v4_mapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        v6 => v6,
    }
}

/// The client's own row for the connection `conn`, among `tcp` (`v4`) and
/// `tcp6` (`v6`) rows: `local` = the client's address, `remote` = ours (in
/// tcp6 also in the v4-mapped form).
#[must_use]
pub fn find_client_row(conn: &Peer, v4: &[TcpRow], v6: &[TcpRow]) -> Option<(u8, TcpRow)> {
    let hit = |r: &&TcpRow, peer: SocketAddr, local: SocketAddr| r.local == peer && r.remote == local;
    if let Some(r) = v4.iter().find(|r| hit(r, conn.peer, conn.local)) {
        return Some((4, *r));
    }
    let (p6, l6) = (v4_mapped(conn.peer), v4_mapped(conn.local));
    v6.iter().find(|r| hit(r, conn.peer, conn.local) || hit(r, p6, l6)).map(|r| (6, *r))
}

/// A v4-mapped IPv6 address as the IPv4 address it carries.
#[must_use]
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Every address this network namespace holds right now (`getifaddrs`;
/// entries without an address and families other than AF_INET/AF_INET6 are
/// skipped). Read on every call: the VM's own address appears only after
/// the snapshot is restored.
pub fn local_addrs() -> std::io::Result<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes the head of a list it allocated, or fails and writes nothing.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned, alive until freeifaddrs below.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: a non-null ifa_addr points at a sockaddr whose family tells its full type;
            // read_unaligned copies it without assuming the cast type's alignment.
            let family = i32::from(unsafe { std::ptr::read_unaligned(ifa.ifa_addr) }.sa_family);
            if family == libc::AF_INET {
                // SAFETY: AF_INET: the address is a sockaddr_in.
                let sin = unsafe { std::ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in>()) };
                out.push(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())));
            } else if family == libc::AF_INET6 {
                // SAFETY: AF_INET6: the address is a sockaddr_in6.
                let sin6 = unsafe { std::ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in6>()) };
                out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// Is `ip` loopback (v4-mapped included) or an address of this namespace?
/// When the interfaces cannot be read, every client counts as local, so the
/// row rules apply to it (fail closed).
#[must_use]
pub fn is_local(ip: IpAddr) -> bool {
    let ip = canonical(ip);
    ip.is_loopback() || local_addrs().map_or(true, |addrs| addrs.into_iter().any(|a| canonical(a) == ip))
}

/// Pure: the facts of `conn` from its address's locality and the rows. A
/// client whose own socket is among the rows is local whatever its address
/// says (one bound to an address that is local by route but on no
/// interface must not pass as remote).
#[must_use]
pub fn facts_in(conn: &Peer, local_address: bool, v4: &[TcpRow], v6: &[TcpRow]) -> PeerFacts {
    let row = find_client_row(conn, v4, v6);
    PeerFacts { local: local_address || row.is_some(), row }
}

/// What the guard knows of `conn` now: on Linux the client's row in a fresh
/// read of `/proc/net/tcp` and `tcp6` (an unreadable file has no rows; off
/// Linux there are none), then the locality of its address.
#[must_use]
pub fn facts(conn: &Peer) -> PeerFacts {
    let (v4, v6) = if cfg!(target_os = "linux") { (read_rows("/proc/net/tcp"), read_rows("/proc/net/tcp6")) } else { (Vec::new(), Vec::new()) };
    facts_in(conn, is_local(conn.peer.ip()), &v4, &v6)
}

fn read_rows(path: &str) -> Vec<TcpRow> {
    std::fs::read_to_string(path).map(|t| parse_proc_net_tcp(&t)).unwrap_or_default()
}

/// The inode of a `/proc/<pid>/fd/<n>` link target `socket:[<inode>]`.
#[must_use]
pub fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// The LISTEN rows among `rows` as `/health/detail` lists them; `own` holds
/// the inodes of the shim's own sockets.
#[must_use]
pub fn listeners_in(rows: &[TcpRow], own: &BTreeSet<u64>) -> Vec<ListenerInfo> {
    rows.iter()
        .filter(|r| r.state == TCP_LISTEN)
        .map(|r| ListenerInfo { addr: canonical(r.local.ip()).to_string(), port: r.local.port(), uid: r.uid, inode: r.inode, own: own.contains(&r.inode) })
        .collect()
}

/// At most [`LISTENERS_MAX`] of `all`, those of `agent_uid` last (a stable
/// sort: the shim's own and the platform's listeners are what a reader
/// checks, and an agent can open thousands of its own), and how many were
/// left out.
#[must_use]
pub fn bounded(mut all: Vec<ListenerInfo>, agent_uid: u32) -> (Vec<ListenerInfo>, u64) {
    all.sort_by_key(|l| l.uid == agent_uid);
    let omitted = all.len().saturating_sub(LISTENERS_MAX);
    all.truncate(LISTENERS_MAX);
    (all, omitted as u64)
}

/// Every LISTEN socket of this network namespace (`tcp`, then `tcp6`), each
/// marked `own` when its inode is one of this process's fds (critic H2: the
/// listeners the guard cannot cover). Empty off Linux.
#[must_use]
pub fn listeners() -> Vec<ListenerInfo> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let own: BTreeSet<u64> = std::fs::read_dir("/proc/self/fd")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .filter_map(|t| t.to_str().and_then(socket_inode))
        .collect();
    let mut out = listeners_in(&read_rows("/proc/net/tcp"), &own);
    out.extend(listeners_in(&read_rows("/proc/net/tcp6"), &own));
    out
}

/// The row facts every hook and guard line carries:
/// `peer_uid=<uid|-> ino=<inode|-> st=<two hex|-> fam=<4|6|->`.
#[must_use]
pub fn log_fields(facts: Option<&PeerFacts>) -> String {
    match facts.and_then(|f| f.row) {
        Some((fam, r)) => format!("peer_uid={} ino={} st={:02X} fam={fam}", r.uid, r.inode, r.state),
        None => "peer_uid=- ino=- st=- fam=-".into(),
    }
}

/// 403 `forbidden_peer` with the reason.
#[must_use]
pub fn forbidden(reason: &'static str) -> Response {
    (StatusCode::FORBIDDEN, Json(serde_json::json!({"status": "forbidden_peer", "reason": reason}))).into_response()
}

/// Count one refusal on `port` (`/health/detail`'s `refused_peers`).
pub fn count_refusal(state: &ShimState, port: u16) {
    *state.refused.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(port.to_string()).or_default() += 1;
}

/// The guard on the app and code routers (`--agent-guard`), before any other
/// layer: `off` looks nothing up; `log` decides and logs; `on` refuses with
/// 403 `forbidden_peer`. One `ai-env: guard` line per guarded request; the
/// facts ride the request's extensions for the handlers' own logs.
pub async fn guard(State(state): State<Arc<ShimState>>, mut req: Request, next: Next) -> Response {
    let mode = state.opts.agent_guard;
    if mode == AgentGuard::Off {
        return next.run(req).await;
    }
    let conn = req.extensions().get::<ConnectInfo<Peer>>().map(|c| c.0);
    let facts = conn.map_or(PeerFacts::UNKNOWN, |c| facts(&c));
    let decision = decide(&facts, state.opts.uid);
    let enforcing = mode == AgentGuard::On;
    let (port, peer, local) = conn.map_or(("-".into(), "-".into(), "-".into()), |c| (c.local.port().to_string(), c.peer.to_string(), c.local.to_string()));
    errln!("ai-env: guard port={port} peer={peer} local={local} {} decision={}", log_fields(Some(&facts)), decision.shown(enforcing));
    match decision {
        Decision::Refuse(reason) if enforcing => {
            count_refusal(&state, conn.map_or(0, |c| c.local.port()));
            drain(req).await;
            forbidden(reason)
        }
        _ => {
            req.extensions_mut().insert(facts);
            next.run(req).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Two rows of a real `/proc/net/tcp` (format of Linux 6.1): a LISTEN on
    /// 0.0.0.0:9000 and an established client 127.0.0.1:41234 → 127.0.0.1:9000
    /// owned by uid 1000.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:A0F2 0100007F:2328 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:A0F3 0100007F:2328 06 00000000:00000000 03:00000F2A 00000000     0        0 0 3 0000000000000000
";

    #[test]
    fn parses_v4_rows() {
        let rows = parse_proc_net_tcp(TCP);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], TcpRow { local: sa("0.0.0.0:9000"), remote: sa("0.0.0.0:0"), state: 0x0A, uid: 0, inode: 12345 });
        assert_eq!(rows[1], TcpRow { local: sa("127.0.0.1:41202"), remote: sa("127.0.0.1:9000"), state: 1, uid: 1000, inode: 67890 });
        assert_eq!(rows[2].state, 6, "TIME_WAIT");
        assert_eq!((rows[2].uid, rows[2].inode), (0, 0), "a TIME_WAIT row shows uid 0, inode 0");
    }

    #[test]
    fn parses_v6_rows_with_v4_mapped_addresses() {
        // ::ffff:127.0.0.1 port 0xA0F4 → ::ffff:127.0.0.1:9000, uid 1000.
        let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000100007F:A0F4 0000000000000000FFFF00000100007F:2328 01 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 20 4 30 10 -1
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 778 1 0000000000000000 100 0 0 10 0
";
        let rows = parse_proc_net_tcp(tcp6);
        assert_eq!(rows[0].local, sa("[::ffff:127.0.0.1]:41204"));
        assert_eq!(rows[0].remote, sa("[::ffff:127.0.0.1]:9000"));
        assert_eq!(rows[1].local, sa("[::1]:8080"));
        let conn = Peer { peer: sa("127.0.0.1:41204"), local: sa("127.0.0.1:9000") };
        assert_eq!(find_client_row(&conn, &[], &rows), Some((6, rows[0])), "a v4-mapped client appears only in tcp6");
    }

    #[test]
    fn finds_only_the_clients_own_end() {
        let rows = parse_proc_net_tcp(TCP);
        let conn = Peer { peer: sa("127.0.0.1:41202"), local: sa("127.0.0.1:9000") };
        assert_eq!(find_client_row(&conn, &rows, &[]), Some((4, rows[1])));
        let other = Peer { peer: sa("127.0.0.1:5555"), local: sa("127.0.0.1:9000") };
        assert_eq!(find_client_row(&other, &rows, &[]), None);
        // Our own end of the same connection (local = 9000) is never taken for the client's.
        let reversed = Peer { peer: sa("127.0.0.1:9000"), local: sa("127.0.0.1:41202") };
        assert_eq!(find_client_row(&reversed, &rows, &[]), None);
    }

    /// A TIME_WAIT (or orphaned) row of the client's own address is found and
    /// refused for its inode 0: a client that sent and closed before the
    /// lookup shows uid 0 and must not pass as root.
    #[test]
    fn a_time_wait_row_is_found_and_refused_as_orphaned() {
        let rows = parse_proc_net_tcp(TCP);
        let conn = Peer { peer: sa("127.0.0.1:41203"), local: sa("127.0.0.1:9000") };
        let row = find_client_row(&conn, &rows, &[]);
        assert_eq!(row.map(|(f, r)| (f, r.state, r.uid, r.inode)), Some((4, 6, 0, 0)));
        assert_eq!(decide(&PeerFacts { local: true, row }, 1000), Decision::Refuse("orphaned"));
    }

    #[test]
    fn a_client_with_a_row_here_is_local_whatever_its_address() {
        let rows = parse_proc_net_tcp(TCP);
        let conn = Peer { peer: sa("127.0.0.1:41202"), local: sa("127.0.0.1:9000") };
        assert_eq!(facts_in(&conn, false, &rows, &[]), PeerFacts { local: true, row: Some((4, rows[1])) }, "its own row says it is in this namespace");
        assert_eq!(decide(&facts_in(&conn, false, &rows, &[]), 1000), Decision::Refuse("agent_uid"));
        let remote = Peer { peer: sa("192.0.2.7:5000"), local: sa("10.0.0.5:8080") };
        assert_eq!(facts_in(&remote, false, &rows, &[]), PeerFacts { local: false, row: None }, "no row, a foreign address: remote");
        assert_eq!(facts_in(&remote, true, &rows, &[]), PeerFacts { local: true, row: None }, "no row, one of our addresses: refused as no_row");
    }

    #[test]
    fn decision_matrix() {
        let row = |uid, inode| Some((4, TcpRow { local: sa("127.0.0.1:1"), remote: sa("127.0.0.1:9000"), state: 1, uid, inode }));
        assert_eq!(decide(&PeerFacts { local: false, row: None }, 1000), Decision::Admit, "remote: the endpoint proxy");
        assert_eq!(decide(&PeerFacts { local: true, row: None }, 1000), Decision::Refuse("no_row"), "an RST-aborted or vanished local client");
        assert_eq!(decide(&PeerFacts { local: true, row: row(0, 0) }, 1000), Decision::Refuse("orphaned"), "closed before the lookup: shows uid 0");
        assert_eq!(decide(&PeerFacts { local: true, row: row(1000, 9) }, 1000), Decision::Refuse("agent_uid"));
        assert_eq!(decide(&PeerFacts { local: true, row: row(0, 9) }, 1000), Decision::Admit, "root: the platform");
        assert_eq!(decide(&PeerFacts { local: true, row: row(1001, 9) }, 1000), Decision::Admit, "another uid than the agent's");
        assert_eq!(decide(&PeerFacts::UNKNOWN, 1000), Decision::Refuse("no_row"), "no ConnectInfo: fail closed");
    }

    #[test]
    fn decisions_are_shown_by_policy() {
        assert_eq!(Decision::Admit.shown(true), "admit");
        assert_eq!(Decision::Admit.shown(false), "admit");
        assert_eq!(Decision::Refuse("agent_uid").shown(true), "refuse:agent_uid");
        assert_eq!(Decision::Refuse("no_row").shown(false), "would-refuse:no_row");
    }

    #[test]
    fn loopback_and_own_addresses_are_local() {
        for ip in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"] {
            assert!(is_local(ip.parse().unwrap()), "{ip}");
        }
        let ours = local_addrs().expect("getifaddrs works on the test host");
        assert!(ours.iter().any(|a| a.is_loopback()), "the loopback interface is listed: {ours:?}");
        for a in ours {
            assert!(is_local(a), "{a} is one of ours");
            if let IpAddr::V4(v4) = a {
                assert!(is_local(IpAddr::V6(v4.to_ipv6_mapped())), "{a} v4-mapped compares as v4");
            }
        }
        for ip in ["192.0.2.7", "198.51.100.1", "2001:db8::7", "::ffff:192.0.2.7"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip} (documentation ranges) is never ours");
        }
    }

    #[test]
    fn canonical_unmaps_v4_mapped_only() {
        assert_eq!(canonical("::ffff:10.0.0.5".parse().unwrap()), "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(canonical("::1".parse().unwrap()), "::1".parse::<IpAddr>().unwrap());
        assert_eq!(canonical("10.0.0.5".parse().unwrap()), "10.0.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn listeners_are_the_listen_rows_marked_own_by_inode() {
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        for bad in ["pipe:[12345]", "socket:[]", "socket:[x]", "/dev/null", "socket:12345"] {
            assert_eq!(socket_inode(bad), None, "{bad}");
        }
        let rows = parse_proc_net_tcp(TCP);
        let l = listeners_in(&rows, &BTreeSet::from([12345]));
        assert_eq!(l, vec![ListenerInfo { addr: "0.0.0.0".into(), port: 9000, uid: 0, inode: 12345, own: true }], "only st 0A");
        assert!(!listeners_in(&rows, &BTreeSet::new())[0].own);
    }

    /// Past the bound the agent's own listeners go first, never another
    /// uid's: those keep their order and all of them are listed.
    #[test]
    fn the_listener_list_is_bounded_with_the_agents_own_left_out_first() {
        let li = |port: u16, uid: u32| ListenerInfo { addr: "127.0.0.1".into(), port, uid, inode: u64::from(port), own: false };
        let mut all: Vec<ListenerInfo> = (0..600u16).map(|i| li(10_000 + i, 1000)).collect();
        all.insert(300, li(8022, 0));
        all.insert(0, li(9000, 0));
        all.push(li(5555, 993));
        let (listed, omitted) = bounded(all.clone(), 1000);
        assert_eq!((listed.len(), omitted), (LISTENERS_MAX, 603 - LISTENERS_MAX as u64));
        assert_eq!(listed[..3].iter().map(|l| l.port).collect::<Vec<_>>(), [9000, 8022, 5555], "every other uid's first, in order");
        assert!(listed[3..].iter().all(|l| l.uid == 1000));
        assert_eq!(listed[3].port, 10_000, "the agent's in their order");
        assert_eq!(bounded(all[..5].to_vec(), 1000), (all[..5].to_vec(), 0), "under the bound: as read");
    }

    #[test]
    fn log_fields_show_the_row_or_dashes() {
        let r = TcpRow { local: sa("127.0.0.1:1"), remote: sa("127.0.0.1:9000"), state: 0x0A, uid: 1000, inode: 77 };
        assert_eq!(log_fields(Some(&PeerFacts { local: true, row: Some((6, r)) })), "peer_uid=1000 ino=77 st=0A fam=6");
        assert_eq!(log_fields(Some(&PeerFacts { local: false, row: None })), "peer_uid=- ino=- st=- fam=-");
        assert_eq!(log_fields(None), "peer_uid=- ino=- st=- fam=-");
    }

    /// On Linux the lookup finds this test's own client socket with this
    /// process's uid and a non-zero inode, in a fresh read per call.
    #[tokio::test]
    async fn facts_find_a_live_client_on_linux() {
        let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let client = tokio::net::TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (_server, _) = l.accept().await.unwrap();
        let conn = Peer { peer: client.local_addr().unwrap(), local: client.peer_addr().unwrap() };
        let f = facts(&conn);
        assert!(f.local);
        if cfg!(target_os = "linux") {
            let (_, row) = f.row.expect("the client's row");
            assert_eq!(row.uid, nix::unistd::geteuid().as_raw());
            assert_ne!(row.inode, 0);
            assert_eq!(decide(&f, row.uid), Decision::Refuse("agent_uid"));
            assert!(listeners().iter().any(|li| li.port == l.local_addr().unwrap().port() && li.own), "our own LISTEN socket is marked own");
        } else {
            assert_eq!(f.row, None, "no /proc/net/tcp off Linux");
            assert!(listeners().is_empty());
        }
    }
}
