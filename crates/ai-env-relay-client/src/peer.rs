//! Who is asking (V-R18): the client admits a connection when its peer runs as the agent's uid and the client's
//! leader (its chat's claude, which leads its own session) is the peer or one of its first [`ANCESTRY_HOPS`]
//! ancestors. The kernel says which chat a process belongs to (`SO_PEERCRED`, then the parent chain), never a file
//! or a variable (LD-V4). The MCP server walks the same chain to find its socket.

/// How far up a peer's ancestry the leader is looked for.
pub const ANCESTRY_HOPS: usize = 16;

/// `pid`'s parent. Linux: field 4 of `/proc/<pid>/stat` (after the last `)`: a command name may hold one); macOS:
/// `proc_pidinfo(PROC_PIDTBSDINFO).pbi_ppid`. `None` when `pid` is gone or unreadable.
#[must_use]
pub fn parent_of(pid: u32) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = &stat[stat.rfind(')')? + 1..];
        rest.split_whitespace().nth(1)?.parse().ok()
    }
    #[cfg(target_os = "macos")]
    {
        let pid = libc::c_int::try_from(pid).ok()?;
        // SAFETY: an all-zero proc_bsdinfo is a valid value for proc_pidinfo to fill.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: the buffer is a proc_bsdinfo of `size` bytes on the stack.
        let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, std::ptr::addr_of_mut!(info).cast(), size) };
        (n == size).then_some(info.pbi_ppid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Whether `leader` is `pid` or one of its first [`ANCESTRY_HOPS`] ancestors (a walk stops at pid ≤ 1 or a repeat).
/// A leader of 0 or 1 is never anyone's.
#[must_use]
pub fn descends_from(pid: u32, leader: u32, parent: impl Fn(u32) -> Option<u32>) -> bool {
    if leader <= 1 {
        return false;
    }
    let mut seen = Vec::with_capacity(ANCESTRY_HOPS + 1);
    let mut cur = pid;
    for hop in 0..=ANCESTRY_HOPS {
        if cur == leader {
            return true;
        }
        if cur <= 1 || seen.contains(&cur) || hop == ANCESTRY_HOPS {
            return false;
        }
        seen.push(cur);
        match parent(cur) {
            Some(p) => cur = p,
            None => return false,
        }
    }
    false
}

/// `kill(pid, 0)` did not fail with ESRCH (a zombie still counts, as the shim keeps its leader one until its group's
/// KILL). 0 and pids past `i32::MAX` are no process.
#[must_use]
pub fn alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return false };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 only checks that the process exists.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Why a peer was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The kernel gave no peer pid.
    NoPid,
    /// The peer runs as another uid than the agent's.
    Uid(u32),
    /// The leader is not among the peer's ancestors (this pid's).
    NotInSession(u32),
}

impl Refusal {
    /// The refusal's `forbidden_peer` message (§V-vm.3.6's frozen words).
    #[must_use]
    pub fn message(self) -> String {
        match self {
            Refusal::NoPid => "no peer pid".to_string(),
            Refusal::Uid(u) => format!("uid {u} is not the agent's"),
            Refusal::NotInSession(_) => "not a process of this session".to_string(),
        }
    }

    /// The `refused peer` line's `(<why>)`.
    #[must_use]
    pub fn why(self) -> &'static str {
        match self {
            Refusal::NoPid => "no pid",
            Refusal::Uid(_) => "uid",
            Refusal::NotInSession(_) => "not of this session",
        }
    }
}

/// V-R18: the uid must be `agent_uid`, the pid known, and `leader` the pid or one of its first [`ANCESTRY_HOPS`]
/// ancestors.
pub fn admit(uid: u32, pid: Option<u32>, agent_uid: u32, leader: u32, parent: impl Fn(u32) -> Option<u32>) -> Result<(), Refusal> {
    if uid != agent_uid {
        return Err(Refusal::Uid(uid));
    }
    let pid = pid.ok_or(Refusal::NoPid)?;
    if !descends_from(pid, leader, parent) {
        return Err(Refusal::NotInSession(pid));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Over a parent map: a chain of 16 hops finds the leader, 17 does not; a chain through pid 1 stops; a cycle
    /// stops; `admit` refuses another uid, no pid and a stranger, and admits the leader's descendant.
    #[test]
    fn descends_from_walks_at_most_sixteen_parents() {
        // 1000 → 1001 → … → 1017 (each the parent of the one before), then 1.
        let chain: HashMap<u32, u32> = (1000..1017).map(|p| (p, p + 1)).chain([(1017, 1)]).collect();
        let parent = |p: u32| chain.get(&p).copied();
        assert!(descends_from(1000, 1000, parent), "the leader itself");
        assert!(descends_from(1000, 1001, parent));
        assert!(descends_from(1000, 1016, parent), "16 hops");
        assert!(!descends_from(1000, 1017, parent), "17 hops");
        assert!(descends_from(1001, 1017, parent), "16 hops from the next one");
        // Through pid 1: 2000 → 1 → 2001 never reaches 2001.
        let through_init: HashMap<u32, u32> = [(2000, 1), (1, 2001)].into_iter().collect();
        assert!(!descends_from(2000, 2001, |p| through_init.get(&p).copied()));
        assert!(!descends_from(2000, 1, |p| through_init.get(&p).copied()), "init is nobody's leader");
        // A cycle: 3000 → 3001 → 3000.
        let cycle: HashMap<u32, u32> = [(3000, 3001), (3001, 3000)].into_iter().collect();
        assert!(!descends_from(3000, 3002, |p| cycle.get(&p).copied()));
        assert!(descends_from(3000, 3001, |p| cycle.get(&p).copied()));
        // An unknown parent ends the walk.
        assert!(!descends_from(4000, 4001, |_| None));
        assert_eq!(admit(1000, Some(1000), 1000, 1005, parent), Ok(()));
        assert_eq!(admit(999, Some(1000), 1000, 1005, parent), Err(Refusal::Uid(999)));
        assert_eq!(admit(1000, None, 1000, 1005, parent), Err(Refusal::NoPid));
        assert_eq!(admit(1000, Some(4000), 1000, 1005, parent), Err(Refusal::NotInSession(4000)));
        assert_eq!(admit(1000, Some(1000), 1000, 1017, parent), Err(Refusal::NotInSession(1000)), "past the hops");
        assert_eq!(Refusal::Uid(999).message(), "uid 999 is not the agent's");
        assert_eq!(Refusal::NoPid.message(), "no peer pid");
        assert_eq!(Refusal::NotInSession(7).message(), "not a process of this session");
        assert_eq!([Refusal::Uid(1), Refusal::NoPid, Refusal::NotInSession(2)].map(Refusal::why), ["uid", "no pid", "not of this session"]);
    }

    /// `parent_of(this process)` is `getppid()`, on macOS and Linux; this process is alive, pid 0 is not a process.
    #[test]
    fn parent_of_reads_this_process_tree() {
        // SAFETY: getppid never fails.
        let ppid = unsafe { libc::getppid() };
        assert_eq!(parent_of(std::process::id()), u32::try_from(ppid).ok());
        assert!(alive(std::process::id()));
        assert!(!alive(0));
    }
}
