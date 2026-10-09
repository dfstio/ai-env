//! MicroVM lifecycle (plan S4): the real control-plane client, the VM
//! registry and placement locks, run/select with pending rows, endpoint
//! tokens and `/health`, tag-free gc, the experimental shell, the live
//! probes, the file-backed fake for process-level tests, and the
//! `ai-env vm …` commands.
pub mod client;
pub mod cmd;
pub mod fake_file;
pub mod gc;
pub mod health;
pub mod lab;
pub mod lab_mac;
pub mod lock;
pub mod registry;
pub mod run;
pub mod shell;
pub mod token;

/// `<user>@<short host>`: who started a VM, carried in the run-hook payload
/// and echoed by `/health` (ownership without tags). The user comes from the
/// password database for the effective uid (not `$USER`), the host is
/// `gethostname` up to the first dot; anything outside printable ASCII (or a
/// second `@`) becomes `-`, so the result always passes
/// `RunHookPayload::validate`.
#[must_use]
pub fn owner() -> String {
    owner_from(&user_name().unwrap_or_else(|| "unknown".to_string()), &short_host().unwrap_or_else(|| "localhost".to_string()))
}

/// The pure half of [`owner`].
#[must_use]
pub fn owner_from(user: &str, host: &str) -> String {
    let clean = |s: &str, max: usize| -> String {
        let out: String = s.chars().take(max).map(|c| if c.is_ascii_graphic() && c != '@' { c } else { '-' }).collect();
        if out.is_empty() {
            "-".to_string()
        } else {
            out
        }
    };
    format!("{}@{}", clean(user, 64), clean(host.split('.').next().unwrap_or(host), 64))
}

fn user_name() -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: zeroed is a valid bit pattern for `passwd` (pointers null, ints 0); it is only read after getpwuid_r filled it.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r writes into `pwd` and `buf` (length passed) and sets `result`; both outlive the call.
    let rc = unsafe { libc::getpwuid_r(libc::geteuid(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: on success pw_name points at a NUL-terminated string inside `buf`, alive here.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    Some(name.to_string_lossy().into_owned()).filter(|n| !n.is_empty())
}

fn short_host() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most buf.len() bytes into buf.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let full = String::from_utf8_lossy(&buf[..end]).into_owned();
    full.split('.').next().filter(|s| !s.is_empty()).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::frame::RunHookPayload;
    use crate::wire::redact::Secret;

    #[test]
    fn owner_shape_passes_payload_validation() {
        assert_eq!(owner_from("mike", "AppleMacBook.local"), "mike@AppleMacBook");
        assert_eq!(owner_from("a b@c", "h\u{e9}st"), "a-b-c@h-st");
        assert_eq!(owner_from("", ""), "-@-");
        for o in [owner(), owner_from("a b", "x.y"), owner_from(&"u".repeat(300), "h")] {
            let p = RunHookPayload::new(&Secret::new("t".repeat(64)), &o, "2026-09-29T10:00:00.000Z");
            p.validate().unwrap_or_else(|e| panic!("{o}: {e}"));
        }
        let me = owner();
        assert_eq!(me.matches('@').count(), 1, "{me}");
    }
}
