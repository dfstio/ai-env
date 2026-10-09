//! The shim's one-slot credential cache (S7).
//!
//! The Mac delivers a credential once per VM running period on its own
//! `credential` frame; spawns then name it (`spawn.credential`) instead of
//! carrying the value, so a re-sent `spawn` that names the cached credential
//! never carries its value; a `--credential-file` spawn carries its one
//! secret inline (S6's `spawn.secrets`), as does any re-send of it, to the
//! same VM only. The `/agent` connection resolves the name here into the
//! spawn's one-shot secret, and the spawn manager delivers it as before (fd 3
//! or env).
//!
//! The copy lives only while the VM runs: `/suspend` drops it and closes the
//! cache in one step (a `credential` racing the suspend is refused, never
//! cached behind it), `/resume` reopens it and drops anything there (the
//! backstop for a suspend whose hook never ran), `/terminate` and the shutdown
//! drop it and close for good (no later `/suspend` or `/resume` reopens it),
//! and `credential_forget` drops it. The spawn manager owns the cache so its
//! clock's jump guard (more than `JUMP` the clock did not see) drops it too;
//! the clock runs from the first `hello`, so this also covers a copy `vm warm`
//! delivered before any spawn. That guard is a weak backstop (no monotonic
//! jump was seen across a suspend: D3), hence `/resume`'s drop. A replaced or
//! dropped value is zeroized ([`Secret`]'s drop). Spawns already given the
//! value keep their own copy;
//! [`crate::shim::spawn::SpawnManager::credential_holders`] counts them.
//!
//! Logging is lifecycle only — the name, the byte count and the tag, never the
//! value: the shim's `errln!` does not scrub.
use crate::wire::frame::{CredentialErrCode, CredentialView, CREDENTIAL_TAG_MAX};
use crate::wire::redact::Secret;

struct Cached {
    name: String,
    value: Secret<String>,
    tag: Option<String>,
    at: String,
}

#[derive(Default)]
struct Slot {
    cached: Option<Cached>,
    /// Nothing may be cached, and a `put` is refused with this code:
    /// `Suspended` from `/suspend` until `/resume`, `Draining` once stopping
    /// (never replaced).
    closed: Option<CredentialErrCode>,
}

impl Slot {
    /// Take the copy out (any, or only when it is `name`); the caller logs it
    /// once the lock is released, and its drop zeroizes the value.
    fn take(&mut self, name: Option<&str>) -> Option<Cached> {
        let matches = self.cached.as_ref().is_some_and(|c| name.is_none_or(|n| n == c.name));
        if matches {
            self.cached.take()
        } else {
            None
        }
    }
}

/// Log a dropped copy (lifecycle only); whether there was one.
fn forgotten(dropped: Option<Cached>, why: &str) -> bool {
    match dropped {
        Some(c) => {
            errln!("ai-env: credential forgotten name={} ({why})", c.name);
            true
        }
        None => false,
    }
}

/// A closed cache's refusal text.
fn closed_message(code: CredentialErrCode) -> &'static str {
    match code {
        CredentialErrCode::Suspended => "the VM is suspending: nothing is cached until it resumes",
        CredentialErrCode::Draining => "the shim is stopping: nothing is cached",
        CredentialErrCode::BadRequest | CredentialErrCode::Other => "the credential cache is closed",
    }
}

/// The slot's mutex, in a module of its own so that `SlotLock::lock` is the
/// only way to it: the unit tests' lock seam then sees every lock the cache
/// takes (a lock taken around it would leave the race test a window it never
/// probes).
mod locked {
    use super::Slot;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    #[derive(Default)]
    pub(super) struct SlotLock(Mutex<Slot>);

    impl SlotLock {
        pub(super) fn lock(&self) -> MutexGuard<'_, Slot> {
            // Unit tests may run another thread's `put` here, before any lock
            // this thread takes: the race with `close` made deterministic.
            #[cfg(test)]
            super::tests::before_lock();
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }
}

/// One credential, by name, for the VM's current running period.
#[derive(Default)]
pub struct CredentialCache {
    slot: locked::SlotLock,
}

/// Is `tag` an acceptable seal id: 1–64 of `[A-Za-z0-9-]`?
fn tag_ok(tag: &str) -> bool {
    (1..=CREDENTIAL_TAG_MAX).contains(&tag.len()) && tag.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

impl CredentialCache {
    #[must_use]
    pub fn new() -> CredentialCache {
        CredentialCache::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Slot> {
        self.slot.lock()
    }

    /// Cache `value` under `name`, replacing (and zeroizing) any earlier copy.
    /// The name follows the spawn environment's rule (it becomes a variable
    /// name, or `<NAME>_FILE_DESCRIPTOR`); the value is 1–4096 bytes (what fd 3
    /// carries) without NUL; the tag, when present, a seal id. Refused while
    /// the cache is closed by a `/suspend`. The refusal's text names the
    /// field, never the value.
    pub fn put(&self, name: &str, value: Secret<String>, tag: Option<String>) -> Result<(), (CredentialErrCode, String)> {
        crate::shim::spawn::check_name(name).map_err(|m| (CredentialErrCode::BadRequest, m))?;
        let len = value.expose().len();
        if len == 0 || len > crate::shim::spawn::SECRET_FD_MAX_BYTES {
            return Err((CredentialErrCode::BadRequest, format!("the credential {name} is {len} bytes (1 to {})", crate::shim::spawn::SECRET_FD_MAX_BYTES)));
        }
        if value.expose().as_bytes().contains(&0) {
            return Err((CredentialErrCode::BadRequest, format!("the credential {name} holds a NUL byte")));
        }
        if let Some(t) = &tag {
            if !tag_ok(t) {
                return Err((CredentialErrCode::BadRequest, format!("the tag of {name} is not 1 to {CREDENTIAL_TAG_MAX} of [A-Za-z0-9-]")));
            }
        }
        let mut slot = self.lock();
        if let Some(code) = slot.closed {
            return Err((code, closed_message(code).into()));
        }
        let at = crate::wire::time::rfc3339_utc(crate::wire::time::unix_now());
        // The earlier copy, if any, is zeroized as it is dropped here.
        slot.cached = Some(Cached { name: name.to_string(), value, tag: tag.clone(), at });
        drop(slot);
        errln!("ai-env: credential cached name={name} bytes={len} tag={}", tag.as_deref().unwrap_or("-"));
        Ok(())
    }

    /// A copy of the cached value of `name`, for one spawn; `None` when the
    /// cache holds nothing, or another name.
    #[must_use]
    pub fn copy(&self, name: &str) -> Option<Secret<String>> {
        let slot = self.lock();
        slot.cached.as_ref().filter(|c| c.name == name).map(|c| Secret::new(c.value.expose().clone()))
    }

    /// Drop the cached value (zeroized) — any, or only when it is `name`.
    /// Whether something was dropped; `why` is logged.
    pub fn forget(&self, name: Option<&str>, why: &str) -> bool {
        let dropped = self.lock().take(name);
        forgotten(dropped, why)
    }

    /// Drop the copy and refuse new ones with `code`, in one step under the
    /// lock: `Suspended` for `/suspend` (until [`Self::reopen`]), `Draining`
    /// for `/terminate` and the shutdown (for good: a later close never
    /// replaces it, so a `/suspend` after a stop is no suspend that
    /// `/resume` could reopen).
    pub fn close(&self, code: CredentialErrCode, why: &str) {
        let mut slot = self.lock();
        if slot.closed != Some(CredentialErrCode::Draining) {
            slot.closed = Some(code);
        }
        let dropped = slot.take(None);
        drop(slot);
        forgotten(dropped, why);
    }

    /// `/resume`: accept credentials again after a suspend, dropping anything
    /// cached in the same step (a suspend whose hook never ran). A cache
    /// closed by stopping stays closed.
    pub fn reopen(&self, why: &str) {
        let mut slot = self.lock();
        if slot.closed == Some(CredentialErrCode::Suspended) {
            slot.closed = None;
        }
        let dropped = slot.take(None);
        drop(slot);
        forgotten(dropped, why);
    }

    /// Does the cache hold a deliverable copy now?
    #[must_use]
    pub fn has(&self) -> bool {
        self.lock().cached.is_some()
    }

    /// What `hello_ok` and `/health/detail` show: the name, tag and time of
    /// the cached copy — never the value — and `holders`, the live spawns
    /// handed a secret.
    #[must_use]
    pub fn view(&self, holders: u32) -> CredentialView {
        let slot = self.lock();
        let c = slot.cached.as_ref();
        CredentialView { credential_name: c.map(|c| c.name.clone()), credential_tag: c.and_then(|c| c.tag.clone()), credential_at: c.map(|c| c.at.clone()), credential_holders: holders }
    }

    /// The name of the cached credential, for a refusal that must say what is there.
    #[must_use]
    pub fn cached_name(&self) -> Option<String> {
        self.lock().cached.as_ref().map(|c| c.name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Secret<String> {
        Secret::new(v.to_string())
    }

    thread_local! {
        /// Run on this thread just before it takes a cache's lock (the seam
        /// [`before_lock`]); `None`, the default, does nothing.
        static BEFORE_LOCK: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
    }

    /// Called by [`locked::SlotLock::lock`], the only way to the slot, in unit
    /// tests: this thread's hook, if a test set one (never a panic on a
    /// thread already tearing down).
    pub(super) fn before_lock() {
        let _ = BEFORE_LOCK.try_with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f();
            }
        });
    }

    #[test]
    fn put_copy_replace_and_forget() {
        let c = CredentialCache::new();
        assert!(!c.has() && c.copy("A_TOKEN").is_none());
        c.put("A_TOKEN", s("first-value"), Some("seal-1".into())).unwrap();
        assert!(c.has());
        assert_eq!(c.copy("A_TOKEN").unwrap().expose(), "first-value");
        assert!(c.copy("OTHER").is_none(), "only the name it holds");
        let v = c.view(2);
        assert_eq!((v.credential_name.as_deref(), v.credential_tag.as_deref(), v.credential_holders), (Some("A_TOKEN"), Some("seal-1"), 2));
        assert!(v.credential_at.is_some());
        // One slot: a second put replaces the first, whatever its name.
        c.put("B_TOKEN", s("second-value"), None).unwrap();
        assert!(c.copy("A_TOKEN").is_none() && c.copy("B_TOKEN").unwrap().expose() == "second-value");
        assert!(!c.forget(Some("A_TOKEN"), "test"), "forgetting another name drops nothing");
        assert!(c.forget(Some("B_TOKEN"), "test") && !c.has());
        assert!(!c.forget(None, "test"), "nothing left");
    }

    #[test]
    fn bad_requests_name_the_field_never_the_value() {
        let c = CredentialCache::new();
        let secret_text = "not-to-be-echoed-value";
        for (name, value, tag, says) in [
            ("1BAD", secret_text.to_string(), None, "environment name"),
            ("HOME", secret_text.to_string(), None, "set by the shim"),
            ("A", String::new(), None, "0 bytes"),
            ("A", "x".repeat(crate::shim::spawn::SECRET_FD_MAX_BYTES + 1), None, "4097 bytes"),
            ("A", format!("{secret_text}\0"), None, "NUL"),
            ("A", secret_text.to_string(), Some("has space".to_string()), "tag"),
            ("A", secret_text.to_string(), Some("t".repeat(CREDENTIAL_TAG_MAX + 1)), "tag"),
        ] {
            let (code, msg) = c.put(name, Secret::new(value), tag).unwrap_err();
            assert_eq!(code, CredentialErrCode::BadRequest, "{name}: {msg}");
            assert!(msg.contains(says) && !msg.contains(secret_text), "{name}: {msg}");
        }
        assert!(!c.has(), "nothing refused was cached");
        c.put("A", Secret::new("x".repeat(crate::shim::spawn::SECRET_FD_MAX_BYTES)), Some("a".repeat(CREDENTIAL_TAG_MAX))).unwrap();
    }

    /// `/suspend` drops the copy and refuses one racing in; `/resume` reopens
    /// and drops again (a suspend whose hook never ran).
    #[test]
    fn suspend_closes_and_resume_reopens_empty() {
        let c = CredentialCache::new();
        c.put("A_TOKEN", s("value"), None).unwrap();
        c.close(CredentialErrCode::Suspended, "suspend");
        assert!(!c.has());
        let (code, msg) = c.put("A_TOKEN", s("value"), None).unwrap_err();
        assert_eq!(code, CredentialErrCode::Suspended, "{msg}");
        c.reopen("resume");
        assert!(!c.has());
        c.put("A_TOKEN", s("value"), None).unwrap();
        // A resume with no suspend before it (the hook never ran): the copy goes anyway.
        c.reopen("resume");
        assert!(!c.has(), "resume never keeps a copy");
        c.put("A_TOKEN", s("value"), None).unwrap();
    }

    /// `/terminate` and the shutdown close for good: a later `/resume` does
    /// not reopen, a later `/suspend` does not turn the stop into a suspend
    /// (which `/resume` would reopen), and a `put` is refused as draining
    /// throughout.
    #[test]
    fn stopping_closes_for_good() {
        let c = CredentialCache::new();
        c.put("A_TOKEN", s("value"), None).unwrap();
        c.close(CredentialErrCode::Draining, "terminate");
        assert!(!c.has());
        let refused = |after: &str| {
            let (code, msg) = c.put("A_TOKEN", s("value"), None).unwrap_err();
            assert_eq!(code, CredentialErrCode::Draining, "after {after}: {msg}");
            assert!(!c.has(), "after {after}");
        };
        refused("the stop");
        c.reopen("resume");
        refused("a resume");
        c.close(CredentialErrCode::Suspended, "suspend");
        refused("a suspend");
        c.reopen("resume");
        refused("a suspend and a resume");
    }

    /// `close` drops and closes under one lock, so a `put` racing it either
    /// lands before (and is dropped by it) or is refused — never cached
    /// behind it. Deterministic, through the lock seam, which every lock the
    /// cache takes passes ([`locked`]): another thread's `put` runs to its end
    /// just before the first lock `close` takes, then (on a fresh cache) just
    /// before the second, and so on. A `close` split into two critical
    /// sections (the drop, then the close) leaves the put that landed between
    /// them cached, and fails here; so does one that takes no lock, as it
    /// leaves nothing to probe.
    #[test]
    fn a_put_racing_close_is_never_left_cached() {
        use std::{cell::Cell, rc::Rc, sync::Arc};
        for code in [CredentialErrCode::Suspended, CredentialErrCode::Draining] {
            let mut at = 0usize;
            loop {
                let c = Arc::new(CredentialCache::new());
                let (locks, putter) = (Rc::new(Cell::new(0usize)), c.clone());
                let seen = locks.clone();
                BEFORE_LOCK.with(|h| {
                    *h.borrow_mut() = Some(Box::new(move || {
                        if seen.get() == at {
                            let c = putter.clone();
                            std::thread::spawn(move || {
                                let _ = c.put("A_TOKEN", s("value"), None);
                            })
                            .join()
                            .unwrap();
                        }
                        seen.set(seen.get() + 1);
                    }));
                });
                c.close(code, "test");
                BEFORE_LOCK.with(|h| *h.borrow_mut() = None);
                let took = locks.get();
                assert!(at < took, "{code:?}: close took {took} lock(s), so no put landed before lock {at}");
                assert!(!c.has(), "{code:?}: a put landing just before lock {at} of the {took} close took was left cached");
                at += 1;
                if at >= took {
                    break;
                }
            }
        }
    }
}
