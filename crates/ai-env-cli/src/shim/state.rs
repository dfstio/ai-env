//! The `/run` record: one per VM lifetime, first request wins.
//!
//! The platform calls `/run` once per VM (a clone of the image snapshot) with
//! the Mac's `runHookPayload`. The first body is kept; a byte-identical
//! replay is answered 200 (a retried delivery), any other body 409. A `/run`
//! without a payload is still recorded ("fail-closed"): the VM boots, but no
//! commitment exists, so every later `hello` on `/agent` is refused.
use crate::wire::frame::RunHookPayload;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RunRecord {
    pub microvm_id: Option<String>,
    /// `None` = fail-closed (no commitment).
    pub payload: Option<RunHookPayload>,
    pub body_sha256: [u8; 32],
    pub at: Instant,
    pub boot_nonce: String,
}

/// What a `/run` request is relative to the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    First,
    Replay,
    Conflict,
}

/// What `/health` may show of the record (never the payload itself).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunView {
    pub microvm_id: Option<String>,
    pub owner: Option<String>,
    pub created: Option<String>,
    pub boot_nonce: Option<String>,
    /// `/run` has RETURNED 200 (after any `--delay-run`).
    pub seen: bool,
    pub at: Option<Instant>,
}

#[derive(Default)]
struct Inner {
    record: Option<RunRecord>,
    seen: bool,
}

#[derive(Default)]
pub struct RunState {
    inner: Mutex<Inner>,
}

impl RunState {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Where a body with this hash stands, without claiming.
    #[must_use]
    pub fn peek(&self, body_sha256: &[u8; 32]) -> Option<Claim> {
        self.lock().record.as_ref().map(|r| if &r.body_sha256 == body_sha256 { Claim::Replay } else { Claim::Conflict })
    }

    /// Atomically: store `make()` if no record exists (`First`), else
    /// classify against the stored body (`make` is not called).
    pub fn claim(&self, body_sha256: &[u8; 32], make: impl FnOnce() -> RunRecord) -> Claim {
        let mut g = self.lock();
        match &g.record {
            Some(r) if &r.body_sha256 == body_sha256 => Claim::Replay,
            Some(_) => Claim::Conflict,
            None => {
                g.record = Some(make());
                Claim::First
            }
        }
    }

    /// `/run` is about to return 200.
    pub fn mark_seen(&self) {
        self.lock().seen = true;
    }

    #[must_use]
    pub fn view(&self) -> RunView {
        let g = self.lock();
        match &g.record {
            None => RunView { seen: g.seen, ..RunView::default() },
            Some(r) => RunView {
                microvm_id: r.microvm_id.clone(),
                owner: r.payload.as_ref().map(|p| p.owner.clone()),
                created: r.payload.as_ref().map(|p| p.created.clone()),
                boot_nonce: Some(r.boot_nonce.clone()),
                seen: g.seen,
                at: Some(r.at),
            },
        }
    }

    /// The commitment `hello` is checked against (S6); `None` before `/run`
    /// and after a fail-closed `/run`.
    #[must_use]
    pub fn payload(&self) -> Option<RunHookPayload> {
        self.lock().record.as_ref().and_then(|r| r.payload.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(hash: u8, payload: bool) -> RunRecord {
        RunRecord {
            microvm_id: Some("mvm-1".into()),
            payload: payload.then(|| RunHookPayload { v: 1, commit: "ab".repeat(32), owner: "mike@mbp".into(), created: "2026-09-29T08:00:00Z".into() }),
            body_sha256: [hash; 32],
            at: Instant::now(),
            boot_nonce: "0".repeat(32),
        }
    }

    #[test]
    fn first_wins_then_replay_or_conflict() {
        let s = RunState::default();
        assert_eq!(s.peek(&[1; 32]), None);
        assert_eq!(s.claim(&[1; 32], || record(1, true)), Claim::First);
        assert_eq!(s.claim(&[1; 32], || unreachable!("not called on a replay")), Claim::Replay);
        assert_eq!(s.claim(&[2; 32], || unreachable!("not called on a conflict")), Claim::Conflict);
        assert_eq!(s.peek(&[1; 32]), Some(Claim::Replay));
        assert_eq!(s.peek(&[2; 32]), Some(Claim::Conflict));
    }

    #[test]
    fn view_hides_the_payload_and_tracks_seen() {
        let s = RunState::default();
        assert_eq!(s.view(), RunView::default());
        s.claim(&[1; 32], || record(1, true));
        let v = s.view();
        assert!(!v.seen, "claimed but not yet returned");
        assert_eq!(v.owner.as_deref(), Some("mike@mbp"));
        assert_eq!(v.microvm_id.as_deref(), Some("mvm-1"));
        s.mark_seen();
        assert!(s.view().seen);
        assert!(s.payload().is_some());
    }

    #[test]
    fn fail_closed_record_has_no_commitment() {
        let s = RunState::default();
        s.claim(&[1; 32], || record(1, false));
        s.mark_seen();
        let v = s.view();
        assert!(v.seen && v.owner.is_none() && v.created.is_none() && v.boot_nonce.is_some());
        assert!(s.payload().is_none());
    }
}
