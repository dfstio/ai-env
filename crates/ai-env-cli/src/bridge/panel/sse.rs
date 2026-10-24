//! The `events` streams (B §B5.11): `audit`, each new row the page's filter
//! takes (its stored line, scrubbed again), from one `audit::read::Follower`
//! per stream started at the file's end and polled every `FOLLOW_POLL`; and
//! `action`, each change of an action's state (`{id, action, target, state,
//! twin, line, code}`), the board's last ones first. A keep-alive comment every
//! [`SSE_KEEPALIVE`]; at most [`SSE_MAX`] streams (another is 503); every
//! stream ends when the panel stops.
use super::actions::ActionView;
use super::model::PageErr;
use super::{Shared, SSE_KEEPALIVE, SSE_MAX};
use crate::bridge::audit::read::{Filter, Follower, FOLLOW_POLL};
use axum::response::sse::{Event, KeepAlive, Sse};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;

/// The actions a new stream says first (their state now).
const ACTIONS_FIRST: usize = 16;

/// One open stream's place among the [`SSE_MAX`]; given back when the stream is dropped.
pub(crate) struct Slot(Arc<Shared>);

impl Slot {
    /// A place, unless [`SSE_MAX`] streams are open.
    pub(crate) fn take(shared: &Arc<Shared>) -> Option<Slot> {
        shared.streams.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < SSE_MAX).then_some(n + 1)).ok()?;
        Some(Slot(Arc::clone(shared)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What one stream holds.
struct Stream {
    _slot: Slot,
    follower: Follower,
    filter: Filter,
    changes: tokio::sync::broadcast::Receiver<ActionView>,
    stopping: tokio::sync::watch::Receiver<bool>,
    pending: VecDeque<Event>,
}

/// An `audit` event: the row's stored line, scrubbed again and made inert as `audit tail --json` prints it
/// (`audit::read::json_line_safe`: never a carriage return or a line feed, DEL and C1 as their escapes), so a
/// terminal reading the stream (`curl …/events`) acts on nothing in it.
fn audit_event(raw: &str) -> Event {
    Event::default().event("audit").data(&*crate::bridge::audit::read::json_line_safe(&crate::wire::redact::scrub(raw)))
}

/// An `action` event: the action's document.
fn action_event(a: &ActionView) -> Event {
    Event::default().event("action").data(serde_json::to_string(a).unwrap_or_default().replace(['\r', '\n'], " "))
}

/// The next event of `s`, or its end (the panel stops, or the board's sender is gone).
async fn next(mut s: Stream) -> Option<(Result<Event, Infallible>, Stream)> {
    loop {
        if let Some(ev) = s.pending.pop_front() {
            return Some((Ok(ev), s));
        }
        if *s.stopping.borrow() {
            return None;
        }
        tokio::select! {
            changed = s.stopping.changed() => {
                if changed.is_err() || *s.stopping.borrow() {
                    return None;
                }
            }
            change = s.changes.recv() => match change {
                Ok(a) => s.pending.push_back(action_event(&a)),
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return None,
            },
            () = tokio::time::sleep(FOLLOW_POLL) => {
                for r in s.follower.poll() {
                    if s.filter.matches(&r) {
                        s.pending.push_back(audit_event(&r.raw));
                    }
                }
            }
        }
    }
}

/// `GET events` with `filter` (already built): the stream, or `None` when [`SSE_MAX`] are open (503).
pub(crate) fn open(shared: &Arc<Shared>, filter: Filter) -> Option<axum::response::Response> {
    use axum::response::IntoResponse as _;
    let slot = Slot::take(shared)?;
    // Subscribed with the board held (each change is sent under it): every change after this snapshot reaches the stream.
    let (pending, changes) = {
        let board = shared.board();
        (board.recent(ACTIONS_FIRST).iter().map(action_event).collect(), shared.changes.subscribe())
    };
    let stream = Stream {
        _slot: slot,
        follower: Follower::at_end(&shared.paths.audit()),
        filter,
        changes,
        stopping: shared.stopping.clone(),
        pending,
    };
    let events = futures_util::stream::unfold(stream, next);
    Some(Sse::new(events).keep_alive(KeepAlive::new().interval(SSE_KEEPALIVE)).into_response())
}

/// The 503 of a stream past [`SSE_MAX`] (with `Retry-After: 15`).
pub(crate) fn busy() -> axum::response::Response {
    let mut r = super::routes::plain(http::StatusCode::SERVICE_UNAVAILABLE, &format!("service unavailable: {SSE_MAX} event streams are open"));
    r.headers_mut().insert(http::header::RETRY_AFTER, http::HeaderValue::from_static("15"));
    r
}

/// A filter error as the stream's refusal.
pub(crate) fn refused(e: &PageErr) -> axum::response::Response {
    super::routes::page_error(super::html::TOP, e, true)
}
