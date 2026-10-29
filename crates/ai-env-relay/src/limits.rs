//! Token buckets, per-IP slots and sessions (R-2, R-57, R-58). Synchronous only (R-75, a `make lint` guard):
//! nothing in this file awaits; every map is a private field here, and every method returns owned values.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dashmap::DashMap;
use tokio::time::Instant;

use crate::config::Limits;
use crate::tls::Face;

/// One token, in the bucket's unit: a token a minute refills one unit a nanosecond, so every refill is exact.
const TOKEN: u128 = 60_000_000_000;
/// A session idle this long, with nothing in flight, is dropped (R-58).
const SESSION_IDLE: Duration = Duration::from_secs(600);

/// A token bucket.
pub struct TokenBucket {
    capacity: u128,
    per_min: u128,
    tokens: u128,
    last: Instant,
}

impl TokenBucket {
    /// `burst` tokens, refilled at `per_min` a minute.
    pub fn new(burst: u32, per_min: u32, now: Instant) -> TokenBucket {
        let capacity = u128::from(burst) * TOKEN;
        TokenBucket { capacity, per_min: u128::from(per_min), tokens: capacity, last: now }
    }

    /// Takes one token if there is one.
    pub fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= TOKEN {
            self.tokens -= TOKEN;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: Instant) {
        if now > self.last {
            let credit = (now - self.last).as_nanos().saturating_mul(self.per_min);
            self.tokens = self.tokens.saturating_add(credit).min(self.capacity);
            self.last = now;
        }
    }

    fn full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.capacity
    }
}

/// Why a connection or a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Over the rate.
    RateLimited,
    /// Over the connection caps.
    TooManyConnections,
    /// Over the calls in flight.
    TooManyInFlight,
    /// Over the sessions.
    TooManySessions,
}

impl Refusal {
    /// The peer line's `reason` and the call line's `outcome` (R-64, R-66).
    pub(crate) fn word(self) -> &'static str {
        match self {
            Refusal::RateLimited => "rate_limited",
            Refusal::TooManyConnections => "too_many_connections",
            Refusal::TooManyInFlight | Refusal::TooManySessions => "too_many",
        }
    }
}

struct PerIp {
    bucket: TokenBucket,
    live: u32,
}

#[derive(Default)]
struct SlotState {
    per_ip: HashMap<IpAddr, PerIp>,
    public_live: u32,
    private_live: u32,
}

/// A connection's slot, released on drop.
pub struct ConnSlot {
    state: Arc<Mutex<SlotState>>,
    face: Face,
    ip: IpAddr,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match self.face {
            Face::Public => {
                st.public_live = st.public_live.saturating_sub(1);
                if let Some(p) = st.per_ip.get_mut(&self.ip) {
                    p.live = p.live.saturating_sub(1);
                }
            }
            Face::Private => st.private_live = st.private_live.saturating_sub(1),
        }
    }
}

/// The per-IP connection slots and buckets of both faces.
pub struct IpSlots {
    state: Arc<Mutex<SlotState>>,
    public_max: u32,
    per_ip: u32,
    burst: u32,
    per_min: u32,
    private_max: u32,
}

impl IpSlots {
    /// The slots of R-2's limits.
    pub(crate) fn new(l: &Limits) -> IpSlots {
        IpSlots {
            state: Arc::default(),
            public_max: l.public_conns_max,
            per_ip: l.public_conns_per_ip,
            burst: l.public_accepts_burst,
            per_min: l.public_accepts_per_min,
            private_max: l.private_conns_max,
        }
    }

    /// A slot for a connection from `ip` on `face`, or the refusal (R-2).
    pub fn admit(&self, face: Face, ip: std::net::IpAddr, now: tokio::time::Instant) -> Result<ConnSlot, Refusal> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match face {
            Face::Public => {
                if st.public_live >= self.public_max {
                    return Err(Refusal::TooManyConnections);
                }
                let (burst, per_min) = (self.burst, self.per_min);
                let peer = st.per_ip.entry(ip).or_insert_with(|| PerIp { bucket: TokenBucket::new(burst, per_min, now), live: 0 });
                if !peer.bucket.take(now) {
                    return Err(Refusal::RateLimited);
                }
                if peer.live >= self.per_ip {
                    return Err(Refusal::TooManyConnections);
                }
                peer.live += 1;
                st.public_live += 1;
            }
            Face::Private => {
                if st.private_live >= self.private_max {
                    return Err(Refusal::TooManyConnections);
                }
                st.private_live += 1;
            }
        }
        Ok(ConnSlot { state: Arc::clone(&self.state), face, ip })
    }

    /// Forgets the peers with no live connection and a full bucket.
    pub(crate) fn sweep(&self, now: Instant) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).per_ip.retain(|_, p| p.live > 0 || !p.bucket.full(now));
    }
}

/// A call's in-flight permit.
pub struct SessionPass {
    in_flight: Arc<AtomicU32>,
}

impl Drop for SessionPass {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Slot {
    bucket: TokenBucket,
    in_flight: Arc<AtomicU32>,
    last_used: Instant,
}

/// The private face's sessions.
pub struct Sessions {
    map: DashMap<String, Slot>,
    burst: u32,
    per_min: u32,
    calls_per_session: u32,
    sessions_max: usize,
}

impl Sessions {
    /// The sessions of R-57's limits.
    pub(crate) fn new(l: &Limits) -> Sessions {
        Sessions {
            map: DashMap::new(),
            burst: l.session_burst,
            per_min: l.session_per_min,
            calls_per_session: l.calls_per_session,
            sessions_max: l.sessions_max as usize,
        }
    }

    /// One request of a session: the bucket, then (for a Call) its in-flight permit (R-57).
    pub fn enter(&self, session_id: &str, call: bool, now: tokio::time::Instant) -> Result<Option<SessionPass>, Refusal> {
        if !self.map.contains_key(session_id) && self.map.len() >= self.sessions_max {
            return Err(Refusal::TooManySessions);
        }
        let mut slot = self.map.entry(session_id.to_string()).or_insert_with(|| Slot {
            bucket: TokenBucket::new(self.burst, self.per_min, now),
            in_flight: Arc::new(AtomicU32::new(0)),
            last_used: now,
        });
        if !slot.bucket.take(now) {
            return Err(Refusal::RateLimited);
        }
        slot.last_used = now;
        if !call {
            return Ok(None);
        }
        if slot.in_flight.load(Ordering::SeqCst) >= self.calls_per_session {
            return Err(Refusal::TooManyInFlight);
        }
        slot.in_flight.fetch_add(1, Ordering::SeqCst);
        Ok(Some(SessionPass { in_flight: Arc::clone(&slot.in_flight) }))
    }

    /// Drops sessions idle for 600 s with nothing in flight (R-58).
    pub fn sweep(&self, now: tokio::time::Instant) {
        self.map.retain(|_, s| s.in_flight.load(Ordering::SeqCst) > 0 || now.saturating_duration_since(s.last_used) < SESSION_IDLE);
    }

    /// How many sessions are kept (the status line).
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit 21 (virtual time: every instant is given, none is waited for).
    #[test]
    fn a_token_bucket_refills_at_its_rate() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(20, 20, t0);
        assert!((0..20).all(|_| b.take(t0)), "the burst");
        assert!(!b.take(t0), "the 21st");
        let t3 = t0 + Duration::from_secs(3);
        assert!(b.take(t3), "3 s at 20 a minute is one token");
        assert!(!b.take(t3));
        let hour = t3 + Duration::from_secs(3600);
        assert!((0..20).all(|_| b.take(hour)));
        assert!(!b.take(hour), "never above the burst after an idle hour");
    }

    /// Unit 22.
    #[test]
    fn ip_slots_count_and_release() {
        let l = Limits { private_conns_max: 2, ..Limits::default() };
        let slots = IpSlots::new(&l);
        let now = Instant::now();
        let a: IpAddr = "198.51.100.7".parse().unwrap();
        let b: IpAddr = "203.0.113.9".parse().unwrap();
        let mut held: Vec<ConnSlot> = (0..8).map(|_| slots.admit(Face::Public, a, now).expect("eight from one IP")).collect();
        assert_eq!(slots.admit(Face::Public, a, now).err(), Some(Refusal::TooManyConnections), "the ninth");
        held.pop();
        assert!(slots.admit(Face::Public, a, now).is_ok(), "one released, the next admitted");
        assert!(slots.admit(Face::Public, b, now).is_ok(), "another IP unaffected");
        let p1 = slots.admit(Face::Private, a, now).unwrap();
        let _p2 = slots.admit(Face::Private, b, now).unwrap();
        assert_eq!(slots.admit(Face::Private, "10.42.1.9".parse().unwrap(), now).err(), Some(Refusal::TooManyConnections), "private_conns_max only");
        drop(p1);
        assert!(slots.admit(Face::Private, a, now).is_ok());
    }

    #[test]
    fn sessions_bound_their_rate_and_their_calls() {
        let l = Limits { calls_per_session: 2, session_burst: 5, sessions_max: 2, ..Limits::default() };
        let s = Sessions::new(&l);
        let now = Instant::now();
        let p1 = s.enter("s1", true, now).unwrap().expect("a pass");
        let _p2 = s.enter("s1", true, now).unwrap().expect("a pass");
        assert_eq!(s.enter("s1", true, now).err(), Some(Refusal::TooManyInFlight));
        drop(p1);
        assert!(s.enter("s1", true, now).is_ok());
        assert!(s.enter("s1", false, now).is_ok(), "the fifth request of the burst");
        assert_eq!(s.enter("s1", false, now).err(), Some(Refusal::RateLimited), "the sixth");
        assert!(s.enter("s2", false, now).is_ok());
        assert_eq!(s.enter("s3", false, now).err(), Some(Refusal::TooManySessions));
        s.sweep(now + SESSION_IDLE);
        assert_eq!(s.len(), 1, "s2 idle with nothing in flight is dropped; s1 keeps its calls");
    }
}
