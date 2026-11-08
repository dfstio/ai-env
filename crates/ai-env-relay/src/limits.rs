//! Token buckets, per-IP slots and bans, the private face's accept bucket, and sessions (R-2, R-57, R-58, R-98 to
//! R-104, R-112, R-136). Synchronous only (R-75, a `make lint` guard): nothing in this file awaits; every map is a private
//! field here, and every method returns owned values.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use tokio::time::Instant;

use crate::config::Limits;
use crate::tls::Face;

/// One token, in the bucket's unit: a token a minute refills one unit a nanosecond, so every refill is exact.
const TOKEN: u128 = 60_000_000_000;
/// A session idle this long, with nothing in flight, is dropped (R-58).
const SESSION_IDLE: Duration = Duration::from_secs(600);
/// R-100: the public face's per-IP map holds at most this many peers.
pub const PER_IP_MAX: usize = 8192;
/// R-112: a session's charged evictions are counted in a fixed window this long from the first of them.
const EVICTION_WINDOW: Duration = Duration::from_secs(600);

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
        self.take_n(1, now)
    }

    /// Takes `n` tokens if there are that many (R-107's bytes); else takes none.
    pub fn take_n(&mut self, n: u64, now: Instant) -> bool {
        self.refill(now);
        let need = u128::from(n) * TOKEN;
        if self.tokens >= need {
            self.tokens -= need;
            true
        } else {
            false
        }
    }

    /// Gives `n` tokens back (LD-R53's bytes), never above the burst.
    pub fn give_n(&mut self, n: u64) {
        self.tokens = self.tokens.saturating_add(u128::from(n) * TOKEN).min(self.capacity);
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
    /// The public peer is banned (R-98, R-99).
    Banned,
}

impl Refusal {
    /// The peer line's `reason` and the call line's `outcome` (R-64, R-66).
    pub(crate) fn word(self) -> &'static str {
        match self {
            Refusal::RateLimited => "rate_limited",
            Refusal::TooManyConnections => "too_many_connections",
            Refusal::TooManyInFlight | Refusal::TooManySessions => "too_many",
            Refusal::Banned => "banned",
        }
    }
}

/// One public peer (R-2, R-98): its accept bucket, its live connections, its faults and ban, its tunnels.
struct PerIp {
    bucket: TokenBucket,
    live: u32,
    /// Faults counted in the window that opened at `window_from` (R-98).
    faults: u32,
    window_from: Instant,
    banned_until: Option<Instant>,
    /// Its last admission or fault: the oldest idle peer is the one a full map forgets (R-100).
    last_seen: Instant,
    /// Its live tunnels (`authenticated` less `tunnel_ended`) and its last tunnel's end: its faults then count nothing.
    tunnels: u32,
    last_tunnel_end: Option<Instant>,
}

impl PerIp {
    fn new(burst: u32, per_min: u32, now: Instant) -> PerIp {
        PerIp {
            bucket: TokenBucket::new(burst, per_min, now),
            live: 0,
            faults: 0,
            window_from: now,
            banned_until: None,
            last_seen: now,
            tunnels: 0,
            last_tunnel_end: None,
        }
    }

    fn banned(&self, now: Instant) -> bool {
        self.banned_until.is_some_and(|until| now < until)
    }

    /// R-98's exemption: a live tunnel, or one that ended less than `window` ago.
    fn exempt(&self, now: Instant, window: Duration) -> bool {
        self.tunnels > 0 || self.last_tunnel_end.is_some_and(|end| now < end + window)
    }

    fn window_open(&self, now: Instant, window: Duration) -> bool {
        self.faults > 0 && now < self.window_from + window
    }

    /// R-100's sweep keeps it.
    fn kept(&mut self, now: Instant, window: Duration) -> bool {
        self.live > 0 || !self.bucket.full(now) || self.banned(now) || self.window_open(now, window) || self.exempt(now, window)
    }
}

#[derive(Default)]
struct SlotState {
    per_ip: HashMap<IpAddr, PerIp>,
    public_live: u32,
    private_live: u32,
    /// R-104: the private face's one accept bucket (every VM shares one address), made at the face's first admission.
    private_bucket: Option<TokenBucket>,
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

/// The per-IP connection slots, buckets and bans of the public face, and the private face's cap and bucket.
pub struct IpSlots {
    state: Arc<Mutex<SlotState>>,
    public_max: u32,
    per_ip: u32,
    burst: u32,
    per_min: u32,
    private_max: u32,
    private_burst: u32,
    private_per_min: u32,
    ban_faults: u32,
    ban_window: Duration,
    ban_for: Duration,
}

impl IpSlots {
    /// The slots of R-2's, R-98's and R-104's limits.
    pub(crate) fn new(l: &Limits) -> IpSlots {
        IpSlots {
            state: Arc::default(),
            public_max: l.public_conns_max,
            per_ip: l.public_conns_per_ip,
            burst: l.public_accepts_burst,
            per_min: l.public_accepts_per_min,
            private_max: l.private_conns_max,
            private_burst: l.private_accepts_burst,
            private_per_min: l.private_accepts_per_min,
            ban_faults: l.ban_faults,
            ban_window: Duration::from_secs(u64::from(l.ban_window_s)),
            ban_for: Duration::from_secs(u64::from(l.ban_s)),
        }
    }

    /// `ip`'s entry, made as `admit` makes one when absent. A full map first forgets the peer with the oldest
    /// `last_seen` among those with no live connection and no ban in force; None when every entry is live or banned
    /// (R-100).
    fn peer<'a>(&self, st: &'a mut SlotState, ip: IpAddr, now: Instant) -> Option<&'a mut PerIp> {
        if !st.per_ip.contains_key(&ip) {
            if st.per_ip.len() >= PER_IP_MAX {
                let oldest = st.per_ip.iter().filter(|(_, p)| p.live == 0 && !p.banned(now)).min_by_key(|(_, p)| p.last_seen).map(|(k, _)| *k)?;
                st.per_ip.remove(&oldest);
            }
            st.per_ip.insert(ip, PerIp::new(self.burst, self.per_min, now));
        }
        st.per_ip.get_mut(&ip)
    }

    /// A slot for a connection from `ip` on `face`, or the refusal (R-2, R-99, R-104). Public: a ban in force first
    /// (a ban that passed is cleared here), then the face's cap, the peer's bucket and its live count. Private: the
    /// face's cap, then the face's one bucket.
    pub fn admit(&self, face: Face, ip: std::net::IpAddr, now: tokio::time::Instant) -> Result<ConnSlot, Refusal> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match face {
            Face::Public => {
                if let Some(p) = st.per_ip.get_mut(&ip) {
                    match p.banned_until {
                        Some(until) if now < until => return Err(Refusal::Banned),
                        Some(_) => p.banned_until = None,
                        None => {}
                    }
                }
                if st.public_live >= self.public_max {
                    return Err(Refusal::TooManyConnections);
                }
                let Some(peer) = self.peer(&mut st, ip, now) else {
                    return Err(Refusal::TooManyConnections);
                };
                peer.last_seen = now;
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
                let (burst, per_min) = (self.private_burst, self.private_per_min);
                if !st.private_bucket.get_or_insert_with(|| TokenBucket::new(burst, per_min, now)).take(now) {
                    return Err(Refusal::RateLimited);
                }
                st.private_live += 1;
            }
        }
        Ok(ConnSlot { state: Arc::clone(&self.state), face, ip })
    }

    /// One fault of the public peer `ip` (R-98, R-102); true when it started a ban. A peer holding a live tunnel, or
    /// whose last tunnel ended less than `ban_window_s` ago, counts nothing; a banned one gains nothing; else the
    /// fault is counted in its window (a window past `ban_window_s` restarts), and `ban_faults` of them ban it for
    /// `ban_s`. A full map of live or banned peers drops the fault (R-100).
    pub fn fault(&self, ip: std::net::IpAddr, now: tokio::time::Instant) -> bool {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(p) = self.peer(&mut st, ip, now) else { return false };
        p.last_seen = now;
        if p.exempt(now, self.ban_window) || p.banned(now) {
            return false;
        }
        if p.faults == 0 || now >= p.window_from + self.ban_window {
            p.window_from = now;
            p.faults = 0;
        }
        p.faults += 1;
        if p.faults >= self.ban_faults {
            p.banned_until = Some(now + self.ban_for);
            p.faults = 0;
            return true;
        }
        false
    }

    /// R-98: a tunnel of `ip` authenticated (`AuthOk`).
    pub fn authenticated(&self, ip: std::net::IpAddr, now: tokio::time::Instant) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(p) = self.peer(&mut st, ip, now) {
            p.tunnels += 1;
        }
    }

    /// R-98: a tunnel of `ip` ended: one tunnel fewer, and the end stamped.
    pub fn tunnel_ended(&self, ip: std::net::IpAddr, now: tokio::time::Instant) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(p) = self.peer(&mut st, ip, now) {
            p.tunnels = p.tunnels.saturating_sub(1);
            p.last_tunnel_end = Some(now);
        }
    }

    /// R-100: forgets every peer with no live connection, a full bucket, no ban in force, no open window, no live
    /// tunnel and no tunnel end within `ban_window_s`.
    pub(crate) fn sweep(&self, now: Instant) {
        let window = self.ban_window;
        self.state.lock().unwrap_or_else(PoisonError::into_inner).per_ip.retain(|_, p| p.kept(now, window));
    }

    /// Whether the per-IP map holds `ip` (the unit tests).
    #[cfg(test)]
    fn holds(&self, ip: IpAddr) -> bool {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).per_ip.contains_key(&ip)
    }

    /// The per-IP map's size (the unit tests).
    #[cfg(test)]
    fn peers(&self) -> usize {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).per_ip.len()
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
    /// The token signer that made it, whose share of the sessions it counts in and whose tokens alone enter it (R-136).
    signer: String,
    bucket: TokenBucket,
    in_flight: Arc<AtomicU32>,
    last_used: Instant,
    /// R-112: charged evictions in the window that opened at the first of them.
    evictions: u32,
    evicted_from: Option<Instant>,
}

impl Slot {
    fn window_open(&self, now: Instant) -> bool {
        self.evicted_from.is_some_and(|from| now < from + EVICTION_WINDOW)
    }
}

/// The private face's sessions.
pub struct Sessions {
    map: DashMap<String, Slot>,
    /// R-136: the slots each token signer holds. Taken only while one of `map`'s shards is held, never the other way
    /// round, so the two maps cannot deadlock.
    per_signer: DashMap<String, u32>,
    burst: u32,
    per_min: u32,
    calls_per_session: u32,
    sessions_max: usize,
    sessions_per_signer: u32,
    evictions_max: u32,
}

impl Sessions {
    /// The sessions of R-57's, R-112's and R-136's limits.
    pub(crate) fn new(l: &Limits) -> Sessions {
        Sessions {
            map: DashMap::new(),
            per_signer: DashMap::new(),
            burst: l.session_burst,
            per_min: l.session_per_min,
            calls_per_session: l.calls_per_session,
            sessions_max: l.sessions_max as usize,
            sessions_per_signer: l.sessions_per_signer,
            evictions_max: l.session_evictions_per_10min,
        }
    }

    /// One request of a session of the token signer `signer_id`: a new session within `sessions_max` and the signer's
    /// share, a held one only for the signer that made it (R-136), the bucket, then for a Call its evictions (R-112) and
    /// its in-flight permit (R-57).
    pub fn enter(&self, session_id: &str, signer_id: &str, call: bool, now: tokio::time::Instant) -> Result<Option<SessionPass>, Refusal> {
        if !self.map.contains_key(session_id) && self.map.len() >= self.sessions_max {
            return Err(Refusal::TooManySessions);
        }
        let mut slot = match self.map.entry(session_id.to_string()) {
            // Workers see a session's id: another signer's token naming it takes nothing from its bucket, charges it no
            // eviction and keeps it no longer.
            Entry::Occupied(held) if held.get().signer != signer_id => return Err(Refusal::TooManySessions),
            Entry::Occupied(held) => held.into_ref(),
            Entry::Vacant(new) => {
                self.count_new(signer_id)?;
                new.insert(Slot {
                    signer: signer_id.to_string(),
                    bucket: TokenBucket::new(self.burst, self.per_min, now),
                    in_flight: Arc::new(AtomicU32::new(0)),
                    last_used: now,
                    evictions: 0,
                    evicted_from: None,
                })
            }
        };
        if !slot.bucket.take(now) {
            return Err(Refusal::RateLimited);
        }
        slot.last_used = now;
        if !call {
            return Ok(None);
        }
        // R-112: a session past its evictions makes no new call until its window ends; its lists go on.
        if slot.evictions >= self.evictions_max && slot.window_open(now) {
            return Err(Refusal::RateLimited);
        }
        if slot.in_flight.load(Ordering::SeqCst) >= self.calls_per_session {
            return Err(Refusal::TooManyInFlight);
        }
        slot.in_flight.fetch_add(1, Ordering::SeqCst);
        Ok(Some(SessionPass { in_flight: Arc::clone(&slot.in_flight) }))
    }

    /// R-136: one more session of `signer_id`, unless it holds its share: one key cannot fill `sessions_max`.
    fn count_new(&self, signer_id: &str) -> Result<(), Refusal> {
        let mut held = self.per_signer.entry(signer_id.to_string()).or_insert(0);
        if *held >= self.sessions_per_signer {
            return Err(Refusal::TooManySessions);
        }
        *held += 1;
        Ok(())
    }

    /// R-136: one session of `signer_id` less; a signer that holds none is forgotten.
    fn count_gone(&self, signer_id: &str) {
        if let Some(mut held) = self.per_signer.get_mut(signer_id) {
            *held = held.saturating_sub(1);
        }
        self.per_signer.remove_if(signer_id, |_, held| *held == 0);
    }

    /// R-112: one charged eviction of the session's calls. The first opens a fixed 600 s window; the session's
    /// `session_evictions_per_10min`-th in it refuses its new calls until the window ends.
    pub fn evicted(&self, session_id: &str, now: tokio::time::Instant) {
        if let Some(mut slot) = self.map.get_mut(session_id) {
            if !slot.window_open(now) {
                slot.evicted_from = Some(now);
                slot.evictions = 0;
            }
            slot.evictions = slot.evictions.saturating_add(1);
        }
    }

    /// Drops sessions idle for 600 s with nothing in flight and no eviction window open (R-58, R-112), each signer's share
    /// with them (R-136).
    pub fn sweep(&self, now: tokio::time::Instant) {
        self.map.retain(|_, s| {
            let keep = s.in_flight.load(Ordering::SeqCst) > 0 || now.saturating_duration_since(s.last_used) < SESSION_IDLE || s.window_open(now);
            if !keep {
                self.count_gone(&s.signer);
            }
            keep
        });
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

        // R-107's bytes: n tokens at once, or none.
        let mut bytes = TokenBucket::new(1000, 600, t0);
        assert!(bytes.take_n(600, t0));
        assert!(!bytes.take_n(401, t0), "short: nothing taken");
        assert!(bytes.take_n(400, t0), "the 400 left are all there");
        assert!(!bytes.take_n(1, t0));
        assert!(bytes.take_n(10, t0 + Duration::from_secs(1)), "600 a minute is 10 a second");
        assert!(!bytes.take_n(1, t0 + Duration::from_secs(1)));
    }

    /// LD-R53: tokens given back come out again, up to the burst and never above it, at the instant they are given as
    /// after any refill.
    #[test]
    fn tokens_given_back_never_pass_the_burst() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(1000, 600, t0);
        assert!(b.take_n(700, t0));
        b.give_n(200);
        assert!(b.take_n(500, t0), "the 300 left and the 200 back");
        assert!(!b.take_n(1, t0));
        b.give_n(1000);
        b.give_n(1);
        assert!(!b.take_n(1001, t0), "a full bucket given one more holds its burst");
        assert!(b.take_n(1000, t0), "and all of it");
        b.give_n(u64::MAX);
        assert!(!b.take_n(1001, t0), "the most anyone can give");
        assert!(b.take_n(999, t0));
        let t1 = t0 + Duration::from_secs(1);
        b.give_n(5);
        assert!(b.take_n(16, t1), "the 1 left, the 5 back and a second's 10");
        assert!(!b.take_n(1, t1));
        // Given back, then refilled: the refill stops at the burst too.
        let hour = t1 + Duration::from_secs(3600);
        b.give_n(1000);
        assert!(!b.take_n(1001, hour));
        assert!(b.take_n(1000, hour));
    }

    /// Unit 22 (R-99 amended: the ban comes before the cap and the bucket; the cap before a new peer's entry and bucket).
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

        // An address with its eight live connections and its bucket empty, then a ban in force: refused `Banned`,
        // not `TooManyConnections` nor `RateLimited`.
        let c: IpAddr = "198.51.100.9".parse().unwrap();
        let _live: Vec<ConnSlot> = (0..8).map(|_| slots.admit(Face::Public, c, now).expect("eight from one IP")).collect();
        for _ in 0..12 {
            assert_eq!(slots.admit(Face::Public, c, now).err(), Some(Refusal::TooManyConnections), "the live count, a token each");
        }
        assert_eq!(slots.admit(Face::Public, c, now).err(), Some(Refusal::RateLimited), "the bucket is empty");
        assert!(!(0..19).any(|_| slots.fault(c, now)));
        assert!(slots.fault(c, now), "the 20th fault bans");
        assert_eq!(slots.admit(Face::Public, c, now).err(), Some(Refusal::Banned), "the ban before the bucket and the live count");
        // The face's cap reached: the ban still comes first.
        let capped = IpSlots::new(&Limits { public_conns_max: 1, ..Limits::default() });
        let _only = capped.admit(Face::Public, a, now).unwrap();
        assert!(!(0..19).any(|_| capped.fault(b, now)));
        assert!(capped.fault(b, now));
        assert_eq!(capped.admit(Face::Public, b, now).err(), Some(Refusal::Banned), "before the face's cap");
        // R-99's order: with the face's cap reached, a new peer is refused before its bucket and its entry. A released
        // slot opens the cap again, and the new peer's refusals cost none of its burst.
        for _ in 0..3 {
            assert_eq!(capped.admit(Face::Public, c, now).err(), Some(Refusal::TooManyConnections), "the face's cap");
        }
        assert!(!capped.holds(c), "refused before any per-IP state");
        drop(_only);
        drop(capped.admit(Face::Public, a, now).expect("the slot released: the cap is open again"));
        for i in 0..20 {
            drop(capped.admit(Face::Public, c, now).unwrap_or_else(|r| panic!("{i} of the new peer's whole burst: {r:?}")));
        }
        assert_eq!(capped.admit(Face::Public, c, now).err(), Some(Refusal::RateLimited), "its burst of 20, whole");
    }

    /// Unit 39 (R-98, R-99, R-100; explicit instants).
    #[test]
    fn a_peer_is_banned_at_its_threshold_and_freed_after_its_ban() {
        let l = Limits { public_accepts_burst: 1000, public_accepts_per_min: 6000, ..Limits::default() };
        let (window, ban) = (Duration::from_secs(u64::from(l.ban_window_s)), Duration::from_secs(u64::from(l.ban_s)));
        assert_eq!((l.ban_faults, window, ban), (20, Duration::from_secs(600), Duration::from_secs(900)));
        let slots = IpSlots::new(&l);
        let t0 = Instant::now();
        let a: IpAddr = "198.51.100.7".parse().unwrap();
        let other: IpAddr = "203.0.113.9".parse().unwrap();
        for i in 0..19 {
            assert!(!slots.fault(a, t0 + Duration::from_secs(i)), "fault {i}");
        }
        drop(slots.admit(Face::Public, a, t0 + Duration::from_secs(19)).expect("19 faults: admitted"));
        let banned_at = t0 + Duration::from_secs(20);
        assert!(slots.fault(a, banned_at), "the 20th starts the ban");
        assert_eq!(slots.admit(Face::Public, a, banned_at).err(), Some(Refusal::Banned));
        assert!(!slots.fault(a, banned_at + Duration::from_secs(1)), "a banned peer gains nothing");
        assert!(slots.admit(Face::Public, other, banned_at).is_ok(), "another address unaffected");
        assert_eq!(slots.admit(Face::Public, a, banned_at + ban - Duration::from_millis(1)).err(), Some(Refusal::Banned), "until ban_s");
        let freed = banned_at + ban;
        drop(slots.admit(Face::Public, a, freed).expect("ban_s later: admitted"));
        // The window is new: 19 faults do not ban, the 20th does.
        assert!(!(0..19).any(|i| slots.fault(a, freed + Duration::from_millis(i))));
        assert!(slots.fault(a, freed + Duration::from_millis(19)));

        // Faults spread over more than ban_window_s never ban: each window restarts at its first fault.
        let spread: IpAddr = "198.51.100.8".parse().unwrap();
        let mut t = t0;
        for i in 0..60 {
            assert!(!slots.fault(spread, t), "fault {i}");
            // 19 in each window, the next one 600 s after the window's first.
            t += if i % 19 == 18 { window - Duration::from_secs(18) } else { Duration::from_secs(1) };
        }
        assert!(slots.admit(Face::Public, spread, t).is_ok());

        // The sweep keeps a banned entry and an open window, and drops an idle full one.
        let s = IpSlots::new(&l);
        let (banned, open, idle) = ("198.51.100.20".parse().unwrap(), "198.51.100.21".parse().unwrap(), "198.51.100.22".parse().unwrap());
        for _ in 0..20 {
            s.fault(banned, t0);
        }
        s.fault(open, t0);
        drop(s.admit(Face::Public, idle, t0).unwrap());
        let later = t0 + Duration::from_secs(300);
        s.sweep(later);
        assert!(s.holds(banned) && s.holds(open), "a ban in force and an open window are kept");
        assert!(!s.holds(idle), "an idle peer whose bucket refilled is forgotten");
        s.sweep(t0 + ban + Duration::from_secs(1));
        assert!(!s.holds(banned) && !s.holds(open), "ban and window over: forgotten");

        // R-98's exemption: a live tunnel's address, and one whose tunnel ended 599 s before, fault 25 times
        // unbanned; 601 s after the end, 20 faults ban it.
        let s = IpSlots::new(&l);
        let (live, ended): (IpAddr, IpAddr) = ("198.51.100.30".parse().unwrap(), "198.51.100.31".parse().unwrap());
        s.authenticated(live, t0);
        s.authenticated(ended, t0);
        s.tunnel_ended(ended, t0);
        assert!(!(0..25).any(|_| s.fault(live, t0 + Duration::from_secs(10))), "a live tunnel's address is never banned");
        assert!(!(0..25).any(|_| s.fault(ended, t0 + Duration::from_secs(599))), "599 s after its tunnel's end");
        assert!(s.admit(Face::Public, live, t0 + Duration::from_secs(10)).is_ok() && s.admit(Face::Public, ended, t0 + Duration::from_secs(599)).is_ok());
        let after = t0 + Duration::from_secs(601);
        assert!(!(0..19).any(|_| s.fault(ended, after)));
        assert!(s.fault(ended, after), "601 s after the end: the 20th fault bans");
        assert_eq!(s.admit(Face::Public, ended, after).err(), Some(Refusal::Banned));
        s.sweep(t0 + Duration::from_secs(400));
        assert!(s.holds(live), "a live tunnel's entry is kept");
    }

    /// Unit 40 (R-100).
    #[test]
    fn the_per_ip_map_is_capped_and_evicts_the_oldest_idle_peer() {
        let l = Limits { public_conns_max: 10_000, ..Limits::default() };
        let slots = IpSlots::new(&l);
        let t0 = Instant::now();
        // 8193 peers: the IPv6 documentation prefix (2001:db8::/32), since the IPv4 ranges hold 768 addresses.
        let ip = |i: usize| IpAddr::from(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, i as u16));
        // 8192 peers: the first idle (seen at t0), every other one live, seen later.
        drop(slots.admit(Face::Public, ip(0), t0).unwrap());
        let mut held = Vec::new();
        for i in 1..PER_IP_MAX {
            held.push(slots.admit(Face::Public, ip(i), t0 + Duration::from_secs(1)).unwrap());
        }
        assert_eq!(slots.peers(), PER_IP_MAX);
        let t1 = t0 + Duration::from_secs(2);
        assert!(slots.admit(Face::Public, ip(PER_IP_MAX), t1).is_ok(), "a new peer");
        assert_eq!(slots.peers(), PER_IP_MAX, "the map stays at 8192");
        assert!(!slots.holds(ip(0)) && slots.holds(ip(PER_IP_MAX)), "the oldest idle peer was forgotten");

        // Of two idle peers the older goes; a banned one never.
        let s = IpSlots::new(&l);
        for _ in 0..20 {
            s.fault(ip(0), t0);
        }
        drop(s.admit(Face::Public, ip(1), t0 + Duration::from_secs(1)).unwrap());
        drop(s.admit(Face::Public, ip(2), t0 + Duration::from_secs(2)).unwrap());
        let mut live = Vec::new();
        for i in 3..PER_IP_MAX {
            live.push(s.admit(Face::Public, ip(i), t0 + Duration::from_secs(3)).unwrap());
        }
        s.fault(ip(PER_IP_MAX), t0 + Duration::from_secs(4));
        assert!(s.holds(ip(0)), "the banned peer, the oldest, stays");
        assert!(!s.holds(ip(1)) && s.holds(ip(2)), "the oldest idle unbanned one went");

        // A map of live or banned entries refuses the new peer and drops its fault.
        let full = IpSlots::new(&l);
        let mut live = Vec::new();
        for i in 0..PER_IP_MAX / 2 {
            live.push(full.admit(Face::Public, ip(i), t0).unwrap());
        }
        for i in PER_IP_MAX / 2..PER_IP_MAX {
            for _ in 0..20 {
                full.fault(ip(i), t0);
            }
        }
        assert_eq!(full.peers(), PER_IP_MAX);
        let newcomer = ip(PER_IP_MAX);
        assert_eq!(full.admit(Face::Public, newcomer, t0).err(), Some(Refusal::TooManyConnections));
        assert!(!full.fault(newcomer, t0), "its fault is dropped");
        assert!(!full.holds(newcomer) && full.peers() == PER_IP_MAX);
        drop(live);
    }

    /// Unit 41 (R-104: one bucket for the face, behind its cap).
    #[test]
    fn the_private_accept_bucket_is_one_for_the_face() {
        let l = Limits::default();
        assert_eq!((l.private_accepts_burst, l.private_accepts_per_min), (64, 120));
        let slots = IpSlots::new(&l);
        let t0 = Instant::now();
        let (a, b): (IpAddr, IpAddr) = ("10.42.1.10".parse().unwrap(), "10.42.1.11".parse().unwrap());
        for i in 0..64 {
            drop(slots.admit(Face::Private, if i % 2 == 0 { a } else { b }, t0).expect("the face's burst"));
        }
        assert_eq!(slots.admit(Face::Private, a, t0).err(), Some(Refusal::RateLimited), "the 65th, whichever address");
        assert_eq!(slots.admit(Face::Private, b, t0).err(), Some(Refusal::RateLimited));
        let half = t0 + Duration::from_millis(500);
        drop(slots.admit(Face::Private, b, half).expect("120 a minute: one token back 0.5 s later"));
        assert_eq!(slots.admit(Face::Private, a, half).err(), Some(Refusal::RateLimited));
        // The public face's buckets are untouched (and the private face makes no per-IP entry).
        assert!(!slots.holds(a) && !slots.holds(b));
        for _ in 0..20 {
            drop(slots.admit(Face::Public, "198.51.100.7".parse().unwrap(), t0).expect("the public burst"));
        }

        // R-104's order: the face's cap before its bucket, so connections refused at the cap burn none of its tokens.
        let capped = IpSlots::new(&Limits { private_conns_max: 1, private_accepts_burst: 2, ..Limits::default() });
        let only = capped.admit(Face::Private, a, t0).expect("the face's one slot");
        for _ in 0..2 {
            assert_eq!(capped.admit(Face::Private, b, t0).err(), Some(Refusal::TooManyConnections), "the cap, not the bucket");
        }
        drop(only);
        assert!(capped.admit(Face::Private, b, t0).is_ok(), "the slot released, the burst's second token still there");
    }

    /// Unit 42 (R-112).
    #[test]
    fn a_session_past_its_evictions_is_refused_its_calls() {
        let l = Limits::default();
        assert_eq!(l.session_evictions_per_10min, 3);
        let s = Sessions::new(&l);
        let t0 = Instant::now();
        drop(s.enter("s1", "mac", true, t0).unwrap());
        s.evicted("s1", t0);
        s.evicted("s1", t0 + Duration::from_secs(100));
        drop(s.enter("s1", "mac", true, t0 + Duration::from_secs(101)).expect("two evictions: calls go on"));
        s.evicted("s1", t0 + Duration::from_secs(200));
        assert_eq!(s.enter("s1", "mac", true, t0 + Duration::from_secs(201)).err(), Some(Refusal::RateLimited), "the third: calls refused");
        assert!(s.enter("s1", "mac", false, t0 + Duration::from_secs(202)).is_ok(), "a list is not refused");
        assert!(s.enter("s2", "mac", true, t0 + Duration::from_secs(203)).is_ok(), "another session unaffected");
        assert_eq!(s.enter("s1", "mac", true, t0 + Duration::from_secs(599)).err(), Some(Refusal::RateLimited), "until the window ends");
        drop(s.enter("s1", "mac", true, t0 + Duration::from_secs(600)).expect("600 s after the first eviction"));
        // A new window opens at the next eviction.
        s.evicted("s1", t0 + Duration::from_secs(700));
        drop(s.enter("s1", "mac", true, t0 + Duration::from_secs(701)).expect("one eviction in the new window"));
        // A session idle past 600 s whose eviction window is still open keeps its count through the sweep.
        let w = Sessions::new(&l);
        drop(w.enter("s3", "mac", true, t0).unwrap());
        for i in 0..3 {
            w.evicted("s3", t0 + Duration::from_secs(100 + i));
        }
        w.sweep(t0 + Duration::from_secs(650));
        assert_eq!(w.len(), 1, "idle 650 s, its window open until 700 s: kept");
        assert_eq!(w.enter("s3", "mac", true, t0 + Duration::from_secs(650)).err(), Some(Refusal::RateLimited));
        w.sweep(t0 + Duration::from_secs(650) + SESSION_IDLE);
        assert_eq!(w.len(), 0, "idle again and its window over: dropped");
    }

    #[test]
    fn sessions_bound_their_rate_and_their_calls() {
        let l = Limits { calls_per_session: 2, session_burst: 5, sessions_max: 2, ..Limits::default() };
        let s = Sessions::new(&l);
        let now = Instant::now();
        let p1 = s.enter("s1", "mac", true, now).unwrap().expect("a pass");
        let _p2 = s.enter("s1", "mac", true, now).unwrap().expect("a pass");
        assert_eq!(s.enter("s1", "mac", true, now).err(), Some(Refusal::TooManyInFlight));
        drop(p1);
        assert!(s.enter("s1", "mac", true, now).is_ok());
        assert!(s.enter("s1", "mac", false, now).is_ok(), "the fifth request of the burst");
        assert_eq!(s.enter("s1", "mac", false, now).err(), Some(Refusal::RateLimited), "the sixth");
        assert!(s.enter("s2", "mac", false, now).is_ok());
        assert_eq!(s.enter("s3", "mac", false, now).err(), Some(Refusal::TooManySessions));
        s.sweep(now + SESSION_IDLE);
        assert_eq!(s.len(), 1, "s2 idle with nothing in flight is dropped; s1 keeps its calls");
    }

    /// Unit 47 (R-136): a new session of a signer that holds its share is refused, before it holds any state; its own
    /// sessions go on, another signer's are admitted, `sessions_max` still binds them all, another signer's token enters
    /// no session it did not make, and the sweep gives the share back.
    #[test]
    fn one_signer_holds_at_most_its_share_of_the_sessions() {
        assert_eq!(Limits::default().sessions_per_signer, 256);
        let l = Limits { sessions_per_signer: 2, sessions_max: 5, ..Limits::default() };
        let s = Sessions::new(&l);
        let now = Instant::now();
        assert!(s.enter("a1", "mac-a", false, now).is_ok() && s.enter("a2", "mac-a", true, now).is_ok());
        assert_eq!(s.enter("a3", "mac-a", false, now).err(), Some(Refusal::TooManySessions), "the third, a list");
        assert_eq!(s.enter("a3", "mac-a", true, now).err(), Some(Refusal::TooManySessions), "the third, a call");
        assert_eq!(s.len(), 2, "a refused session holds no state");
        assert!(s.enter("a1", "mac-a", false, now).is_ok(), "a session it holds goes on");
        assert!(s.enter("a2", "mac-a", false, now).is_ok());
        assert!(s.enter("b1", "mac-b", false, now).is_ok() && s.enter("b2", "mac-b", false, now).is_ok(), "another signer's share is its own");
        assert_eq!(s.enter("b3", "mac-b", false, now).err(), Some(Refusal::TooManySessions));
        assert!(s.enter("c1", "mac-c", false, now).is_ok());
        assert_eq!(s.enter("c2", "mac-c", false, now).err(), Some(Refusal::TooManySessions), "sessions_max, whatever the share");
        assert_eq!(s.len(), 5);
        // A session is the signer's that made it: another's token in it is refused, on both calls, and makes nothing new.
        assert_eq!(s.enter("c1", "mac-a", false, now).err(), Some(Refusal::TooManySessions), "another's session, a list");
        assert_eq!(s.enter("c1", "mac-a", true, now).err(), Some(Refusal::TooManySessions), "another's session, a call");
        assert_eq!(s.per_signer.get("mac-a").map(|n| *n), Some(2));
        assert_eq!(s.per_signer.get("mac-c").map(|n| *n), Some(1));
        // It takes nothing from that session's bucket and keeps it no longer.
        let one = Sessions::new(&Limits { session_burst: 2, ..Limits::default() });
        assert!(one.enter("b1", "mac-b", false, now).is_ok());
        for _ in 0..5 {
            assert_eq!(one.enter("b1", "mac-a", false, now).err(), Some(Refusal::TooManySessions));
        }
        assert!(one.enter("b1", "mac-b", false, now).is_ok(), "the second of its burst is still its own");
        assert_eq!(one.enter("b1", "mac-b", false, now).err(), Some(Refusal::RateLimited));
        assert_eq!(one.enter("b1", "mac-a", false, now + SESSION_IDLE - Duration::from_secs(1)).err(), Some(Refusal::TooManySessions));
        one.sweep(now + SESSION_IDLE);
        assert_eq!(one.len(), 0, "idle since its own signer's last request");
        // The sweep gives a share back, and only what it dropped: a call in flight keeps its session, and its count.
        let later = now + SESSION_IDLE;
        let held = s.enter("a2", "mac-a", true, now).unwrap().expect("a pass");
        s.sweep(later);
        assert_eq!(s.len(), 1, "a2 alone, its call in flight");
        assert_eq!(s.per_signer.get("mac-a").map(|n| *n), Some(1));
        assert!(s.per_signer.get("mac-b").is_none() && s.per_signer.get("mac-c").is_none(), "a signer with no session is forgotten");
        assert!(s.enter("a3", "mac-a", false, later).is_ok(), "room again");
        assert_eq!(s.enter("a4", "mac-a", false, later).err(), Some(Refusal::TooManySessions), "a2 and a3");
        drop(held);
        let last = later + SESSION_IDLE;
        s.sweep(last);
        assert_eq!(s.len(), 0);
        assert!(s.per_signer.is_empty(), "nothing is left of any signer");
        assert!(s.enter("a5", "mac-a", false, last).is_ok() && s.enter("a6", "mac-a", false, last).is_ok());

        // Threads racing for one signer's share get exactly it, and the count stays the map's with a sweep racing them.
        let racing = Sessions::new(&Limits { sessions_per_signer: 10, sessions_max: 4096, ..Limits::default() });
        let attempts = |t: u32| (0..100).filter(|i| racing.enter(&format!("r{t}-{i}"), "mac-r", false, now).is_ok()).count();
        let admitted: usize = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8).map(|t| scope.spawn(move || attempts(t))).collect();
            threads.into_iter().map(|t| t.join().unwrap()).sum()
        });
        assert_eq!(admitted, 10, "exactly its share");
        let swept = Sessions::new(&Limits { sessions_per_signer: 2000, sessions_max: 4096, ..Limits::default() });
        std::thread::scope(|scope| {
            for t in 0..4u32 {
                let swept = &swept;
                scope.spawn(move || (0..200).for_each(|i| drop(swept.enter(&format!("s{t}-{i}"), "mac-s", false, now))));
            }
            let swept = &swept;
            scope.spawn(move || (0..50).for_each(|_| swept.sweep(now + SESSION_IDLE)));
        });
        let held = swept.per_signer.get("mac-s").map_or(0, |n| *n) as usize;
        assert_eq!(held, swept.len(), "the count is the map's");
    }
}
