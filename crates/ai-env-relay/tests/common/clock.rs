//! The manual wall clock (`Deps.clock`): freshness, `not_after`, token times and `last_seen` read it; the
//! relay's timers run on tokio's clock, which the paused tests advance.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ai_env_relay::Clock;

/// A wall clock that moves only when told.
pub struct ManualClock {
    now: Mutex<SystemTime>,
}

impl ManualClock {
    /// A clock at `unix` seconds.
    pub fn at(unix: u64) -> Arc<ManualClock> {
        Arc::new(ManualClock { now: Mutex::new(SystemTime::UNIX_EPOCH + Duration::from_secs(unix)) })
    }

    /// Sets it to `unix` seconds.
    pub fn set(&self, unix: u64) {
        *self.now.lock().unwrap() = SystemTime::UNIX_EPOCH + Duration::from_secs(unix);
    }

    /// Moves it on.
    pub fn advance(&self, d: Duration) {
        *self.now.lock().unwrap() += d;
    }

    /// Now, unix seconds.
    pub fn unix(&self) -> u64 {
        self.now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }

    /// Now, unix milliseconds.
    pub fn ms(&self) -> i64 {
        self.now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as i64
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.now.lock().unwrap()
    }
}
