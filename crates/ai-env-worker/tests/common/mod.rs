//! The worker's integration harness (§WM-worker-mac.8.2): the test PKI (`certs`), the scripted relay
//! (`fake_relay`), the testkit's sources (`sources`), and a worker wired to them.
#![allow(dead_code)]

pub mod certs;
pub mod fake_relay;
pub mod sources;

use std::sync::Arc;
use std::time::Duration;

use ai_env_worker::keys::SigningKey;
use ai_env_worker::signer::{FileSigner, Signer};
use ai_env_worker::{RelayEndpoint, Tuning, WorkerBuilder};

/// Short timings: a test's waits are milliseconds.
pub fn quick() -> Tuning {
    Tuning {
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(2),
        keepalive_interval: Duration::from_secs(15),
        keepalive_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(30),
        backoff_min: Duration::from_millis(50),
        backoff_max: Duration::from_millis(400),
        reset_after: Duration::from_millis(500),
        refused_floor: Duration::from_millis(300),
        sleep_jump: Duration::from_secs(30),
        tick: Duration::from_millis(50),
    }
}

/// The worker's key: seed 1 (WM-T10's).
pub fn key() -> SigningKey {
    SigningKey::from_seed(&[1u8; 32]).expect("seed")
}

pub fn signer() -> Arc<dyn Signer> {
    Arc::new(FileSigner::from_key(key()))
}

/// An endpoint to the fake over its duplex dialer, pinning CA A, for `ai-env-relay`.
pub fn endpoint(relay: &fake_relay::FakeRelay) -> RelayEndpoint {
    RelayEndpoint::new("ai-env-relay:443")
        .expect("an address")
        .ca_pem(&certs::pki().ca_a)
        .expect("CA A")
        .server_name("ai-env-relay")
        .expect("a name")
        .dialer(relay.dialer())
}

/// A builder for `worker-a` against the fake, with short timings.
pub fn builder(relay: &fake_relay::FakeRelay) -> WorkerBuilder {
    ai_env_worker::Worker::builder().worker_id("worker-a").relay(endpoint(relay)).signer(signer()).tuning(quick())
}
