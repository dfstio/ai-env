//! NEGATIVE clippy fixture — `make lint-negative` (T0.5) expects
//! `cargo clippy -p ai-env-cli --example tls_lint_negative --features lint-negative -- -D warnings`
//! to FAIL with one `use of a disallowed method` diagnostic per entry in
//! clippy.toml's `disallowed-methods`. Every entry there carries
//! `allow-invalid = true` (so the shim world, where these crates are absent,
//! stays quiet), which also means a path that silently stopped resolving after
//! a dependency bump would disable that rule without a sound: this file calls
//! each method once, never at runtime, and proves the paths still resolve.
//!
//! Left out on purpose: the `reqwest::blocking::ClientBuilder` pair — clippy.toml
//! does not list it and the `blocking` feature of reqwest is not enabled.
//!
//! Built only with `--features lint-negative` (`autoexamples = false`); every
//! other lint is silenced so the run fails for the disallowed methods alone.
#![allow(dead_code, unused_imports, unused_must_use, unused_variables, clippy::unused_async, clippy::needless_pass_by_value)]

fn main() {}

// tokio_tungstenite::connect_async — default connector (native/webpki roots, TLS 1.2 allowed).
async fn ws_connect_async() {
    let _ = tokio_tungstenite::connect_async("wss://example.invalid/agent").await;
}

// tokio_tungstenite::connect_async_with_config — same default connector.
async fn ws_connect_async_with_config() {
    let _ = tokio_tungstenite::connect_async_with_config("wss://example.invalid/agent", None, false).await;
}

// tokio_tungstenite::client_async_tls — default connector on a caller-supplied stream.
async fn ws_client_async_tls(stream: tokio::net::TcpStream) {
    let _ = tokio_tungstenite::client_async_tls("wss://example.invalid/agent", stream).await;
}

// reqwest::ClientBuilder::danger_accept_invalid_certs — certificate verification off.
fn reqwest_invalid_certs() -> reqwest::ClientBuilder {
    reqwest::Client::builder().danger_accept_invalid_certs(true)
}

// reqwest::ClientBuilder::danger_accept_invalid_hostnames — hostname verification off.
fn reqwest_invalid_hostnames() -> reqwest::ClientBuilder {
    reqwest::Client::builder().danger_accept_invalid_hostnames(true)
}

// rustls::ClientConfig::dangerous — custom certificate verifier on a built config.
fn rustls_client_config_dangerous(cfg: &mut rustls::ClientConfig) {
    let _ = cfg.dangerous();
}

// rustls::ConfigBuilder::dangerous — custom certificate verifier from the builder.
fn rustls_config_builder_dangerous(builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>) {
    let _ = builder.dangerous();
}
