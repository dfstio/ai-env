//! One TLS client policy for everything the Mac dials (the MicroVM endpoint
//! over WebSocket and HTTPS, and the AWS SDK's own client): TLS 1.3 only,
//! Amazon Root CA 1–4 as the only trust anchors, aws-lc-rs as the only crypto
//! provider, and proxy environment variables ignored. Nothing else in the
//! crate may build a `ClientConfig` or touch `aws_smithy_http_client`
//! (`make lint` greps for both).
use aws_sdk_lambdamicrovms::config::SharedHttpClient;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use std::sync::{Arc, OnceLock};

/// Embedded roots (from https://www.amazontrust.com/repository/, verified
/// against webpki-roots by `tls_roots_match_webpki`).
pub const AMAZON_ROOT_CA_PEMS: [&str; 4] = [
    include_str!("../../certs/AmazonRootCA1.pem"),
    include_str!("../../certs/AmazonRootCA2.pem"),
    include_str!("../../certs/AmazonRootCA3.pem"),
    include_str!("../../certs/AmazonRootCA4.pem"),
];

/// TLS 1.3 floor — the endpoint negotiates it; 1.2 is never offered.
pub const PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

fn pem_to_der(pem: &str) -> CertificateDer<'static> {
    use base64::Engine;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).expect("embedded PEM is valid base64");
    CertificateDer::from(der)
}

#[must_use]
pub fn amazon_roots() -> Vec<CertificateDer<'static>> {
    AMAZON_ROOT_CA_PEMS.iter().map(|p| pem_to_der(p)).collect()
}

#[must_use]
pub fn root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    for der in amazon_roots() {
        store.add(der).expect("embedded Amazon root certificate parses");
    }
    store
}

/// aws-lc-rs, installed once as the process default (shared with reqwest and
/// the SDK); there is deliberately no `ring` in the dependency graph.
#[must_use]
pub fn crypto_provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            // Ignore the error: another component may have installed the same provider first.
            let _ = CryptoProvider::install_default((*provider).clone());
            provider
        })
        .clone()
}

/// The one client configuration.
#[must_use]
pub fn client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let cfg = ClientConfig::builder_with_provider(crypto_provider())
                .with_protocol_versions(PROTOCOL_VERSIONS)
                .expect("aws-lc-rs supports TLS 1.3")
                .with_root_certificates(root_store())
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}

/// The connector every WebSocket dial must pass (never the plain variant).
#[must_use]
pub fn ws_connector() -> tokio_tungstenite::Connector {
    tokio_tungstenite::Connector::Rustls(client_config())
}

/// HTTPS client for `/health` and similar side channels: same TLS policy,
/// proxy environment ignored.
pub fn reqwest_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder().use_preconfigured_tls((*client_config()).clone()).no_proxy().build()
}

/// The AWS SDK's HTTP client under the same policy, for `api::sdk_config()`:
/// rustls on aws-lc-rs, a trust store that starts EMPTY (never the platform
/// store) and holds only the four embedded Amazon roots, and the proxy
/// configuration pinned to disabled. The SDK's own default client
/// (`aws-smithy-runtime`'s `default-https-client`) would instead load the
/// native roots and honour `HTTPS_PROXY`/`NO_PROXY`.
///
/// Documented exception to the policy: the TLS 1.3-only floor of the
/// WebSocket/reqwest path is not reachable through this API — the crate
/// builds the rustls `ClientConfig` itself with its safe default versions
/// (1.2 + 1.3), so the control plane negotiates whatever the AWS endpoint
/// selects (1.3). `PROTOCOL_VERSIONS` does not apply here.
#[must_use]
pub fn sdk_http_client() -> SharedHttpClient {
    use aws_smithy_http_client::proxy::ProxyConfig;
    use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
    use aws_smithy_http_client::tls::{Provider, TlsContext, TrustStore};
    use aws_smithy_http_client::{Builder, Connector};

    // Same aws-lc-rs process default as the WS/reqwest path (idempotent).
    let _ = crypto_provider();
    let mut trust = TrustStore::empty();
    for pem in AMAZON_ROOT_CA_PEMS {
        trust.add_pem_certificate(pem.as_bytes());
    }
    let context = TlsContext::builder().with_trust_store(trust).build().expect("a TLS context from PEM bytes cannot fail to build");
    // `Builder::build_https` has no proxy setter and the SDK's default path installs
    // `ProxyConfig::from_env()`; the connector-fn form is the one that takes an explicit
    // `ProxyConfig` while still honouring the SDK's connect/read timeouts and sleep impl.
    Builder::new().build_with_connector_fn(move |settings, components| {
        let mut builder = Connector::builder().proxy_config(ProxyConfig::disabled());
        builder.set_connector_settings(settings.cloned());
        if let Some(components) = components {
            builder.set_sleep_impl(components.sleep_impl());
        }
        builder.tls_provider(Provider::Rustls(CryptoMode::AwsLc)).tls_context(context.clone()).build()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_roots_parse() {
        assert_eq!(amazon_roots().len(), 4);
        assert_eq!(root_store().roots.len(), 4);
    }

    #[test]
    fn tls_roots_match_webpki() {
        let ours = root_store();
        for (i, anchor) in ours.roots.iter().enumerate() {
            let hit = webpki_roots::TLS_SERVER_ROOTS.iter().find(|w| {
                w.subject_public_key_info.as_ref() == anchor.subject_public_key_info.as_ref()
                    && w.subject.as_ref() == anchor.subject.as_ref()
            });
            assert!(hit.is_some(), "embedded root {} is not in webpki-roots", i + 1);
            let label = format!("Amazon Root CA {}", i + 1);
            let subject = anchor.subject.as_ref();
            assert!(
                subject.windows(label.len()).any(|w| w == label.as_bytes()),
                "root {} subject does not contain {label:?}",
                i + 1
            );
        }
    }

    #[test]
    fn tls_versions_are_tls13_only() {
        assert_eq!(PROTOCOL_VERSIONS.len(), 1);
        assert_eq!(PROTOCOL_VERSIONS[0].version, rustls::ProtocolVersion::TLSv1_3);
        let _ = client_config();
    }

    #[test]
    fn reqwest_client_builds() {
        assert!(reqwest_client().is_ok());
    }

    #[test]
    fn sdk_http_client_builds_and_is_accepted_by_the_sdk() {
        use aws_sdk_lambdamicrovms::config::{HttpClient, Region};
        let client = sdk_http_client();
        // The type does not expose the TLS provider; the metadata does say it is the
        // smithy hyper-1 client (the rustls provider is the only TLS feature we enable on it).
        let meta = client.connector_metadata().expect("hyper client reports metadata");
        assert_eq!(meta.name(), "hyper");
        assert_eq!(meta.version().as_deref(), Some("1.x"));
        // `Client::from_conf` validates the base config, which builds the connector once:
        // that is where the embedded PEMs are parsed into the rustls root store (a bad
        // PEM panics here). Offline: nothing is dialed.
        let conf = aws_sdk_lambdamicrovms::Config::builder()
            .behavior_version_latest()
            .region(Region::new(crate::bridge::config::REGION))
            .http_client(client)
            .build();
        let _sdk = aws_sdk_lambdamicrovms::Client::from_conf(conf);
    }
}
