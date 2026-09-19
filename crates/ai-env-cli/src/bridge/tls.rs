//! One TLS client policy for everything the Mac dials (the MicroVM endpoint
//! over WebSocket and HTTPS, later the AWS SDK's own client): TLS 1.3 only,
//! Amazon Root CA 1–4 as the only trust anchors, aws-lc-rs as the only crypto
//! provider, and proxy environment variables ignored. Nothing else in the
//! crate may build a `ClientConfig` (`make lint` greps for it).
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
}
