//! The one TLS configuration of the VM side (V-R20): TLS 1.3 only, the aws-lc-rs provider, the session's relay CA
//! the one trust anchor (no public root store, no `dangerous` verifier: the second configuration invariant 15's
//! amendment sanctions, WM-R11a), no client certificate, ALPN `h2`. Built here alone (`make lint`).
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// TLS 1.3 only, the aws-lc-rs provider, `ca_der` the one anchor, no client auth, ALPN `h2`. `Err` when `ca_der` is
/// no certificate a root store takes.
pub fn client_config(ca_der: &[u8]) -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec())).map_err(|e| format!("the relay CA is not a certificate: {e}"))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS 1.3 with aws-lc-rs: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// An IPv4 literal → `ServerName::IpAddress` (the leaf's IP SAN); a DNS name → `ServerName::DnsName`.
pub fn server_name(name: &str) -> Result<ServerName<'static>, String> {
    if let Ok(ip) = name.parse::<Ipv4Addr>() {
        return Ok(ServerName::IpAddress(IpAddr::V4(ip).into()));
    }
    match ServerName::try_from(name.to_string()) {
        Ok(n @ ServerName::DnsName(_)) => Ok(n),
        _ => Err("not an IPv4 address or a DNS name".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CA certificate made at run time by the OpenSSL 3 CLI (Homebrew's when present), DER.
    fn run_time_ca_der() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let brew = std::path::Path::new("/opt/homebrew/bin/openssl");
        let openssl = if brew.is_file() { brew.to_path_buf() } else { std::path::PathBuf::from("openssl") };
        let (key, der) = (dir.path().join("ca.key"), dir.path().join("ca.der"));
        let ok = |c: &mut std::process::Command| assert!(c.status().unwrap().success(), "{c:?}");
        ok(std::process::Command::new(&openssl).args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out"]).arg(&key));
        ok(std::process::Command::new(&openssl)
            .args(["req", "-x509", "-new", "-key"])
            .arg(&key)
            .args(["-subj", "/CN=ai-env relay test CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-outform", "DER", "-out"])
            .arg(&der));
        std::fs::read(&der).unwrap()
    }

    /// A run-time CA's DER gives a config whose ALPN is `h2` alone; a DER that is no certificate (`[0x30]`) is `Err`;
    /// an IPv4 literal is an IP name, a DNS name a DNS name, a blank refused. TLS 1.3 alone and the one anchor are
    /// behaviour: `tests/relay_client.rs` proves them against relays.
    #[test]
    fn the_tls_config_wants_h2_and_parses_server_names() {
        let config = client_config(&run_time_ca_der()).unwrap();
        assert_eq!(config.alpn_protocols, [b"h2".to_vec()]);
        assert!(client_config(&[0x30]).is_err());
        assert!(client_config(&[]).is_err());
        assert!(matches!(server_name("10.42.0.20").unwrap(), ServerName::IpAddress(_)));
        assert!(matches!(server_name("relay.internal.test").unwrap(), ServerName::DnsName(_)));
        assert!(server_name("bad name").is_err());
        assert!(server_name("::1").is_err(), "IPv4 or a DNS name only");
    }
}
