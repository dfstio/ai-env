//! The relay's certificates (WM-R59, WM-R60; X-2, LD-WM17): an ECDSA P-256 CA and leaf, signed with
//! ECDSA-SHA256 through aws-lc-rs and written by the small DER writer below. Always built: M issues them
//! (`ai-env relay tls`), and no OpenSSL runs at use time.

use std::fmt;
use std::net::Ipv4Addr;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

/// The CA's life, from `now_unix`.
pub const CA_DAYS: u32 = 3650;
/// The leaf's life, from `now_unix`.
pub const LEAF_DAYS: u32 = 397;
/// The leaf's DNS name: what workers verify (X-3).
pub const RELAY_DNS: &str = "ai-env-relay";

/// The CA's common name.
const CA_CN: &str = "ai-env relay CA";
/// Both certificates start an hour before `now_unix`, for clocks a little behind the issuer's.
const BACKDATE_S: u64 = 3600;
const DAY_S: u64 = 86_400;

// The DER tags this writer uses.
const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const UTF8_STRING: u8 = 0x0c;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const EXPLICIT_0: u8 = 0xa0;
const EXPLICIT_3: u8 = 0xa3;
const KEY_ID: u8 = 0x80;
const DNS_NAME: u8 = 0x82;
const IP_ADDRESS: u8 = 0x87;

// The object identifiers' contents (DER), by their names in RFC 5280, RFC 5480 and RFC 5758.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // id-ecPublicKey
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // prime256v1
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]; // ecdsa-with-SHA256
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03]; // id-at-commonName
const OID_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e]; // id-ce-subjectKeyIdentifier
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f]; // id-ce-keyUsage
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11]; // id-ce-subjectAltName
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13]; // id-ce-basicConstraints
const OID_AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23]; // id-ce-authorityKeyIdentifier
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25]; // id-ce-extKeyUsage
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]; // id-kp-serverAuth

/// A certificate and its key (PKCS#8 v1 DER, zeroized when dropped). No `Clone`.
pub struct Issued {
    /// The certificate's DER.
    pub cert_der: Vec<u8>,
    /// The private key's PKCS#8 DER.
    pub key_pkcs8: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Issued {
    /// `Issued(fp <fp>)`: the certificate's fingerprint, never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Issued(fp {})", fingerprint(&self.cert_der))
    }
}

/// CN=ai-env relay CA, basicConstraints CA:TRUE pathlen:0, keyUsage keyCertSign and cRLSign, CA_DAYS from `now_unix`.
pub fn relay_ca(now_unix: u64) -> Result<Issued, CertError> {
    let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).map_err(|_| CertError::Key)?;
    let point = pair.public_key().as_ref();
    let name = common_name(CA_CN);
    let extensions = [
        extension(OID_BASIC_CONSTRAINTS, true, &der(SEQUENCE, &[der(BOOLEAN, &[0xff]), der(INTEGER, &[0x00])].concat())),
        // keyCertSign (bit 5) and cRLSign (bit 6): one unused bit.
        extension(OID_KEY_USAGE, true, &der(BIT_STRING, &[0x01, 0x06])),
        extension(OID_SUBJECT_KEY_ID, false, &der(OCTET_STRING, &key_id(point))),
    ];
    let tbs = tbs_certificate(&name, now_unix, CA_DAYS, &name, point, &extensions)?;
    let cert_der = signed(&pair, tbs)?;
    let key = pair.to_pkcs8v1().map_err(|_| CertError::Key)?;
    Ok(Issued { cert_der, key_pkcs8: Zeroizing::new(key.as_ref().to_vec()) })
}

/// CN=ai-env-relay, SANs exactly DNS RELAY_DNS and IP `ip`, extendedKeyUsage serverAuth, CA:FALSE, LEAF_DAYS, signed by `ca`.
pub fn relay_leaf(ca: &Issued, ip: Ipv4Addr, now_unix: u64) -> Result<Issued, CertError> {
    let ca_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &ca.key_pkcs8).map_err(|_| CertError::Key)?;
    let parts = parse_certificate(&ca.cert_der)?;
    if parts.point != ca_pair.public_key().as_ref() {
        return Err(CertError::Mismatch);
    }
    let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).map_err(|_| CertError::Key)?;
    let point = pair.public_key().as_ref();
    let names = [der(DNS_NAME, RELAY_DNS.as_bytes()), der(IP_ADDRESS, &ip.octets())].concat();
    let extensions = [
        extension(OID_BASIC_CONSTRAINTS, true, &der(SEQUENCE, &[])),
        // digitalSignature (bit 0): seven unused bits.
        extension(OID_KEY_USAGE, true, &der(BIT_STRING, &[0x07, 0x80])),
        extension(OID_EXT_KEY_USAGE, false, &der(SEQUENCE, &der(OID, OID_SERVER_AUTH))),
        extension(OID_SUBJECT_ALT_NAME, false, &der(SEQUENCE, &names)),
        extension(OID_SUBJECT_KEY_ID, false, &der(OCTET_STRING, &key_id(point))),
        extension(OID_AUTHORITY_KEY_ID, false, &der(SEQUENCE, &der(KEY_ID, &key_id(&parts.point)))),
    ];
    let tbs = tbs_certificate(&parts.subject, now_unix, LEAF_DAYS, &common_name(RELAY_DNS), point, &extensions)?;
    let cert_der = signed(&ca_pair, tbs)?;
    let key = pair.to_pkcs8v1().map_err(|_| CertError::Key)?;
    Ok(Issued { cert_der, key_pkcs8: Zeroizing::new(key.as_ref().to_vec()) })
}

/// `ca` again from its sealed key and its certificate; refused when the key does not match the certificate.
pub fn ca_from_parts(cert_der: &[u8], key_pkcs8: &[u8]) -> Result<Issued, CertError> {
    let parts = parse_certificate(cert_der)?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_pkcs8).map_err(|_| CertError::Key)?;
    if parts.point != pair.public_key().as_ref() {
        return Err(CertError::Mismatch);
    }
    Ok(Issued { cert_der: cert_der.to_vec(), key_pkcs8: Zeroizing::new(key_pkcs8.to_vec()) })
}

/// One PEM block ("CERTIFICATE" or "PRIVATE KEY"), 64-character lines.
pub fn pem(label: &str, der: &[u8]) -> String {
    let mut out = String::with_capacity(pem_len(label, der));
    pem_into(label, der, &mut out);
    out
}

/// `pem` into zeroizing memory sized up front, so no copy of a key's text is left behind (keys::to_pkcs8_pem).
pub(crate) fn pem_zeroizing(label: &str, der: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(pem_len(label, der)));
    pem_into(label, der, &mut out);
    out
}

fn pem_len(label: &str, der: &[u8]) -> usize {
    let b64 = der.len().div_ceil(3) * 4;
    2 * label.len() + 32 + b64 + b64.div_ceil(64)
}

fn pem_into(label: &str, der: &[u8], out: &mut String) {
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for piece in der.chunks(48) {
        STANDARD.encode_string(piece, out);
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
}

/// The first 16 lowercase hex characters of SHA-256 of a certificate's DER.
pub fn fingerprint(cert_der: &[u8]) -> String {
    crate::keys::sha256_hex16(cert_der)
}

/// A certificate not made or not read; it never holds key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    /// A key could not be made or read.
    #[error("the key could not be made or read")]
    Key,
    /// The certificate could not be signed.
    #[error("the certificate could not be signed")]
    Sign,
    /// Not a certificate this module can read.
    #[error("not a certificate this writer reads")]
    Parse,
    /// The key does not match the certificate.
    #[error("the key does not match the certificate")]
    Mismatch,
}

/// A DER element: `tag`, its length, `content`.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// A Name of one common name.
fn common_name(cn: &str) -> Vec<u8> {
    let atv = der(SEQUENCE, &[der(OID, OID_COMMON_NAME), der(UTF8_STRING, cn.as_bytes())].concat());
    der(SEQUENCE, &der(SET, &atv))
}

/// One extension.
fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut content = der(OID, oid);
    if critical {
        content.extend(der(BOOLEAN, &[0xff]));
    }
    content.extend(der(OCTET_STRING, value));
    der(SEQUENCE, &content)
}

/// RFC 7093's first method: SHA-256 of the key's bits, cut to 160 bits.
fn key_id(point: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, point).as_ref()[..20].to_vec()
}

/// A v3 TBSCertificate: a random positive serial, ECDSA-SHA256, `now_unix` less an hour to `now_unix` plus
/// `days`, a P-256 key.
fn tbs_certificate(issuer: &[u8], now_unix: u64, days: u32, subject: &[u8], point: &[u8], extensions: &[Vec<u8>]) -> Result<Vec<u8>, CertError> {
    let mut serial = [0u8; 16];
    aws_lc_rs::rand::fill(&mut serial).map_err(|_| CertError::Sign)?;
    // Positive, and minimal: the first byte is neither 0 nor above 0x7f.
    serial[0] = (serial[0] & 0x7f) | 0x40;
    let not_after = now_unix.checked_add(u64::from(days) * DAY_S).ok_or(CertError::Sign)?;
    let validity = der(SEQUENCE, &[time(now_unix.saturating_sub(BACKDATE_S)), time(not_after)].concat());
    let algorithm = der(SEQUENCE, &[der(OID, OID_EC_PUBLIC_KEY), der(OID, OID_P256)].concat());
    let spki = der(SEQUENCE, &[algorithm, der(BIT_STRING, &[&[0u8][..], point].concat())].concat());
    let parts = [
        der(EXPLICIT_0, &der(INTEGER, &[0x02])),
        der(INTEGER, &serial),
        signature_algorithm(),
        issuer.to_vec(),
        validity,
        subject.to_vec(),
        spki,
        der(EXPLICIT_3, &der(SEQUENCE, &extensions.concat())),
    ];
    Ok(der(SEQUENCE, &parts.concat()))
}

fn signature_algorithm() -> Vec<u8> {
    der(SEQUENCE, &der(OID, OID_ECDSA_SHA256))
}

/// The Certificate: `tbs`, ECDSA-SHA256, `pair`'s signature of `tbs`.
fn signed(pair: &EcdsaKeyPair, tbs: Vec<u8>) -> Result<Vec<u8>, CertError> {
    let sig = pair.sign(&SystemRandom::new(), &tbs).map_err(|_| CertError::Sign)?;
    let bits = [&[0u8][..], sig.as_ref()].concat();
    Ok(der(SEQUENCE, &[tbs, signature_algorithm(), der(BIT_STRING, &bits)].concat()))
}

/// UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280's rule for a certificate's validity).
fn time(unix: u64) -> Vec<u8> {
    let days = i64::try_from(unix / DAY_S).unwrap_or(i64::MAX / 2);
    let (y, m, d) = crate::policy::civil_from_days(days);
    let secs = unix % DAY_S;
    let (hh, mm, ss) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if (1950..2050).contains(&y) {
        der(UTC_TIME, format!("{:02}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z", y % 100).as_bytes())
    } else {
        der(GENERALIZED_TIME, format!("{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z").as_bytes())
    }
}

/// What `relay_leaf` and `ca_from_parts` need of a certificate: its subject Name (the whole element) and its
/// public key's point.
struct Parts {
    subject: Vec<u8>,
    point: Vec<u8>,
}

/// One DER element of `input`: its tag, content and the rest.
fn element(input: &[u8]) -> Result<(u8, &[u8], &[u8]), CertError> {
    let (&tag, rest) = input.split_first().ok_or(CertError::Parse)?;
    let (&first, rest) = rest.split_first().ok_or(CertError::Parse)?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return Err(CertError::Parse);
        }
        (rest[..n].iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b)), &rest[n..])
    };
    if rest.len() < len {
        return Err(CertError::Parse);
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

/// The element of `input` with tag `want`, and the rest.
fn expect(input: &[u8], want: u8) -> Result<(&[u8], &[u8]), CertError> {
    match element(input)? {
        (tag, content, rest) if tag == want => Ok((content, rest)),
        _ => Err(CertError::Parse),
    }
}

fn parse_certificate(cert_der: &[u8]) -> Result<Parts, CertError> {
    let (cert, rest) = expect(cert_der, SEQUENCE)?;
    if !rest.is_empty() {
        return Err(CertError::Parse);
    }
    let (tbs, _) = expect(cert, SEQUENCE)?;
    let mut rest = tbs;
    if rest.first() == Some(&EXPLICIT_0) {
        rest = expect(rest, EXPLICIT_0)?.1;
    }
    let (_serial, rest) = expect(rest, INTEGER)?;
    let (_algorithm, rest) = expect(rest, SEQUENCE)?;
    let (_issuer, rest) = expect(rest, SEQUENCE)?;
    let (_validity, rest) = expect(rest, SEQUENCE)?;
    let (_, after_subject) = expect(rest, SEQUENCE)?;
    let subject = rest[..rest.len() - after_subject.len()].to_vec();
    let (spki, _) = expect(after_subject, SEQUENCE)?;
    let (_algorithm, rest) = expect(spki, SEQUENCE)?;
    let (bits, _) = expect(rest, BIT_STRING)?;
    match bits.split_first() {
        Some((0, point)) if !point.is_empty() => Ok(Parts { subject, point: point.to_vec() }),
        _ => Err(CertError::Parse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn the_ca_and_its_leaf_carry_the_relay_profile() {
        let ca = relay_ca(NOW).expect("a CA");
        let leaf = relay_leaf(&ca, Ipv4Addr::new(10, 42, 0, 20), NOW).expect("a leaf");
        let ca_parts = parse_certificate(&ca.cert_der).expect("parses");
        let leaf_parts = parse_certificate(&leaf.cert_der).expect("parses");
        assert_eq!(ca_parts.subject, common_name(CA_CN));
        assert_eq!(leaf_parts.subject, common_name(RELAY_DNS));
        assert_eq!(ca_parts.point.len(), 65, "an uncompressed P-256 point");
        let has = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        assert!(has(&leaf.cert_der, &ca_parts.subject), "the leaf names its issuer");
        assert!(has(&leaf.cert_der, &der(IP_ADDRESS, &[10, 42, 0, 20])));
        assert!(has(&leaf.cert_der, &der(DNS_NAME, b"ai-env-relay")));
        assert!(has(&leaf.cert_der, OID_SERVER_AUTH));
        assert!(!has(&ca.cert_der, OID_SERVER_AUTH));
        // 1800000000 is 2027-01-15T08:00:00Z; the CA ends ten years later, both start an hour before.
        assert!(has(&ca.cert_der, b"270115070000Z"));
        assert!(has(&ca.cert_der, b"370112080000Z"));
        assert!(has(&leaf.cert_der, b"280216080000Z"), "397 days");
        assert_eq!(fingerprint(&ca.cert_der).len(), 16);
        assert_eq!(format!("{ca:?}"), format!("Issued(fp {})", fingerprint(&ca.cert_der)));

        let again = ca_from_parts(&ca.cert_der, &ca.key_pkcs8).expect("the same CA");
        assert_eq!(again.cert_der, ca.cert_der);
        assert!(relay_leaf(&again, Ipv4Addr::new(10, 42, 0, 20), NOW).is_ok());
        let other = relay_ca(NOW).expect("another CA");
        assert_eq!(ca_from_parts(&ca.cert_der, &other.key_pkcs8).expect_err("refused"), CertError::Mismatch);
        assert_eq!(ca_from_parts(b"not DER", &ca.key_pkcs8).expect_err("refused"), CertError::Parse);
        assert_eq!(ca_from_parts(&ca.cert_der, b"not a key").expect_err("refused"), CertError::Key);
        let swapped = Issued { cert_der: ca.cert_der.clone(), key_pkcs8: Zeroizing::new(other.key_pkcs8.to_vec()) };
        assert_eq!(relay_leaf(&swapped, Ipv4Addr::new(10, 42, 0, 20), NOW).expect_err("refused"), CertError::Mismatch);
    }

    #[test]
    fn pem_blocks_have_64_character_lines_and_dates_switch_to_generalized_time() {
        let der_bytes: Vec<u8> = (0u8..=200).collect();
        let text = pem("CERTIFICATE", &der_bytes);
        assert_eq!(text.len(), pem_len("CERTIFICATE", &der_bytes), "sized up front");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.first(), Some(&"-----BEGIN CERTIFICATE-----"));
        assert_eq!(lines.last(), Some(&"-----END CERTIFICATE-----"));
        assert!(lines[1..lines.len() - 2].iter().all(|l| l.len() == 64));
        let blocks = crate::keys::pem_blocks(text.as_bytes()).expect("reads back");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, "CERTIFICATE");
        assert_eq!(blocks[0].1.as_slice(), der_bytes.as_slice());
        assert_eq!(pem_zeroizing("PRIVATE KEY", &der_bytes).as_str(), pem("PRIVATE KEY", &der_bytes));
        // 2049-12-31T23:59:59Z, then 2050-01-01T00:00:00Z.
        assert_eq!(time(2_524_607_999), der(UTC_TIME, b"491231235959Z"));
        assert_eq!(time(2_524_608_000), der(GENERALIZED_TIME, b"20500101000000Z"));
        assert_eq!(der(OCTET_STRING, &[0u8; 200])[..3], [OCTET_STRING, 0x81, 200]);
        assert_eq!(der(OCTET_STRING, &[0u8; 300])[..4], [OCTET_STRING, 0x82, 0x01, 0x2c]);
    }
}
