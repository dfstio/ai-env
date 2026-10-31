//! The relay's certificates (WM-R59, WM-R60; X-2, LD-WM17): an ECDSA P-256 CA and leaf, signed with
//! ECDSA-SHA256 through aws-lc-rs and written by the small DER writer below; and the workers' client
//! certificates under that CA (R-117, R-118): each worker's own P-256 key, its point as `p256:` text, and the
//! certificate the deployer issues for it. Always built: M issues them (`ai-env relay tls`, `ai-env relay
//! allow --tls-key`), and no OpenSSL runs at use time.

use std::fmt;
use std::net::Ipv4Addr;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ParsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING};
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
/// id-kp-clientAuth (1.3.6.1.5.5.7.3.2), the DER of the OID's contents: the one extended key usage of a
/// worker's client certificate (R-117).
pub const OID_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// A P-256 point uncompressed: `0x04`, then x and y.
const POINT_LEN: usize = 65;
/// A client point's text prefix (R-118).
const POINT_PREFIX: &str = "p256:";
/// `p256:` and the 88 characters of the point's base64.
const POINT_TEXT_LEN: usize = 93;

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

/// A worker's public point for its client certificate (R-118): P-256, 65 bytes uncompressed (`0x04` first),
/// on the curve. Its text is `p256:` and the standard base64 (with padding) of the 65 bytes, 93 characters,
/// as `tls-keygen` prints it and `ai-env relay allow --tls-key` takes it. Public: `Debug` shows a fingerprint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClientPoint([u8; POINT_LEN]);

impl ClientPoint {
    /// Exactly `p256:` and the standard base64 (with padding) of 65 bytes, 93 characters, that are a point on
    /// P-256; anything else is `CertError::Point`.
    pub fn parse_text(s: &str) -> Result<ClientPoint, CertError> {
        let b64 = s.strip_prefix(POINT_PREFIX).filter(|_| s.len() == POINT_TEXT_LEN).ok_or(CertError::Point)?;
        let bytes = STANDARD.decode(b64).map_err(|_| CertError::Point)?;
        ClientPoint::of_bytes(&bytes)
    }

    /// 65 bytes, `0x04` first, that aws-lc-rs reads as a point on P-256 (it refuses one off the curve).
    fn of_bytes(bytes: &[u8]) -> Result<ClientPoint, CertError> {
        let point = <[u8; POINT_LEN]>::try_from(bytes).map_err(|_| CertError::Point)?;
        if point[0] != 0x04 {
            return Err(CertError::Point);
        }
        ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).map_err(|_| CertError::Point)?;
        Ok(ClientPoint(point))
    }

    /// `p256:<base64 of the 65 bytes>`, 93 characters.
    pub fn text(&self) -> String {
        format!("{POINT_PREFIX}{}", STANDARD.encode(self.0))
    }

    /// The 65 bytes.
    pub fn bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

impl fmt::Debug for ClientPoint {
    /// `ClientPoint(fp <fp>)`: the first 16 hex of SHA-256 of the 65 bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientPoint(fp {})", crate::keys::sha256_hex16(&self.0))
    }
}

/// A fresh P-256 key pair for a worker's client certificate (R-117, design D1: the worker's own TLS key, never
/// its Ed25519 worker key): PKCS#8 v1 DER, zeroized when dropped.
pub fn client_key() -> Result<Zeroizing<Vec<u8>>, CertError> {
    let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).map_err(|_| CertError::Key)?;
    let key = pair.to_pkcs8v1().map_err(|_| CertError::Key)?;
    Ok(Zeroizing::new(key.as_ref().to_vec()))
}

/// The public point of a P-256 key: exactly one PKCS#8 DER element (aws-lc would ignore bytes after it), else
/// `CertError::Key`.
pub fn client_point(key_pkcs8: &[u8]) -> Result<ClientPoint, CertError> {
    if !matches!(expect(key_pkcs8, SEQUENCE), Ok((_, rest)) if rest.is_empty()) {
        return Err(CertError::Key);
    }
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_pkcs8).map_err(|_| CertError::Key)?;
    ClientPoint::of_bytes(pair.public_key().as_ref())
}

/// A worker's client certificate (R-117), its DER: `point`'s certificate signed by `ca` with ECDSA-SHA256.
/// Subject CN `worker_id` (the caller passes an id, WM-R1); issuer the CA's subject; `basicConstraints`
/// CA:FALSE and `keyUsage` digitalSignature, both critical; `extendedKeyUsage` clientAuth alone; the point's
/// subject key id and the CA's as the authority key id (RFC 7093's method, as `relay_leaf`); no SAN; a random
/// positive serial; valid from an hour before `now_unix` to `not_after_unix` (`CertError::Validity` when that
/// is not after `now_unix`).
pub fn client_leaf(ca: &Issued, worker_id: &str, point: &ClientPoint, now_unix: u64, not_after_unix: u64) -> Result<Vec<u8>, CertError> {
    if not_after_unix <= now_unix {
        return Err(CertError::Validity);
    }
    let ca_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &ca.key_pkcs8).map_err(|_| CertError::Key)?;
    let parts = parse_certificate(&ca.cert_der)?;
    if parts.point != ca_pair.public_key().as_ref() {
        return Err(CertError::Mismatch);
    }
    let extensions = [
        extension(OID_BASIC_CONSTRAINTS, true, &der(SEQUENCE, &[])),
        // digitalSignature (bit 0): seven unused bits.
        extension(OID_KEY_USAGE, true, &der(BIT_STRING, &[0x07, 0x80])),
        extension(OID_EXT_KEY_USAGE, false, &der(SEQUENCE, &der(OID, OID_CLIENT_AUTH))),
        extension(OID_SUBJECT_KEY_ID, false, &der(OCTET_STRING, &key_id(point.bytes()))),
        extension(OID_AUTHORITY_KEY_ID, false, &der(SEQUENCE, &der(KEY_ID, &key_id(&parts.point)))),
    ];
    let tbs = tbs_between(&parts.subject, now_unix.saturating_sub(BACKDATE_S), not_after_unix, &common_name(worker_id), point.bytes(), &extensions)?;
    signed(&ca_pair, tbs)
}

/// The 64 lowercase hex characters of SHA-256 of a certificate's DER: a whitelist entry's `tls_fp` (R-117,
/// R-123). `fingerprint` is its first 16, the form every message and row shows.
pub fn tls_fp(cert_der: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert_der).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// The public key's bits of a certificate (an EC point, for the certificates of this module), for
/// `RelayEndpoint::client_identity`'s match of a key with its certificate (R-120).
#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
pub(crate) fn certificate_point(cert_der: &[u8]) -> Result<Vec<u8>, CertError> {
    Ok(parse_certificate(cert_der)?.point)
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
    /// Not a P-256 public point, or not its `p256:` text (R-118).
    #[error("not a P-256 public point")]
    Point,
    /// A client certificate's `not_after` that is not after its `now` (R-117).
    #[error("the certificate would end before it starts")]
    Validity,
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
    let not_after = now_unix.checked_add(u64::from(days) * DAY_S).ok_or(CertError::Sign)?;
    tbs_between(issuer, now_unix.saturating_sub(BACKDATE_S), not_after, subject, point, extensions)
}

/// A v3 TBSCertificate: a random positive serial, ECDSA-SHA256, valid from `not_before` to `not_after`, a P-256 key.
fn tbs_between(issuer: &[u8], not_before: u64, not_after: u64, subject: &[u8], point: &[u8], extensions: &[Vec<u8>]) -> Result<Vec<u8>, CertError> {
    let mut serial = [0u8; 16];
    aws_lc_rs::rand::fill(&mut serial).map_err(|_| CertError::Sign)?;
    // Positive, and minimal: the first byte is neither 0 nor above 0x7f.
    serial[0] = (serial[0] & 0x7f) | 0x40;
    let validity = der(SEQUENCE, &[time(not_before), time(not_after)].concat());
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

    /// One DER element of `input` whole (its tag and length too), and the rest.
    fn whole(input: &[u8]) -> (&[u8], &[u8]) {
        let (_, _, rest) = element(input).expect("an element");
        (&input[..input.len() - rest.len()], rest)
    }

    /// What this module writes into a certificate, read back.
    struct Fields {
        serial: Vec<u8>,
        issuer: Vec<u8>,
        validity: Vec<u8>,
        subject: Vec<u8>,
        /// Each extension's OID, criticality and value.
        extensions: Vec<(Vec<u8>, bool, Vec<u8>)>,
        tbs: Vec<u8>,
        signature: Vec<u8>,
    }

    fn fields(cert_der: &[u8]) -> Fields {
        let (cert, _) = expect(cert_der, SEQUENCE).expect("a certificate");
        let (tbs_whole, rest) = whole(cert);
        let (_algorithm, rest) = expect(rest, SEQUENCE).expect("its algorithm");
        let (bits, _) = expect(rest, BIT_STRING).expect("its signature");
        let (tbs, _) = expect(tbs_whole, SEQUENCE).expect("a TBSCertificate");
        let (_version, rest) = expect(tbs, EXPLICIT_0).expect("v3");
        let (serial, rest) = expect(rest, INTEGER).expect("a serial");
        let (_algorithm, rest) = expect(rest, SEQUENCE).expect("an algorithm");
        let (issuer, rest) = whole(rest);
        let (validity, rest) = expect(rest, SEQUENCE).expect("a validity");
        let (subject, rest) = whole(rest);
        let (_spki, rest) = expect(rest, SEQUENCE).expect("a key");
        let (outer, _) = expect(rest, EXPLICIT_3).expect("extensions");
        let (mut list, _) = expect(outer, SEQUENCE).expect("a list");
        let mut extensions = Vec::new();
        while !list.is_empty() {
            let (ext, rest) = expect(list, SEQUENCE).expect("an extension");
            let (oid, mut body) = expect(ext, OID).expect("its OID");
            let mut critical = false;
            if body.first() == Some(&BOOLEAN) {
                let (flag, after) = expect(body, BOOLEAN).expect("its criticality");
                critical = flag == [0xff];
                body = after;
            }
            let (value, _) = expect(body, OCTET_STRING).expect("its value");
            extensions.push((oid.to_vec(), critical, value.to_vec()));
            list = rest;
        }
        let signature = bits.split_first().expect("no unused bits").1.to_vec();
        Fields { serial: serial.to_vec(), issuer: issuer.to_vec(), validity: validity.to_vec(), subject: subject.to_vec(), extensions, tbs: tbs_whole.to_vec(), signature }
    }

    /// WM-T54.
    #[test]
    fn client_leafs_carry_the_client_profile() {
        let ca = relay_ca(NOW).expect("a CA");
        let key = client_key().expect("a key");
        let point = client_point(&key).expect("its point");
        let until = NOW + 30 * DAY_S;
        let leaf = client_leaf(&ca, "worker-a", &point, NOW, until).expect("a client leaf");
        let (ca_fields, f) = (fields(&ca.cert_der), fields(&leaf));
        assert_eq!(f.subject, common_name("worker-a"), "CN is the worker id");
        assert_eq!(f.issuer, ca_fields.subject, "the issuer is the CA's subject");
        assert_eq!(f.validity, [time(NOW - BACKDATE_S), time(until)].concat(), "from an hour before now to not_after");
        let ca_ski = ca_fields.extensions.iter().find(|(oid, ..)| oid == OID_SUBJECT_KEY_ID).map(|(_, _, value)| expect(value, OCTET_STRING).expect("a key id").0.to_vec());
        let ca_ski = ca_ski.expect("the CA's subject key id");
        let want = vec![
            (OID_BASIC_CONSTRAINTS.to_vec(), true, der(SEQUENCE, &[])),
            (OID_KEY_USAGE.to_vec(), true, der(BIT_STRING, &[0x07, 0x80])),
            (OID_EXT_KEY_USAGE.to_vec(), false, der(SEQUENCE, &der(OID, OID_CLIENT_AUTH))),
            (OID_SUBJECT_KEY_ID.to_vec(), false, der(OCTET_STRING, &key_id(point.bytes()))),
            (OID_AUTHORITY_KEY_ID.to_vec(), false, der(SEQUENCE, &der(KEY_ID, &ca_ski))),
        ];
        assert_eq!(f.extensions, want, "CA:FALSE and digitalSignature (critical), clientAuth alone, its key id, the CA's as its authority's, no SAN");
        let has = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        assert!(!has(&leaf, OID_SERVER_AUTH) && !has(&leaf, OID_SUBJECT_ALT_NAME), "no serverAuth, no SAN");
        assert_eq!(parse_certificate(&leaf).expect("parses").point, point.bytes(), "the worker's own point");
        let ca_point = parse_certificate(&ca.cert_der).expect("parses").point;
        assert!(aws_lc_rs::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &ca_point).verify(&f.tbs, &f.signature).is_ok(), "ECDSA-SHA256 by the CA");
        assert!(f.serial.len() == 16 && (0x40..=0x7f).contains(&f.serial[0]), "a positive serial");
        let again = client_leaf(&ca, "worker-a", &point, NOW, until).expect("again");
        assert_ne!(fields(&again).serial, f.serial, "a random serial");

        let fp = tls_fp(&leaf);
        assert!(fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{fp}");
        assert_eq!(fp[..16], fingerprint(&leaf));

        // The point's text round-trips its 93 characters; nothing else is a point.
        let text = point.text();
        assert!(text.len() == 93 && text.starts_with("p256:"), "{text}");
        assert_eq!(ClientPoint::parse_text(&text), Ok(point));
        assert_eq!(point.bytes()[0], 0x04);
        assert_eq!(format!("{point:?}"), format!("ClientPoint(fp {})", crate::keys::sha256_hex16(point.bytes())));
        let b64 = |bytes: &[u8]| format!("p256:{}", STANDARD.encode(bytes));
        let mut origin = [0u8; 65];
        origin[0] = 0x04;
        let mut flipped = *point.bytes();
        flipped[64] ^= 0x01;
        let mut tagged = *point.bytes();
        tagged[0] = 0x05;
        let mut compressed = point.bytes()[..33].to_vec();
        compressed[0] = 0x02 | (point.bytes()[64] & 1);
        let refused = [
            b64(&origin),
            b64(&flipped),
            b64(&point.bytes()[..64]),
            b64(&tagged),
            b64(&compressed),
            text.replacen("p256:", "P256:", 1),
            text.replacen("p256:", "ed25519:", 1),
            text.trim_end_matches('=').to_string(),
            format!("{text}AAAA"),
            format!(" {text}"),
            String::new(),
        ];
        for bad in refused {
            assert_eq!(ClientPoint::parse_text(&bad), Err(CertError::Point), "{bad:?}");
        }
        assert_eq!(b64(&point.bytes()[..64]).len(), 93, "the 64-byte point's text is as long as a point's");
        assert_eq!(CertError::Point.to_string(), "not a P-256 public point");

        assert_eq!(client_leaf(&ca, "worker-a", &point, NOW, NOW), Err(CertError::Validity));
        assert_eq!(client_leaf(&ca, "worker-a", &point, NOW, NOW - 1), Err(CertError::Validity));
        assert_eq!(CertError::Validity.to_string(), "the certificate would end before it starts");
        let other = relay_ca(NOW).expect("another CA");
        let swapped = Issued { cert_der: ca.cert_der.clone(), key_pkcs8: Zeroizing::new(other.key_pkcs8.to_vec()) };
        assert_eq!(client_leaf(&swapped, "worker-a", &point, NOW, until), Err(CertError::Mismatch));
        assert_eq!(client_point(b"not DER"), Err(CertError::Key));
        let mut longer = key.to_vec();
        longer.push(0);
        assert_eq!(client_point(&longer), Err(CertError::Key), "a byte after the key");
        let ed25519 = crate::keys::SigningKey::from_seed(&[3; 32]).expect("seed").to_pkcs8_der().expect("DER");
        assert_eq!(client_point(&ed25519), Err(CertError::Key), "an Ed25519 key");
        assert_ne!(client_point(&client_key().expect("a key")).expect("a point"), point, "a fresh key each time");

        // The relay's verifier of client certificates takes it under the CA, and nothing else (TLS 17's).
        #[cfg(feature = "runtime")]
        {
            use rustls::pki_types::{CertificateDer, UnixTime};
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(ca.cert_der.clone())).expect("the CA as a root");
            let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(std::sync::Arc::new(roots), provider).build().expect("a verifier");
            let at = |unix: u64| UnixTime::since_unix_epoch(std::time::Duration::from_secs(unix));
            let verify = |der: &[u8], unix: u64| verifier.verify_client_cert(&CertificateDer::from(der.to_vec()), &[], at(unix)).is_ok();
            assert!(verify(&leaf, NOW), "a client certificate under the CA");
            assert!(verify(&leaf, until), "until its not_after");
            assert!(!verify(&leaf, until + 1), "not after it");
            let server = relay_leaf(&ca, Ipv4Addr::new(192, 0, 2, 20), NOW).expect("the relay's leaf");
            assert!(!verify(&server.cert_der, NOW), "serverAuth alone is no client certificate");
            let foreign = client_leaf(&other, "worker-a", &point, NOW, until).expect("under another CA");
            assert!(!verify(&foreign, NOW), "another CA's");
        }
    }
}
