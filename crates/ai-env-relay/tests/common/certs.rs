//! The run-time CA of the relay's tests (LD-R23): a small DER writer for X.509 v3 certificates with Ed25519 keys
//! from aws-lc-rs, so no key or certificate is committed and no crate is added. Every key comes from a seed at run
//! time, and the PEM markers are assembled from parts, so no source file holds a private-key marker. The
//! production profile (ECDSA P-256) is W's `certs`; this one only has to satisfy rustls's verifier.
//!
//! Also compiled into the crate's unit tests (`src/lib.rs`, `#[path]`).
#![allow(dead_code)]

use std::time::{Duration, SystemTime};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

const ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
const CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
const KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0f];
const SUBJECT_ALT_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
const EXT_KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x25];
const SERVER_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(body);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn integer(n: u64) -> Vec<u8> {
    let mut b: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
    if b.is_empty() || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

fn bits(bytes: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0u8][..], bytes].concat())
}

fn name(cn: &str) -> Vec<u8> {
    seq(&[&tlv(0x31, &seq(&[CN, &tlv(0x0c, cn.as_bytes())]))])
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        seq(&[oid, &[0x01, 0x01, 0xff], &tlv(0x04, value)])
    } else {
        seq(&[oid, &tlv(0x04, value)])
    }
}

/// UTCTime (`YYMMDDHHMMSSZ`) of a time before 2050.
fn utc_time(t: SystemTime) -> Vec<u8> {
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let text = format!("{:02}{month:02}{day:02}{:02}{:02}{:02}Z", year % 100, rem / 3600, rem % 3600 / 60, rem % 60);
    tlv(0x17, text.as_bytes())
}

fn validity() -> Vec<u8> {
    let now = SystemTime::now();
    seq(&[&utc_time(now - Duration::from_secs(86_400)), &utc_time(now + Duration::from_secs(30 * 86_400))])
}

fn spki(public_key: &[u8]) -> Vec<u8> {
    seq(&[&seq(&[ED25519]), &bits(public_key)])
}

fn certificate(serial: u64, issuer: &[u8], subject: &[u8], subject_key: &[u8], extensions: &[Vec<u8>], signer: &Ed25519KeyPair) -> Vec<u8> {
    let alg = seq(&[ED25519]);
    let ext_refs: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
    let tbs = seq(&[&[0xa0, 0x03, 0x02, 0x01, 0x02], &integer(serial), &alg, issuer, &validity(), subject, &spki(subject_key), &tlv(0xa3, &seq(&ext_refs))]);
    let signature = signer.sign(&tbs);
    seq(&[&tbs, &alg, &bits(signature.as_ref())])
}

/// A CA: its key and its self-signed certificate.
pub struct Ca {
    key: Ed25519KeyPair,
    name: Vec<u8>,
    /// Its certificate, DER.
    pub cert_der: Vec<u8>,
}

/// A leaf: its certificate and its PKCS#8 key.
pub struct Leaf {
    /// Its certificate, DER.
    pub cert_der: Vec<u8>,
    /// Its key, PKCS#8 v2 DER.
    pub key_pkcs8: Vec<u8>,
}

impl Ca {
    /// A CA named `cn` with the key of `seed`.
    pub fn new(cn: &str, seed: [u8; 32]) -> Ca {
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).expect("an Ed25519 seed");
        let name = name(cn);
        let extensions = [
            extension(BASIC_CONSTRAINTS, true, &seq(&[&[0x01, 0x01, 0xff]])),
            extension(KEY_USAGE, true, &[0x03, 0x02, 0x01, 0x06]),
        ];
        let cert_der = certificate(1, &name, &name, key.public_key().as_ref(), &extensions, &key);
        Ca { key, name, cert_der }
    }

    /// A server leaf with these SANs, its key from `seed`, signed by this CA.
    pub fn leaf(&self, serial: u64, dns: &[&str], ips: &[[u8; 4]], seed: [u8; 32]) -> Leaf {
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).expect("an Ed25519 seed");
        let mut sans: Vec<u8> = Vec::new();
        for d in dns {
            sans.extend(tlv(0x82, d.as_bytes()));
        }
        for ip in ips {
            sans.extend(tlv(0x87, ip));
        }
        let extensions = [
            extension(BASIC_CONSTRAINTS, true, &seq(&[])),
            extension(KEY_USAGE, true, &[0x03, 0x02, 0x07, 0x80]),
            extension(EXT_KEY_USAGE, false, &seq(&[SERVER_AUTH])),
            extension(SUBJECT_ALT_NAME, false, &tlv(0x30, &sans)),
        ];
        let cert_der = certificate(serial, &self.name, &name("ai-env-relay"), key.public_key().as_ref(), &extensions, &self.key);
        let key_pkcs8 = key.to_pkcs8().expect("PKCS#8").as_ref().to_vec();
        Leaf { cert_der, key_pkcs8 }
    }
}

fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= c.len() { A[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }
    out
}

/// One PEM block, its markers assembled at run time.
pub fn pem(label: &str, der: &[u8]) -> String {
    let dashes = "-".repeat(5);
    let body: Vec<String> = b64(der).as_bytes().chunks(64).map(|l| String::from_utf8_lossy(l).into_owned()).collect();
    format!("{dashes}BEGIN {label}{dashes}\n{}\n{dashes}END {label}{dashes}\n", body.join("\n"))
}

/// `tls.pem` as I's reload writes it: the leaf, the CA, then the PKCS#8 key (§R-relay.3.5).
pub fn tls_pem(leaf: &Leaf, ca: &Ca) -> String {
    tls_pem_with_key(leaf, ca, leaf)
}

/// `tls.pem` with another leaf's key (refused by `server_config`).
pub fn tls_pem_with_key(leaf: &Leaf, ca: &Ca, key_of: &Leaf) -> String {
    [pem("CERTIFICATE", &leaf.cert_der), pem("CERTIFICATE", &ca.cert_der), pem(&["PRIVATE", "KEY"].join(" "), &key_of.key_pkcs8)].concat()
}

/// The CA's certificate as a PEM, for a client's roots.
pub fn ca_pem(ca: &Ca) -> String {
    pem("CERTIFICATE", &ca.cert_der)
}
