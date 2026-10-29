//! Ed25519 keys through aws-lc-rs, and key files (WM-R3, WM-R4). Nothing here prints a private key: every
//! `Debug` and error shows a 16-hex fingerprint at most.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

/// The largest key file read.
pub const KEY_FILE_MAX: u64 = 4096;
/// An Ed25519 public key's length.
pub const PUBLIC_KEY_LEN: usize = 32;
/// An Ed25519 signature's length.
pub const SIGNATURE_LEN: usize = 64;

/// A public key's text prefix (WM-R3).
const TEXT_PREFIX: &str = "ed25519:";
/// The one PEM label a key file holds.
const KEY_LABEL: &str = "PRIVATE KEY";

/// A signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// Ed25519.
    Ed25519,
}

impl Alg {
    /// `ed25519`.
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::Ed25519 => "ed25519",
        }
    }

    /// The proto's `SigAlg`.
    pub fn wire(self) -> ai_env_relay_proto::v1::SigAlg {
        match self {
            Alg::Ed25519 => ai_env_relay_proto::v1::SigAlg::Ed25519,
        }
    }

    /// The algorithm of its text form.
    pub fn parse(s: &str) -> Option<Alg> {
        (s == Alg::Ed25519.as_str()).then_some(Alg::Ed25519)
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// A key of these 32 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<PublicKey, KeyError> {
        <[u8; PUBLIC_KEY_LEN]>::try_from(b).map(PublicKey).map_err(|_| KeyError(format!("a public key is {PUBLIC_KEY_LEN} bytes, not {}", b.len())))
    }

    /// `ed25519:<b64 of 32 bytes>`.
    pub fn parse_text(s: &str) -> Result<PublicKey, KeyError> {
        let b64 = s.strip_prefix(TEXT_PREFIX).ok_or_else(|| KeyError(format!("a public key's text is {TEXT_PREFIX}<base64 of 32 bytes>")))?;
        PublicKey::parse_b64(b64)
    }

    /// The relay lists' form: the `b64` alone (standard base64 with its padding, 44 characters).
    pub fn parse_b64(s: &str) -> Result<PublicKey, KeyError> {
        let bad = || KeyError(format!("a public key is the standard base64 (with padding) of {PUBLIC_KEY_LEN} bytes"));
        let bytes = STANDARD.decode(s).map_err(|_| bad())?;
        PublicKey::from_bytes(&bytes).map_err(|_| bad())
    }

    /// The 32 bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `ed25519:<b64>`, 52 characters.
    pub fn text(&self) -> String {
        format!("{TEXT_PREFIX}{}", self.b64())
    }

    /// The `b64` of the 32 bytes.
    pub fn b64(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// The first 16 lowercase hex characters of SHA-256 of the 32 bytes.
    pub fn fingerprint(&self) -> String {
        sha256_hex16(&self.0)
    }

    /// Whether `sig` is this key's signature of `msg`.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        sig.len() == SIGNATURE_LEN && signature::UnparsedPublicKey::new(&signature::ED25519, &self.0).verify(msg, sig).is_ok()
    }
}

impl fmt::Debug for PublicKey {
    /// `PublicKey(fp <fp>)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey(fp {})", self.fingerprint())
    }
}

/// The first 16 lowercase hex characters of SHA-256 of `bytes` (WM-R3's fingerprint, `certs::fingerprint`).
pub(crate) fn sha256_hex16(bytes: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    digest.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// An Ed25519 private key, in aws-lc-rs only. No `Clone`.
pub struct SigningKey {
    pair: Ed25519KeyPair,
}

impl SigningKey {
    /// A fresh key.
    pub fn generate() -> Result<SigningKey, KeyError> {
        Ed25519KeyPair::generate().map(|pair| SigningKey { pair }).map_err(|_| KeyError("no Ed25519 key could be generated".to_string()))
    }

    /// The key of a seed: tests and known answers (a real seed comes from a CSPRNG).
    pub fn from_seed(seed: &[u8; 32]) -> Result<SigningKey, KeyError> {
        Ed25519KeyPair::from_seed_unchecked(seed).map(|pair| SigningKey { pair }).map_err(|_| KeyError("not an Ed25519 seed".to_string()))
    }

    /// PKCS#8 v1 or v2 DER: exactly one DER element (aws-lc would ignore bytes after it).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<SigningKey, KeyError> {
        let bad = || KeyError("not a PKCS#8 Ed25519 private key".to_string());
        if !one_der_sequence(der) {
            return Err(bad());
        }
        Ed25519KeyPair::from_pkcs8(der).map(|pair| SigningKey { pair }).map_err(|_| bad())
    }

    /// One `PRIVATE KEY` PEM block.
    pub fn from_pkcs8_pem(pem: &[u8]) -> Result<SigningKey, KeyError> {
        let mut blocks = pem_blocks(pem).map_err(KeyError)?;
        match blocks.as_slice() {
            [(label, _)] if label == KEY_LABEL => {}
            [(label, _)] => return Err(KeyError(format!("a {label} block, not a {KEY_LABEL} block"))),
            [] => return Err(KeyError(format!("no {KEY_LABEL} block"))),
            more => return Err(KeyError(format!("{} PEM blocks, not one {KEY_LABEL} block", more.len()))),
        }
        let (_, der) = blocks.remove(0);
        SigningKey::from_pkcs8_der(&der)
    }

    /// PKCS#8 v2 DER, in zeroizing memory.
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        // `Document` zeroizes its own copy when dropped.
        let doc = self.pair.to_pkcs8().map_err(|_| KeyError("the key could not be encoded".to_string()))?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// PKCS#8 v2 PEM (`PRIVATE KEY`, 64-character lines), in zeroizing memory.
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>, KeyError> {
        let der = self.to_pkcs8_der()?;
        Ok(crate::certs::pem_zeroizing(KEY_LABEL, &der))
    }

    /// Its public key.
    pub fn public_key(&self) -> PublicKey {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(self.pair.public_key().as_ref());
        PublicKey(out)
    }

    /// The Ed25519 signature of `msg`.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; SIGNATURE_LEN];
        out.copy_from_slice(self.pair.sign(msg).as_ref());
        out
    }
}

impl fmt::Debug for SigningKey {
    /// `SigningKey(fp <fp>)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey(fp {})", self.public_key().fingerprint())
    }
}

/// Whether `der` is one DER SEQUENCE and nothing after it.
fn one_der_sequence(der: &[u8]) -> bool {
    let (Some(&0x30), Some(&first)) = (der.first(), der.get(1)) else {
        return false;
    };
    let (len, head): (usize, usize) = match first {
        0..=0x7f => (usize::from(first), 2),
        0x81 => (der.get(2).map_or(usize::MAX, |&b| usize::from(b)), 3),
        0x82 => (der.get(2..4).map_or(usize::MAX, |b| usize::from(b[0]) << 8 | usize::from(b[1])), 4),
        _ => return false,
    };
    head.checked_add(len) == Some(der.len())
}

/// One PEM block: its label and its decoded body (zeroized when dropped).
pub(crate) type PemBlock = (String, Zeroizing<Vec<u8>>);

/// The PEM blocks of `text`, in order: each label and its decoded body (zeroized when dropped). Text outside
/// the blocks is ignored (RFC 7468's explanatory text); a block without its END line, or with a body that
/// is not standard base64, is refused.
pub(crate) fn pem_blocks(text: &[u8]) -> Result<Vec<PemBlock>, String> {
    let text = std::str::from_utf8(text).map_err(|_| "not PEM text".to_string())?;
    let mut blocks = Vec::new();
    let mut open: Option<(String, Zeroizing<String>)> = None;
    for line in text.lines().map(str::trim) {
        if let Some((label, body)) = open.as_mut() {
            if let Some(end) = line.strip_prefix("-----END ").and_then(|l| l.strip_suffix("-----")) {
                if end != label {
                    return Err(format!("a {label} block ends as {end}"));
                }
                let der = Zeroizing::new(STANDARD.decode(body.as_bytes()).map_err(|_| format!("a {label} block that is not base64"))?);
                blocks.push((std::mem::take(label), der));
                open = None;
            } else if line.starts_with("-----") {
                return Err(format!("a {label} block without its END line"));
            } else {
                body.push_str(line);
            }
        } else if let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) {
            open = Some((label.to_string(), Zeroizing::new(String::with_capacity(text.len()))));
        }
    }
    match open {
        Some((label, _)) => Err(format!("a {label} block without its END line")),
        None => Ok(blocks),
    }
}

/// Writes a 0600 key file: `O_CREAT|O_EXCL`, or with `force` a temp file renamed over the old one (WM-R4).
pub fn write_key_file(path: &Path, key: &SigningKey, force: bool) -> Result<(), KeyFileError> {
    let shown = path.display();
    let pem = key.to_pkcs8_pem().map_err(|e| KeyFileError(format!("{shown}: {e}")))?;
    let create = |p: &Path| OpenOptions::new().write(true).create_new(true).mode(0o600).open(p);
    if !force {
        let mut file = create(path).map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => KeyFileError(format!("{shown} already exists: --force replaces it")),
            _ => KeyFileError(format!("cannot create {shown}: {e}")),
        })?;
        return write_synced(&mut file, pem.as_bytes()).map_err(|e| KeyFileError(format!("cannot write {shown}: {e}")));
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path.file_name().ok_or_else(|| KeyFileError(format!("{shown} names no file")))?;
    let mut nonce = [0u8; 8];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| KeyFileError(format!("{shown}: no random bytes for a temp name")))?;
    let tmp = dir.join(format!(".{}.tmp-{}-{}", name.to_string_lossy(), std::process::id(), u64::from_be_bytes(nonce)));
    let written = create(&tmp)
        .and_then(|mut file| write_synced(&mut file, pem.as_bytes()))
        .and_then(|()| std::fs::rename(&tmp, path))
        .and_then(|()| File::open(dir).and_then(|d| d.sync_all()));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        KeyFileError(format!("cannot replace {shown}: {e}"))
    })
}

/// All of `bytes`, then fsync, then 0600 again (an inherited ACL or umask never widens it).
fn write_synced(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.sync_all()
}

/// Reads a key file: a regular file of the effective uid, no group or other bits, at most 4096 bytes, one
/// `PRIVATE KEY` block of an Ed25519 key (WM-R4).
pub fn read_key_file(path: &Path) -> Result<SigningKey, KeyFileError> {
    let shown = path.display();
    let refused = |why: String| KeyFileError(format!("{shown}: {why}"));
    let meta = std::fs::symlink_metadata(path).map_err(|e| KeyFileError(format!("cannot read {shown}: {e}")))?;
    let kind = meta.file_type();
    if kind.is_symlink() {
        return Err(refused("is a symlink: point the config at the key file itself".to_string()));
    }
    if !kind.is_file() {
        return Err(refused("is not a regular file".to_string()));
    }
    let euid = nix::unistd::geteuid().as_raw();
    if meta.uid() != euid {
        return Err(refused(format!("is owned by uid {}, not this process's uid {euid}", meta.uid())));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(refused(format!("has mode {mode:04o}: a key file is 0600 (chmod 600)")));
    }
    if meta.len() > KEY_FILE_MAX {
        return Err(refused(format!("is {} bytes, over {KEY_FILE_MAX}", meta.len())));
    }
    // O_NOFOLLOW and O_NONBLOCK: a symlink or a FIFO swapped in since the lstat fails or never blocks.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| KeyFileError(format!("cannot open {shown}: {e}")))?;
    let opened = file.metadata().map_err(|e| KeyFileError(format!("cannot read {shown}: {e}")))?;
    if !opened.file_type().is_file() || (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
        return Err(refused("changed while it was opened".to_string()));
    }
    let cap = usize::try_from(KEY_FILE_MAX).unwrap_or(usize::MAX);
    let mut buf = Zeroizing::new(vec![0u8; cap + 1]);
    let mut n = 0;
    while n < buf.len() {
        match file.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(KeyFileError(format!("cannot read {shown}: {e}"))),
        }
    }
    if n > cap {
        return Err(refused(format!("is over {KEY_FILE_MAX} bytes")));
    }
    SigningKey::from_pkcs8_pem(&buf[..n]).map_err(|e| refused(e.to_string()))
}

/// A key that cannot be used (WM-R3). Phase 0 freezes the name; W chooses its variants (its text names a
/// fingerprint at most, never a key).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct KeyError(String);

/// A key file refused or not written (WM-R4), naming the path. Phase 0 freezes the name; W chooses its variants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct KeyFileError(String);

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sha256(bytes: &[u8]) -> String {
        hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes).as_ref())
    }

    /// WM-T3.
    #[test]
    fn a_key_round_trips_through_pkcs8_and_pem() {
        let key = SigningKey::generate().expect("a key");
        let der = key.to_pkcs8_der().expect("DER");
        assert_eq!(SigningKey::from_pkcs8_der(&der).expect("reads").public_key(), key.public_key());
        let pem = key.to_pkcs8_pem().expect("PEM");
        assert!(pem.starts_with(&format!("-----BEGIN {KEY_LABEL}-----\n")), "{}", pem.lines().next().unwrap_or(""));
        assert!(pem.ends_with(&format!("-----END {KEY_LABEL}-----\n")));
        let body: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(!body.is_empty());
        for (i, line) in body.iter().enumerate() {
            if i + 1 < body.len() {
                assert_eq!(line.len(), 64, "line {i}");
            } else {
                assert!(line.len() <= 64);
            }
        }
        assert_eq!(SigningKey::from_pkcs8_pem(pem.as_bytes()).expect("reads").public_key(), key.public_key());

        let mut v1 = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        assert_eq!(hex(&v1), "302e020100300506032b657004220420");
        v1.extend_from_slice(&[7u8; 32]);
        let seven = SigningKey::from_seed(&[7u8; 32]).expect("seed");
        assert_eq!(SigningKey::from_pkcs8_der(&v1).expect("a v1 DER").public_key(), seven.public_key());
        for len in [v1.len() - 1, v1.len() + 1] {
            let mut other = v1.clone();
            other.resize(len, 0);
            assert!(SigningKey::from_pkcs8_der(&other).is_err(), "a DER of {len} bytes");
        }
    }

    /// WM-T4.
    #[test]
    fn the_seed_seven_key_has_its_known_answers() {
        let key = SigningKey::from_seed(&[7u8; 32]).expect("seed");
        let public = key.public_key();
        assert_eq!(public.fingerprint(), "fe812c12f3ab4ce6");
        let text = public.text();
        assert_eq!(text.len(), 52);
        assert!(text.starts_with("ed25519:"));
        assert_eq!(sha256(text.as_bytes()), "303b977bd6197b3c1d2f1135dfc0ce187f1613b2358f9dfe7dee26e1433372ce");
        assert_eq!(PublicKey::parse_text(&text), Ok(public));
        assert_eq!(PublicKey::parse_b64(&public.b64()), Ok(public));
        let b64 = public.b64();
        for bad in [
            format!("ed25519:{}", &b64[..43]),
            format!("ED25519:{b64}"),
            format!("ed448:{b64}"),
            format!("ed25519:{}", b64.trim_end_matches('=')),
            format!("ed25519:{b64}AAAA"),
        ] {
            assert!(PublicKey::parse_text(&bad).is_err(), "{bad} refused");
        }
        let shown = format!("{key:?} {public:?}");
        assert!(shown.contains("fp fe812c12f3ab4ce6"), "{shown}");
        assert!(!shown.contains(&b64), "{shown}");
        assert_eq!(Alg::parse("ed25519"), Some(Alg::Ed25519));
        assert_eq!(Alg::parse("Ed25519"), None);
        assert_eq!(Alg::Ed25519.wire() as i32, 1);
        let sig = key.sign(b"msg");
        assert!(public.verify(b"msg", &sig));
        assert!(!public.verify(b"msh", &sig));
        assert!(!public.verify(b"msg", &sig[..63]));
    }

    /// WM-T5.
    #[test]
    fn key_files_are_private_regular_and_the_owners() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("worker.key");
        let key = SigningKey::generate().expect("a key");
        write_key_file(&path, &key, false).expect("written");
        assert_eq!(std::fs::metadata(&path).expect("meta").mode() & 0o777, 0o600);
        assert_eq!(read_key_file(&path).expect("read").public_key(), key.public_key());

        let again = SigningKey::generate().expect("a key");
        let e = write_key_file(&path, &again, false).expect_err("refused");
        assert!(e.to_string().contains(&path.display().to_string()), "{e}");
        assert_eq!(read_key_file(&path).expect("read").public_key(), key.public_key(), "unchanged");
        write_key_file(&path, &again, true).expect("replaced");
        assert_eq!(read_key_file(&path).expect("read").public_key(), again.public_key());
        let names: Vec<_> = std::fs::read_dir(dir.path()).expect("list").map(|e| e.expect("entry").file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("worker.key")], "no temp file is left");

        for mode in [0o640, 0o604, 0o644] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let e = read_key_file(&path).expect_err("refused");
            assert!(e.to_string().contains("mode"), "{mode:o}: {e}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(read_key_file(&link).expect_err("a symlink").to_string().contains("symlink"));
        assert!(read_key_file(dir.path()).expect_err("a directory").to_string().contains("not a regular file"));
        let fifo = dir.path().join("fifo.key");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status().expect("mkfifo runs");
        assert!(made.success());
        assert!(read_key_file(&fifo).expect_err("a FIFO").to_string().contains("not a regular file"));

        let write = |name: &str, bytes: &[u8]| {
            let p = dir.path().join(name);
            let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p).expect("create");
            f.write_all(bytes).expect("write");
            p
        };
        let big = write("big.key", &vec![b'A'; 4097]);
        assert!(read_key_file(&big).expect_err("too big").to_string().contains("4096"));
        let pem = key.to_pkcs8_pem().expect("PEM");
        let two = write("two.key", format!("{}{}", pem.as_str(), pem.as_str()).as_bytes());
        assert!(read_key_file(&two).expect_err("two blocks").to_string().contains("2 PEM blocks"));
        let cert = write("cert.key", pem.replace("PRIVATE KEY", "CERTIFICATE").as_bytes());
        assert!(read_key_file(&cert).expect_err("a certificate").to_string().contains("CERTIFICATE"));
        let none = write("none.key", b"no block here\n");
        assert!(read_key_file(&none).expect_err("no block").to_string().contains("no PRIVATE KEY block"));
        let missing = dir.path().join("missing.key");
        assert!(read_key_file(&missing).is_err());
    }
}
