//! Sealed value cells — the in-memory encryption for `ai-env edit`.
//!
//! Construction copied from OpenSSH's ssh-agent key shielding, not invented:
//! * one ephemeral **16 KiB prekey** per edit session, held in `memsec`
//!   guarded memory (guard pages, canary, mlocked, zeroed on free) and kept
//!   `mprotect(NoAccess)` except during the microseconds of a KDF call —
//!   16 KiB deliberately, so a partial memory read cannot reconstruct it;
//! * per-cell subkey = HKDF-SHA256(prekey, info = key_name ‖ 0x00 ‖ generation);
//! * seal = XChaCha20-Poly1305, fresh random 24-byte nonce each time,
//!   AAD = key_name ‖ 0x00 ‖ generation (a memory-write attacker cannot swap
//!   cells between slots or roll one back to an old generation);
//! * plaintext padded to 256-byte buckets before sealing (a ciphertext length
//!   must not distinguish a short password from a 64-hex private key).
//!
//! NO `Debug`/`Display`/`Clone` on any type holding secrets, no `format!` on
//! secret bytes anywhere in this module.
use crate::errors::{CliError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use std::ptr::NonNull;
use zeroize::Zeroizing;

pub const PREKEY_BYTES: usize = 16 * 1024;
pub const PAD_BUCKET: usize = 256;
/// Largest raw value we accept (fits the 4 KiB scratch with its length header).
pub const MAX_VALUE: usize = 4000;

/// The session prekey in guarded, locked memory.
pub struct Prekey {
    ptr: NonNull<[u8; PREKEY_BYTES]>,
}

impl Prekey {
    pub fn new() -> Result<Self> {
        // SAFETY: memsec::malloc returns a guarded, mlocked, canaried region
        // sized for the pointee type; we fill it and immediately lock it away.
        unsafe {
            let ptr: NonNull<[u8; PREKEY_BYTES]> = memsec::malloc()
                .ok_or_else(|| CliError::Msg("cannot allocate guarded memory".into()))?;
            let region: &mut [u8; PREKEY_BYTES] = &mut *ptr.as_ptr();
            fill_random(&mut region[..])?;
            if !memsec::mprotect(ptr, memsec::Prot::NoAccess) {
                memsec::free(ptr);
                return Err(CliError::Msg("cannot protect guarded memory".into()));
            }
            Ok(Self { ptr })
        }
    }

    /// Derive the 32-byte subkey for (name, generation) into the caller's
    /// Zeroizing buffer. The prekey pages are readable only during the
    /// HKDF-Extract inside `derive_inner`.
    ///
    /// HYGIENE (audit fix 1): hkdf/hmac 0.12 leave the PRK and the keyed
    /// ipad/opad HMAC states on the stack with no zeroization of their own,
    /// and the PRK is a full substitute for the prekey. So: (a) the `Hkdf`
    /// value is explicitly volatile-zeroed after use; (b) derivation runs in
    /// an #[inline(never)] frame and is immediately followed by a same-depth
    /// #[inline(never)] stack scrub that overwrites the frame region the
    /// library's unnameable intermediates lived in. This is best-effort by
    /// nature (documented residual: a scheduler-timed snapshot between the
    /// two calls can still catch the transient).
    fn subkey_into(&self, name: &str, generation: u64, out: &mut Zeroizing<[u8; 32]>) -> Result<()> {
        let mut info = Zeroizing::new(Vec::with_capacity(name.len() + 9));
        info.extend_from_slice(name.as_bytes());
        info.push(0);
        info.extend_from_slice(&generation.to_le_bytes());
        let result = self.derive_inner(&info, out);
        scrub_stack();
        result
    }

    #[inline(never)]
    fn derive_inner(&self, info: &[u8], out: &mut [u8; 32]) -> Result<()> {
        // SAFETY: we own ptr; flip protection around the read and restore it.
        unsafe {
            if !memsec::mprotect(self.ptr, memsec::Prot::ReadOnly) {
                return Err(CliError::Msg("cannot unprotect guarded memory".into()));
            }
            let region: &[u8; PREKEY_BYTES] = &*self.ptr.as_ptr();
            let mut hk = Hkdf::<Sha256>::new(None, &region[..]);
            memsec::mprotect(self.ptr, memsec::Prot::NoAccess);

            let expanded = hk.expand(info, out);
            // Hkdf<Sha256> is plain data (two SHA-256 cores keyed by the PRK,
            // no Drop, no pointers): volatile-zero it before the frame dies.
            memsec::memzero(
                std::ptr::addr_of_mut!(hk).cast::<u8>(),
                std::mem::size_of::<Hkdf<Sha256>>(),
            );
            std::hint::black_box(&hk);
            expanded.map_err(|_| CliError::Msg("subkey derivation failed".into()))
        }
    }
}

/// Overwrite the stack region a just-returned crypto frame used. Called at
/// the same depth as `derive_inner` so its 2 KiB local covers that frame's
/// PRK `Output` and hmac's 64-byte key⊕ipad buffer. Never writes below SP.
#[inline(never)]
fn scrub_stack() {
    let mut pad = [0u8; 2048];
    // SAFETY: pad is a live local; memzero is a volatile write loop.
    unsafe { memsec::memzero(pad.as_mut_ptr(), pad.len()) };
    std::hint::black_box(&pad);
}

impl Drop for Prekey {
    fn drop(&mut self) {
        // SAFETY: restore access so memsec can wipe and free the region.
        unsafe {
            memsec::mprotect(self.ptr, memsec::Prot::ReadWrite);
            memsec::free(self.ptr);
        }
    }
}

/// One sealed value. Holds ONLY ciphertext + public metadata.
pub struct SealedCell {
    ct: Vec<u8>,
    nonce: [u8; 24],
    generation: u64,
}

impl SealedCell {
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Seal `plaintext` for slot `name`. `generation` must be one the caller
    /// has never used for this name within this session (monotonic counter).
    pub fn seal(prekey: &Prekey, name: &str, generation: u64, plaintext: &[u8]) -> Result<Self> {
        if plaintext.len() > MAX_VALUE {
            return Err(CliError::Msg(format!(
                "value too long ({} bytes; limit {MAX_VALUE})",
                plaintext.len()
            )));
        }
        // Pad: len_u16_le ‖ plaintext ‖ zeros, to a PAD_BUCKET multiple.
        let inner = 2 + plaintext.len();
        let padded_len = inner.div_ceil(PAD_BUCKET) * PAD_BUCKET;
        let mut padded = Zeroizing::new(vec![0u8; padded_len]);
        padded[..2].copy_from_slice(&(plaintext.len() as u16).to_le_bytes());
        padded[2..2 + plaintext.len()].copy_from_slice(plaintext);

        let mut key = Zeroizing::new([0u8; 32]);
        prekey.subkey_into(name, generation, &mut key)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let mut nonce = [0u8; 24];
        fill_random(&mut nonce)?;
        let ct = cipher
            .encrypt(
                (&nonce).into(),
                Payload { msg: &padded, aad: &aad(name, generation) },
            )
            .map_err(|_| CliError::Msg("seal failed".into()))?;
        Ok(Self { ct, nonce, generation })
    }

    /// Open this cell into `out` (caller's locked scratch); returns the
    /// plaintext length written at `out[..len]`.
    pub fn open(&self, prekey: &Prekey, name: &str, out: &mut [u8]) -> Result<usize> {
        let mut key = Zeroizing::new([0u8; 32]);
        prekey.subkey_into(name, self.generation, &mut key)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let padded = Zeroizing::new(
            cipher
                .decrypt(
                    (&self.nonce).into(),
                    Payload { msg: self.ct.as_slice(), aad: &aad(name, self.generation) },
                )
                .map_err(|_| {
                    CliError::Msg(format!(
                        "internal seal integrity failure for {name:?} — memory corruption?"
                    ))
                })?,
        );
        if padded.len() < 2 {
            return Err(CliError::Msg("sealed cell truncated".into()));
        }
        let len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
        if 2 + len > padded.len() || len > out.len() {
            return Err(CliError::Msg("sealed cell length out of range".into()));
        }
        out[..len].copy_from_slice(&padded[2..2 + len]);
        Ok(len)
    }
}

fn aad(name: &str, generation: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(name.len() + 9);
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&generation.to_le_bytes());
    aad
}

/// Fill from the kernel CSPRNG via getentropy(2) (max 256 bytes per call).
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    for chunk in buf.chunks_mut(256) {
        // SAFETY: valid pointer + length ≤ 256 as required by getentropy.
        let rc = unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
        if rc != 0 {
            return Err(CliError::Msg("getentropy failed".into()));
        }
    }
    Ok(())
}

/// Capped ring of sealed snapshots — the committed-undo history. Never holds
/// plaintext.
pub struct SealedRing {
    items: Vec<SealedCell>,
    cap: usize,
}

impl SealedRing {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self { items: Vec::new(), cap }
    }
    pub fn push(&mut self, cell: SealedCell) {
        if self.items.len() == self.cap {
            self.items.remove(0);
        }
        self.items.push(cell);
    }
    pub fn pop(&mut self) -> Option<SealedCell> {
        self.items.pop()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_aad_binding() {
        let prekey = Prekey::new().unwrap();
        let cell = SealedCell::seal(&prekey, "API_KEY", 3, b"sk-live-42").unwrap();
        let mut out = [0u8; 64];
        let n = cell.open(&prekey, "API_KEY", &mut out).unwrap();
        assert_eq!(&out[..n], b"sk-live-42");

        // Wrong slot name must fail (AAD + subkey binding).
        assert!(cell.open(&prekey, "OTHER", &mut out).is_err());
    }

    #[test]
    fn generation_binding() {
        let prekey = Prekey::new().unwrap();
        let old = SealedCell::seal(&prekey, "K", 1, b"one").unwrap();
        let newer = SealedCell::seal(&prekey, "K", 2, b"two").unwrap();
        let mut out = [0u8; 64];
        // Each opens only under its own generation (stored in the cell).
        assert_eq!(old.open(&prekey, "K", &mut out).unwrap(), 3);
        assert_eq!(newer.open(&prekey, "K", &mut out).unwrap(), 3);
        // A forged generation (tampered field) must fail.
        let mut forged = newer;
        forged.generation = 1;
        assert!(forged.open(&prekey, "K", &mut out).is_err());
    }

    #[test]
    fn padding_hides_length() {
        let prekey = Prekey::new().unwrap();
        let short = SealedCell::seal(&prekey, "K", 0, b"x").unwrap();
        let longer = SealedCell::seal(&prekey, "K", 0, &[b'y'; 200]).unwrap();
        assert_eq!(short.ct.len(), longer.ct.len(), "same bucket => same ct length");
        let big = SealedCell::seal(&prekey, "K", 0, &[b'z'; 300]).unwrap();
        assert!(big.ct.len() > short.ct.len());
    }

    #[test]
    fn empty_and_max_values() {
        let prekey = Prekey::new().unwrap();
        let empty = SealedCell::seal(&prekey, "E", 0, b"").unwrap();
        let mut out = [0u8; MAX_VALUE];
        assert_eq!(empty.open(&prekey, "E", &mut out).unwrap(), 0);

        let max = vec![7u8; MAX_VALUE];
        let cell = SealedCell::seal(&prekey, "M", 0, &max).unwrap();
        assert_eq!(cell.open(&prekey, "M", &mut out).unwrap(), MAX_VALUE);
        assert!(SealedCell::seal(&prekey, "M", 0, &vec![0u8; MAX_VALUE + 1]).is_err());
    }

    #[test]
    fn different_prekeys_do_not_open() {
        let a = Prekey::new().unwrap();
        let b = Prekey::new().unwrap();
        let cell = SealedCell::seal(&a, "K", 0, b"secret").unwrap();
        let mut out = [0u8; 64];
        assert!(cell.open(&b, "K", &mut out).is_err());
    }

    #[test]
    fn ring_caps() {
        let prekey = Prekey::new().unwrap();
        let mut ring = SealedRing::new(3);
        for g in 0..5 {
            ring.push(SealedCell::seal(&prekey, "K", g, b"v").unwrap());
        }
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop().unwrap().generation(), 4);
    }
}
