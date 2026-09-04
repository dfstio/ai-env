//! The scratch: the ONE place plaintext may exist while the editor runs.
//!
//! A fixed-capacity 4 KiB buffer in `memsec` guarded memory (guard pages,
//! mlocked, wiped on free). It can never reallocate — Rust `String`/`Vec`
//! growth reallocates *without zeroing*, which is exactly how secrets get
//! scattered across the heap. Editing is done in place with `copy_within`.
//!
//! No `Debug`, no `Display`, no `Clone`, no `format!` over contents.
use crate::errors::{CliError, Result};
use std::ptr::NonNull;

pub const SCRATCH_BYTES: usize = 4096;

pub struct Scratch {
    ptr: NonNull<[u8; SCRATCH_BYTES]>,
    len: usize,
}

impl Scratch {
    pub fn new() -> Result<Self> {
        // SAFETY: guarded alloc; region stays readable/writable for its life
        // (it is the active editing surface), mlocked + wiped by memsec.
        let ptr: NonNull<[u8; SCRATCH_BYTES]> = unsafe { memsec::malloc() }
            .ok_or_else(|| CliError::Msg("cannot allocate guarded scratch".into()))?;
        unsafe { (*ptr.as_ptr()).fill(0) };
        Ok(Self { ptr, len: 0 })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    fn buf(&self) -> &[u8; SCRATCH_BYTES] {
        // SAFETY: region valid for the lifetime of self.
        unsafe { &*self.ptr.as_ptr() }
    }

    fn buf_mut(&mut self) -> &mut [u8; SCRATCH_BYTES] {
        // SAFETY: region valid for the lifetime of self; unique via &mut self.
        unsafe { &mut *self.ptr.as_ptr() }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf()[..self.len]
    }

    /// The contents as &str. Contents are only ever loaded from validated
    /// UTF-8 and mutated at char boundaries, so this cannot fail in practice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    /// Replace contents (test convenience; production paths use load_with).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn load(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > SCRATCH_BYTES {
            return Err(CliError::Msg("value too large for scratch".into()));
        }
        let len = bytes.len();
        let buf = self.buf_mut();
        buf[..len].copy_from_slice(bytes);
        buf[len..].fill(0);
        self.len = len;
        Ok(())
    }

    /// Load via a callback that writes directly into the buffer (no copy of
    /// the plaintext outside guarded memory). The callback returns the length.
    pub fn load_with(&mut self, f: impl FnOnce(&mut [u8]) -> Result<usize>) -> Result<()> {
        self.wipe();
        let buf = self.buf_mut();
        let len = f(&mut buf[..])?;
        if len > SCRATCH_BYTES {
            self.wipe();
            return Err(CliError::Msg("value too large for scratch".into()));
        }
        self.len = len;
        Ok(())
    }

    /// Insert a char at byte index `at` (must be a char boundary).
    ///
    /// The insert ceiling is `cells::MAX_VALUE`, NOT the physical buffer
    /// size — the caps must agree or a value that fits the scratch would be
    /// unsealable at commit (audit fix 11a).
    pub fn insert_char(&mut self, at: usize, c: char) -> Result<()> {
        let mut enc = [0u8; 4];
        let s = c.encode_utf8(&mut enc);
        let n = s.len();
        if self.len + n > super::cells::MAX_VALUE || at > self.len {
            return Err(CliError::Msg(format!(
                "value full ({} byte limit)",
                super::cells::MAX_VALUE
            )));
        }
        let len = self.len;
        let buf = self.buf_mut();
        buf.copy_within(at..len, at + n);
        buf[at..at + n].copy_from_slice(s.as_bytes());
        self.len += n;
        Ok(())
    }

    /// Remove `count` bytes at `at` (caller guarantees char boundaries).
    pub fn delete_range(&mut self, at: usize, count: usize) {
        if at >= self.len || count == 0 {
            return;
        }
        let count = count.min(self.len - at);
        let len = self.len;
        let buf = self.buf_mut();
        buf.copy_within(at + count..len, at);
        buf[len - count..].fill(0); // wipe the tail immediately
        self.len -= count;
    }

    /// Zero everything.
    pub fn wipe(&mut self) {
        self.buf_mut().fill(0);
        self.len = 0;
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.wipe();
        // SAFETY: memsec wipes again and frees the guarded region.
        unsafe { memsec::free(self.ptr) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_ops() {
        let mut s = Scratch::new().unwrap();
        s.load(b"hello").unwrap();
        s.insert_char(5, '!').unwrap();
        assert_eq!(s.as_str(), "hello!");
        s.insert_char(0, 'é').unwrap(); // 2-byte char
        assert_eq!(s.as_str(), "éhello!");
        s.delete_range(0, 2);
        assert_eq!(s.as_str(), "hello!");
        s.delete_range(5, 1);
        assert_eq!(s.as_str(), "hello");
        s.wipe();
        assert_eq!(s.len(), 0);
        assert_eq!(s.as_str(), "");
    }

    #[test]
    fn tail_is_wiped_after_delete() {
        let mut s = Scratch::new().unwrap();
        s.load(b"secretsecret").unwrap();
        s.delete_range(6, 6);
        assert_eq!(s.as_str(), "secret");
        // Bytes past len must be zero (no residue of the deleted half).
        assert!(s.buf()[6..16].iter().all(|&b| b == 0));
    }

    #[test]
    fn capacity_enforced() {
        let mut s = Scratch::new().unwrap();
        assert!(s.load(&[b'x'; SCRATCH_BYTES + 1]).is_err());
        // Insert ceiling = MAX_VALUE (4000), aligned with SealedCell::seal —
        // the 4001st byte must be a friendly error, not a session-killer.
        s.load(&[b'x'; super::super::cells::MAX_VALUE]).unwrap();
        let err = s.insert_char(0, 'y').unwrap_err();
        assert!(err.to_string().contains("value full"));
    }

    #[test]
    fn load_with_writes_in_place() {
        let mut s = Scratch::new().unwrap();
        s.load_with(|buf| {
            buf[..3].copy_from_slice(b"abc");
            Ok(3)
        })
        .unwrap();
        assert_eq!(s.as_str(), "abc");
    }
}
