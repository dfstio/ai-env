//! Locating the other binary of the pair (`ai-env` ⇄ `ai-env-claude`): the
//! sibling next to the running executable is authoritative; a PATH-only copy
//! is only ever a doctor note.
use crate::age_cmd::{effective_path, find_in_path};
use crate::errors::{CliError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sibling {
    /// Found next to the executable (or next to its canonical path).
    Next(PathBuf),
    /// Only found on PATH.
    PathOnly(PathBuf),
    Missing,
}

pub const INSTALL_HINT: &str = "install with: cargo install --path crates/ai-env-cli --locked";

/// Pure resolution over an explicit executable path and PATH value.
#[must_use]
pub fn find_sibling_in(exe: &Path, path_env: &str, name: &str) -> Sibling {
    if let Some(dir) = exe.parent() {
        let p = dir.join(name);
        if p.is_file() {
            return Sibling::Next(p);
        }
    }
    if let Ok(real) = std::fs::canonicalize(exe) {
        if let Some(dir) = real.parent() {
            let p = dir.join(name);
            if p.is_file() {
                return Sibling::Next(p);
            }
        }
    }
    match find_in_path(name, path_env) {
        Some(p) => Sibling::PathOnly(p),
        None => Sibling::Missing,
    }
}

#[cfg(unix)]
fn access_x(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path; access(2) only reads it.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

#[cfg(not(unix))]
fn access_x(_: &Path) -> bool {
    true
}

/// `(exists, executable)` — a regular file this user may execute (access(2),
/// not mode bits: ACLs and ownership count). Shared by the doctor rows, the
/// wrapper binary and `wrapper install`.
#[must_use]
pub fn exists_exec(p: &Path) -> (bool, bool) {
    let Ok(meta) = std::fs::metadata(p) else {
        return (false, false);
    };
    (true, meta.is_file() && access_x(p))
}

/// Resolve relative to the current executable.
#[must_use]
pub fn find_sibling(name: &str) -> Sibling {
    match std::env::current_exe() {
        Ok(exe) => find_sibling_in(&exe, &effective_path(), name),
        Err(_) => match find_in_path(name, &effective_path()) {
            Some(p) => Sibling::PathOnly(p),
            None => Sibling::Missing,
        },
    }
}

/// The sibling's path plus an optional note; `Missing` is exit 5 with the
/// install hint.
pub fn require_sibling(name: &str) -> Result<(PathBuf, Option<String>)> {
    match find_sibling(name) {
        Sibling::Next(p) => Ok((p, None)),
        Sibling::PathOnly(p) => {
            let note = format!("{name} found on PATH only ({}) — {INSTALL_HINT}", p.display());
            Ok((p, Some(note)))
        }
        Sibling::Missing => Err(CliError::AuthUnavailable(format!("{name} not found — {INSTALL_HINT}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exe_file(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        p
    }

    #[test]
    fn sibling_next_to_exe() {
        let d = tempfile::tempdir().unwrap();
        let exe = exe_file(d.path(), "ai-env");
        let want = exe_file(d.path(), "ai-env-claude");
        assert_eq!(find_sibling_in(&exe, "", "ai-env-claude"), Sibling::Next(want));
    }

    #[test]
    fn sibling_path_only() {
        let d = tempfile::tempdir().unwrap();
        let exe = exe_file(d.path(), "ai-env");
        let other = tempfile::tempdir().unwrap();
        let on_path = exe_file(other.path(), "ai-env-claude");
        let path_env = other.path().to_string_lossy().into_owned();
        assert_eq!(find_sibling_in(&exe, &path_env, "ai-env-claude"), Sibling::PathOnly(on_path));
    }

    #[test]
    fn sibling_missing() {
        let d = tempfile::tempdir().unwrap();
        let exe = exe_file(d.path(), "ai-env");
        assert_eq!(find_sibling_in(&exe, "/nonexistent-dir-for-test", "ai-env-claude"), Sibling::Missing);
    }
}
