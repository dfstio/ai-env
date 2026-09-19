//! Clone of the Claude extension's project-directory slug (verified against
//! the 2.1.278 bundle): the transcript for a workspace lives under
//! `~/.claude/projects/<slug(realpath(cwd))>/`.
//!
//! The extension replaces every UTF-16 code unit outside `[A-Za-z0-9]` with
//! `-`, and when the result exceeds 200 characters appends `-` plus the
//! base-36 rendering of `|javaHash(original path)|`. The path is
//! `realpathSync`'d first and NFC-normalised — on macOS only.
use std::borrow::Cow;
use std::path::Path;
use unicode_normalization::UnicodeNormalization;

/// Slug length above which the extension truncates and appends a hash suffix.
pub const MAX_SLUG: usize = 200;

/// JavaScript `(h << 5) - h + charCodeAt(i) | 0` over UTF-16 code units.
#[must_use]
pub fn js_hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for unit in s.encode_utf16() {
        h = h.wrapping_shl(5).wrapping_sub(h).wrapping_add(i32::from(unit));
    }
    h
}

/// `Math.abs(h).toString(36)` — computed in i64 so `i32::MIN` does not overflow.
#[must_use]
pub fn hash_suffix(h: i32) -> String {
    let mut n = (i64::from(h)).abs();
    if n == 0 {
        return "0".to_string();
    }
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    while n > 0 {
        out.push(digits[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).expect("ascii")
}

/// The slug of an already-realpath'd, already-normalised path.
#[must_use]
pub fn slug_of(path: &str) -> String {
    let dashed: String = path
        .encode_utf16()
        .map(|u| match u {
            0x30..=0x39 | 0x41..=0x5a | 0x61..=0x7a => u as u8 as char,
            _ => '-',
        })
        .collect();
    if dashed.len() <= MAX_SLUG {
        return dashed;
    }
    format!("{}-{}", &dashed[..MAX_SLUG], hash_suffix(js_hash(path)))
}

/// NFC-normalise when `nfc` (the extension does so on macOS only).
#[must_use]
pub fn normalize_cwd(realpath: &str, nfc: bool) -> Cow<'_, str> {
    if nfc {
        Cow::Owned(realpath.nfc().collect())
    } else {
        Cow::Borrowed(realpath)
    }
}

/// What the extension does on this platform.
#[must_use]
pub fn extension_nfc_default() -> bool {
    cfg!(target_os = "macos")
}

/// `slug_of(normalize(realpath(cwd)))` — the directory name under `projects/`.
pub fn project_dir_name(cwd: &Path) -> std::io::Result<String> {
    let real = std::fs::canonicalize(cwd)?;
    let text = real.to_string_lossy();
    Ok(slug_of(&normalize_cwd(&text, extension_nfc_default())))
}

const RESERVED: [&str; 4] = ["con", "prn", "aux", "nul"];

/// `CLAUDE_CODE_PROJECT_DIR_NAME` is honoured only when `CLAUDE_CONFIG_DIR` is
/// set and the name is `^[A-Za-z0-9_-]{1,64}$` and not a Windows device name.
#[must_use]
pub fn override_dir_name(config_dir_set: bool, name: Option<&str>) -> Option<String> {
    if !config_dir_set {
        return None;
    }
    let name = name?;
    if name.is_empty() || name.len() > 64 {
        return None;
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if RESERVED.contains(&lower.as_str()) {
        return None;
    }
    if lower.len() == 4
        && (lower.starts_with("com") || lower.starts_with("lpt"))
        && lower.as_bytes()[3].is_ascii_digit()
    {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_hash_kats() {
        assert_eq!(js_hash(""), 0);
        assert_eq!(js_hash("a"), 97);
        assert_eq!(js_hash("ab"), 3105);
        assert_eq!(js_hash("Aa"), 2112);
        assert_eq!(js_hash("BB"), 2112);
        assert_eq!(js_hash("/Users/mike/x"), -1_029_733_291);
    }

    #[test]
    fn js_hash_i32_min_polygenelubricants() {
        assert_eq!(js_hash("polygenelubricants"), i32::MIN);
    }

    #[test]
    fn hash_suffix_i32_min_is_zik0zk() {
        assert_eq!(hash_suffix(i32::MIN), "zik0zk");
        assert_eq!(hash_suffix(0), "0");
        assert_eq!(hash_suffix(-389_221_465), "6fqd7d");
    }

    #[test]
    fn slug_this_repo() {
        assert_eq!(slug_of("/Users/mike/Documents/DeFi/ai-env"), "-Users-mike-Documents-DeFi-ai-env");
    }

    #[test]
    fn slug_217_chars_u3ctqq() {
        let p = format!("/Users/mike/Documents/{}/proj", "a".repeat(190));
        assert_eq!(p.len(), 217);
        assert_eq!(js_hash(&p), 1_819_622_546);
        let s = slug_of(&p);
        assert_eq!(s.len(), 207);
        assert!(s.starts_with("-Users-mike-Documents-aaaaaaaa"));
        assert!(s.ends_with("-u3ctqq"), "{s}");
        assert_eq!(&s[..MAX_SLUG], &format!("-Users-mike-Documents-{}", "a".repeat(178)));
    }

    #[test]
    fn slug_300_z_6fqd7d() {
        let p = format!("/tmp/{}", "z".repeat(300));
        let s = slug_of(&p);
        assert_eq!(s, format!("-tmp-{}-6fqd7d", "z".repeat(195)));
    }

    #[test]
    fn slug_219_polygene_nyc3pu() {
        let p = format!("/p/{}", "polygenelubricants".repeat(12));
        assert_eq!(p.len(), 219);
        assert_eq!(js_hash(&p), -1_448_393_682);
        assert!(slug_of(&p).ends_with("-nyc3pu"));
    }

    #[test]
    fn slug_nfc_vs_nfd_yoga() {
        let nfd = "/Users/mike/\u{0418}\u{0306}\u{043e}\u{0433}\u{0430}"; // Й as И + combining breve
        assert_eq!(slug_of(&normalize_cwd(nfd, true)), "-Users-mike-----");
        assert_eq!(slug_of(&normalize_cwd(nfd, false)), "-Users-mike------");
    }

    #[test]
    fn slug_astral_two_dashes() {
        assert_eq!(slug_of("/x/\u{1F600}"), "-x---");
    }

    #[test]
    fn override_kats() {
        assert_eq!(override_dir_name(false, Some("ok")), None);
        assert_eq!(override_dir_name(true, Some("my_proj-1")), Some("my_proj-1".to_string()));
        assert_eq!(override_dir_name(true, Some("con")), None);
        assert_eq!(override_dir_name(true, Some("COM1")), None);
        assert_eq!(override_dir_name(true, Some(&"a".repeat(65))), None);
        assert_eq!(override_dir_name(true, Some("has space")), None);
        assert_eq!(override_dir_name(true, None), None);
    }

    #[test]
    fn project_dir_name_canonicalises() {
        let dir = std::env::temp_dir();
        let name = project_dir_name(&dir).unwrap();
        assert!(name.starts_with('-'), "{name}");
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }
}
