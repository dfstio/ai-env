//! `image/claude.lock` — the Claude binary the VM image pins, as shell-
//! sourceable `KEY=VALUE` lines (the Dockerfile sources it; the shim's
//! `/validate` and the Mac's `ai-env infra pin` parse it here, so both sides
//! read one format). Values are restricted to `[A-Za-z0-9._:-]`: nothing a
//! shell could expand, quote or split.

/// Where release artefacts live; `<base>/<version>/manifest.json` and
/// `<base>/<version>/<platform>/claude`.
pub const RELEASE_BASE: &str = "https://downloads.claude.ai/claude-code-releases";

/// The only platform the image runs on.
pub const PLATFORM: &str = "linux-arm64";

/// S11 (A.1): the primary-key fingerprint of Anthropic's Claude Code release key (`CLAUDE_GPG_FPR`, Makefile:83;
/// the vendored `certs/claude-code-release.gpg`): an admitted manifest's VALIDSIG ends in it.
pub const RELEASE_KEY_FPR: &str = "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE";

/// `<RELEASE_BASE>/<version>/manifest.json`.
#[must_use]
pub fn manifest_url(version: &str) -> String {
    format!("{RELEASE_BASE}/{version}/manifest.json")
}

/// `<RELEASE_BASE>/<version>/manifest.json.sig`.
#[must_use]
pub fn sig_url(version: &str) -> String {
    format!("{RELEASE_BASE}/{version}/manifest.json.sig")
}

/// `<RELEASE_BASE>/<version>/<PLATFORM>/claude`; [`ClaudePin::download_url`] calls it (S11, LD-18).
#[must_use]
pub fn binary_url(version: &str) -> String {
    format!("{RELEASE_BASE}/{version}/{PLATFORM}/claude")
}

const KEYS: [&str; 5] = ["CLAUDE_VERSION", "CLAUDE_PLATFORM", "CLAUDE_SHA256", "CLAUDE_SIZE", "CLAUDE_BUILD_DATE"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudePin {
    pub version: String,
    pub platform: String,
    /// Lowercase hex SHA-256 of the binary (a public release checksum).
    pub sha256: String,
    pub size: u64,
    /// RFC 3339 UTC, from the release manifest.
    pub build_date: String,
}

impl ClaudePin {
    /// `<base>/<version>/<platform>/claude` ([`binary_url`]: a valid pin's platform is [`PLATFORM`]).
    #[must_use]
    pub fn download_url(&self) -> String {
        binary_url(&self.version)
    }

    /// What `claude --version` prints for this pin.
    #[must_use]
    pub fn version_line(&self) -> String {
        format!("{} (Claude Code)", self.version)
    }

    /// Field checks shared by the parser and [`render_lock`].
    pub fn validate(&self) -> Result<(), String> {
        if !is_version(&self.version) {
            return Err(format!("CLAUDE_VERSION {:?} is not MAJOR.MINOR.PATCH", self.version));
        }
        if self.platform != PLATFORM {
            return Err(format!("CLAUDE_PLATFORM {:?} is not {PLATFORM}", self.platform));
        }
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err("CLAUDE_SHA256 is not 64 lowercase hex digits".into());
        }
        if self.size == 0 {
            return Err("CLAUDE_SIZE is 0".into());
        }
        if crate::wire::time::parse_rfc3339_utc(&self.build_date).is_none() {
            return Err(format!("CLAUDE_BUILD_DATE {:?} is not RFC 3339 UTC", self.build_date));
        }
        Ok(())
    }
}

/// `N.N.N`, each part 1 to 6 digits (S11: `pub`, for `wire::s3`'s claude key and the admission).
#[must_use]
pub fn is_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.len() <= 6 && p.bytes().all(|c| c.is_ascii_digit()))
}

fn safe_value(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

/// Parse a lock file: blank lines and `#` comments are ignored; every one of
/// the five keys must appear exactly once; nothing else is allowed. Strict
/// where the other readers differ: the Dockerfile's `.` would keep a CR in
/// the value, and the Makefile's `sed 's/^CLAUDE_VERSION=//p'` misses an
/// indented line and keeps trailing blanks — so a CR anywhere, and leading
/// or trailing whitespace on a key line, are refused rather than trimmed.
pub fn parse_lock(text: &str) -> Result<ClaudePin, String> {
    if text.contains('\r') {
        return Err("the lock has a carriage return (CRLF line endings?); it must be LF-only (the Dockerfile sources it)".into());
    }
    let mut vals: [Option<String>; 5] = Default::default();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if line != line.trim() {
            return Err(format!("line {}: leading or trailing whitespace (the Makefile reads ^CLAUDE_VERSION= literally)", n + 1));
        }
        let (k, v) = line.split_once('=').ok_or_else(|| format!("line {}: expected KEY=VALUE", n + 1))?;
        let i = KEYS.iter().position(|key| *key == k).ok_or_else(|| format!("line {}: unknown key {k:?}", n + 1))?;
        if !safe_value(v) {
            return Err(format!("line {}: {k} has characters outside [A-Za-z0-9._:-]", n + 1));
        }
        if vals[i].replace(v.to_string()).is_some() {
            return Err(format!("line {}: {k} appears twice", n + 1));
        }
    }
    let mut it = vals.into_iter().zip(KEYS);
    let mut take = || {
        let (v, k) = it.next().expect("five keys");
        v.ok_or_else(|| format!("{k} is missing"))
    };
    let (version, platform, sha256, size, build_date) = (take()?, take()?, take()?, take()?, take()?);
    let size: u64 = size.parse().map_err(|_| format!("CLAUDE_SIZE {size:?} is not a byte count"))?;
    let pin = ClaudePin { version, platform, sha256, size, build_date };
    pin.validate()?;
    Ok(pin)
}

/// The lock file text for `pin` (validated first), with a header naming its
/// source so a reviewer knows what to compare against.
pub fn render_lock(pin: &ClaudePin) -> Result<String, String> {
    pin.validate()?;
    Ok(format!(
        "# Claude Code binary baked into the MicroVM image. Written by `make claude-pin`\n\
         # from {RELEASE_BASE}/{v}/manifest.json;\n\
         # the Dockerfile verifies size and SHA-256, then `claude --version`.\n\
         CLAUDE_VERSION={v}\nCLAUDE_PLATFORM={p}\nCLAUDE_SHA256={s}\nCLAUDE_SIZE={z}\nCLAUDE_BUILD_DATE={d}\n",
        v = pin.version,
        p = pin.platform,
        s = pin.sha256,
        z = pin.size,
        d = pin.build_date,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid pin; the checksum is built at runtime (no hex
    /// literal that looks like a secret in the tree).
    fn pin() -> ClaudePin {
        ClaudePin {
            version: "2.1.283".into(),
            platform: PLATFORM.into(),
            sha256: "0a".repeat(32),
            size: 240_902_136,
            build_date: "2026-09-25T01:39:37Z".into(),
        }
    }

    #[test]
    fn render_then_parse_round_trips() {
        let text = render_lock(&pin()).unwrap();
        assert!(text.starts_with("# Claude Code binary"), "{text}");
        assert!(text.contains("CLAUDE_SIZE=240902136\n"), "{text}");
        assert_eq!(parse_lock(&text).unwrap(), pin());
    }

    #[test]
    fn urls_and_version_line() {
        let p = pin();
        assert_eq!(p.download_url(), "https://downloads.claude.ai/claude-code-releases/2.1.283/linux-arm64/claude");
        assert_eq!(p.version_line(), "2.1.283 (Claude Code)");
    }

    #[test]
    fn parse_refuses_missing_duplicate_unknown_and_unsafe() {
        let good = render_lock(&pin()).unwrap();
        let drop = |k: &str| good.lines().filter(|l| !l.starts_with(k)).collect::<Vec<_>>().join("\n");
        for k in KEYS {
            let e = parse_lock(&drop(k)).unwrap_err();
            assert!(e.contains(k) && e.contains("missing"), "{k}: {e}");
        }
        assert!(parse_lock(&format!("{good}CLAUDE_SIZE=1\n")).unwrap_err().contains("twice"));
        assert!(parse_lock(&format!("{good}EXTRA=1\n")).unwrap_err().contains("unknown key"));
        assert!(parse_lock(&format!("{good}garbage\n")).unwrap_err().contains("KEY=VALUE"));
        for bad in ["2.1.283;rm", "2.1.283 x", "$(id)", "\"2.1.283\"", ""] {
            let text = good.replace("CLAUDE_VERSION=2.1.283", &format!("CLAUDE_VERSION={bad}"));
            assert!(parse_lock(&text).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn validate_checks_each_field() {
        let cases: [(ClaudePin, &str); 6] = [
            (ClaudePin { version: "2.1".into(), ..pin() }, "CLAUDE_VERSION"),
            (ClaudePin { platform: "linux-x64".into(), ..pin() }, "CLAUDE_PLATFORM"),
            (ClaudePin { sha256: "0A".repeat(32), ..pin() }, "CLAUDE_SHA256"),
            (ClaudePin { sha256: "0a".repeat(31), ..pin() }, "CLAUDE_SHA256"),
            (ClaudePin { size: 0, ..pin() }, "CLAUDE_SIZE"),
            (ClaudePin { build_date: "2026-09-25".into(), ..pin() }, "CLAUDE_BUILD_DATE"),
        ];
        for (p, key) in cases {
            let e = p.validate().unwrap_err();
            assert!(e.contains(key), "{key}: {e}");
            assert!(render_lock(&p).is_err());
        }
    }

    #[test]
    fn comments_and_blank_lines_are_tolerated() {
        let text = render_lock(&pin()).unwrap();
        assert_eq!(parse_lock(&format!("\n# note\n  # indented note\n \t\n{text}\n")).unwrap(), pin());
    }

    /// The repository's file at `rel` (from the workspace root).
    fn repo_file(rel: &str) -> String {
        std::fs::read_to_string(format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// S11 (A §1.8): the fingerprint is the Makefile's `CLAUDE_GPG_FPR`
    /// (which `claude-pin` and P4 name), 40 uppercase hex digits.
    #[test]
    fn the_release_key_fingerprint_is_the_makefiles() {
        let make = repo_file("Makefile");
        let line = make.lines().find(|l| l.starts_with("CLAUDE_GPG_FPR ")).expect("the Makefile's CLAUDE_GPG_FPR line");
        let value = line.split_once('=').map(|(_, v)| v.trim()).unwrap_or_default();
        assert_eq!(value, RELEASE_KEY_FPR, "{line}");
        assert!(RELEASE_KEY_FPR.len() == 40 && RELEASE_KEY_FPR.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)));
    }

    /// S11 (A §1.8): `RELEASE_BASE` is the Makefile's `CLAUDE_RELEASES`;
    /// `binary_url` is the Dockerfile's download URL with its two variables
    /// filled; the manifest's and its signature's URLs sit beside it; a pin's
    /// `download_url` delegates.
    #[test]
    fn the_release_urls_are_the_makefiles() {
        let make = repo_file("Makefile");
        let line = make.lines().find(|l| l.starts_with("CLAUDE_RELEASES ")).expect("the Makefile's CLAUDE_RELEASES line");
        assert_eq!(line.split_once('=').map(|(_, v)| v.trim()), Some(RELEASE_BASE), "{line}");
        let docker = repo_file("image/Dockerfile");
        let url = docker.lines().find_map(|l| l.split('"').find(|part| part.starts_with("https://") && part.ends_with("/claude"))).expect("the Dockerfile's download URL");
        assert_eq!(url, "https://downloads.claude.ai/claude-code-releases/${CLAUDE_VERSION}/${CLAUDE_PLATFORM}/claude");
        assert_eq!(binary_url("2.1.308"), url.replace("${CLAUDE_VERSION}", "2.1.308").replace("${CLAUDE_PLATFORM}", PLATFORM));
        assert_eq!(manifest_url("2.1.308"), format!("{RELEASE_BASE}/2.1.308/manifest.json"));
        assert_eq!(sig_url("2.1.308"), format!("{}.sig", manifest_url("2.1.308")));
        assert_eq!(pin().download_url(), binary_url(&pin().version));
        assert!(is_version("2.1.308") && !is_version("2.1") && !is_version("2.1.308-beta"));
    }

    /// What the shell `.` or the Makefile's anchored sed would read
    /// differently is refused, not trimmed.
    #[test]
    fn crlf_and_padded_key_lines_are_refused() {
        let good = render_lock(&pin()).unwrap();
        let cases = [
            (good.replace('\n', "\r\n"), "carriage return"),
            (good.replace("CLAUDE_BUILD_DATE=2026-09-25T01:39:37Z\n", "CLAUDE_BUILD_DATE=2026-09-25T01:39:37Z\r\n"), "carriage return"),
            (good.replace("CLAUDE_VERSION=", "  CLAUDE_VERSION="), "whitespace"),
            (good.replace("CLAUDE_VERSION=", "\tCLAUDE_VERSION="), "whitespace"),
            (good.replace("CLAUDE_VERSION=2.1.283", "CLAUDE_VERSION=2.1.283 "), "whitespace"),
            (good.replace("CLAUDE_VERSION=2.1.283", "CLAUDE_VERSION=2.1.283\t"), "whitespace"),
        ];
        for (text, want) in cases {
            let e = parse_lock(&text).unwrap_err();
            assert!(e.contains(want), "{want}: {e}");
        }
    }
}
