//! Secrets in memory and in logs: a zeroizing wrapper whose `Debug` never
//! prints the value, plus a scrubber for anything that reaches a log line.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;
use std::io::Write;
use std::sync::{OnceLock, RwLock};
use zeroize::Zeroize;

/// Length of a secret payload, for the `[redacted:len=N]` rendering.
pub trait SecretLen {
    fn secret_len(&self) -> usize;
}
impl SecretLen for String {
    fn secret_len(&self) -> usize {
        self.len()
    }
}
impl SecretLen for Vec<u8> {
    fn secret_len(&self) -> usize {
        self.len()
    }
}
impl<const N: usize> SecretLen for [u8; N] {
    fn secret_len(&self) -> usize {
        N
    }
}

/// A value that is zeroized on drop and never rendered by `Debug`
/// (`[redacted:len=N]`). There is deliberately no `Display`.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(value: T) -> Self {
        Secret(value)
    }

    /// The only way to read the value; call sites are auditable by grep.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize + SecretLen> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted:len={}]", self.0.secret_len())
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Secret(self.0.clone())
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<T: Zeroize + Eq> Eq for Secret<T> {}

impl<T: Zeroize + Serialize> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de, T: Zeroize + Deserialize<'de>> Deserialize<'de> for Secret<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        T::deserialize(d).map(Secret)
    }
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

impl Secret<String> {
    /// Constant-time comparison against raw bytes (length leaks, content does not).
    #[must_use]
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        ct_eq_bytes(self.0.as_bytes(), other)
    }
}

impl Secret<Vec<u8>> {
    #[must_use]
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        ct_eq_bytes(&self.0, other)
    }
}

// ---- scrubber ---------------------------------------------------------------

fn registry() -> &'static RwLock<Vec<String>> {
    static REG: OnceLock<RwLock<Vec<String>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(Vec::new()))
}

/// Register a runtime value (a token, a session secret) so `scrub` masks it
/// wherever it appears. Values shorter than 8 bytes are ignored: masking them
/// would shred ordinary text.
pub fn register_secret(value: &str) {
    if value.len() < 8 {
        return;
    }
    let mut reg = registry().write().unwrap_or_else(|e| e.into_inner());
    if !reg.iter().any(|v| v == value) {
        reg.push(value.to_string());
        reg.sort_by_key(|v| std::cmp::Reverse(v.len()));
    }
}

/// Minimum length of an `eyJ…` token before it is treated as a JWE/JWT.
pub const JWE_MIN_LEN: usize = 200;

const KEY_NAMES: [&str; 6] =
    ["x-aws-proxy-auth", "authorization", "accesstoken", "git_config_value_", "oauth", "token"];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// Mask secrets in a log line: `sk-ant-…` tokens, `eyJ…` tokens of at least
/// [`JWE_MIN_LEN`] chars, registered values, and the values of key-shaped
/// assignments (`token=`, `Authorization:`, `x-aws-proxy-auth:`, …).
pub fn scrub(text: &str) -> Cow<'_, str> {
    let mut out = String::with_capacity(text.len());
    let mut changed = false;

    // Pass 1: registered values (longest first, so nested matches mask whole).
    let mut current: Cow<'_, str> = Cow::Borrowed(text);
    {
        let reg = registry().read().unwrap_or_else(|e| e.into_inner());
        for v in reg.iter() {
            if current.contains(v.as_str()) {
                current = Cow::Owned(current.replace(v.as_str(), &format!("[redacted:len={}]", v.len())));
                changed = true;
            }
        }
    }

    // Pass 2: token shapes and key-shaped assignments.
    let s: &str = &current;
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        if let Some(body) = rest.strip_prefix("sk-ant-") {
            let n = body.chars().take_while(|c| is_token_char(*c)).count();
            if n >= 8 {
                let total = 7 + body.chars().take(n).map(char::len_utf8).sum::<usize>();
                out.push_str(&format!("sk-ant-[redacted:len={total}]"));
                i += total;
                changed = true;
                continue;
            }
        }
        if rest.starts_with("eyJ") {
            let n: usize = rest.chars().take_while(|c| is_token_char(*c)).map(char::len_utf8).sum();
            if n >= JWE_MIN_LEN {
                out.push_str(&format!("eyJ[redacted:jwe:len={n}]"));
                i += n;
                changed = true;
                continue;
            }
        }
        // Key-shaped: `<name-containing-keyword> [=:] "?value` up to a delimiter.
        if let Some(value_start) = key_shaped(rest) {
            let value = &rest[value_start..];
            let vlen = value.find(['"', ',', '}', '\n', '\r']).unwrap_or(value.len());
            let raw = &value[..vlen];
            if !raw.trim().is_empty() {
                out.push_str(&rest[..value_start]);
                out.push_str(&format!("[redacted:len={}]", raw.len()));
                i += value_start + vlen;
                changed = true;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8().max(1);
    }

    if changed {
        Cow::Owned(out)
    } else {
        match current {
            Cow::Borrowed(_) => Cow::Borrowed(text),
            Cow::Owned(o) => Cow::Owned(o),
        }
    }
}

/// If `rest` starts with a key-shaped assignment whose key contains one of the
/// secret-bearing names, return the offset where the value starts.
fn key_shaped(rest: &str) -> Option<usize> {
    let key_len = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')).map(char::len_utf8).sum::<usize>();
    if key_len == 0 {
        return None;
    }
    let key = &rest[..key_len];
    let lower = key.to_ascii_lowercase();
    if !KEY_NAMES.iter().any(|k| lower.contains(k)) {
        return None;
    }
    // JSON keys are quoted: `"session_token":"…"` — skip the closing quote.
    let quote = usize::from(rest[key_len..].starts_with('"'));
    let after = &rest[key_len + quote..];
    let ws = after.chars().take_while(|c| *c == ' ' || *c == '\t').count();
    let after2 = &after[ws..];
    let sep = after2.chars().next()?;
    if sep != '=' && sep != ':' {
        return None;
    }
    let mut pos = key_len + quote + ws + 1;
    let tail = &rest[pos..];
    let ws2 = tail.chars().take_while(|c| *c == ' ' || *c == '\t').count();
    pos += ws2;
    if rest[pos..].starts_with('"') {
        pos += 1;
    }
    Some(pos)
}

/// `io::Write` adapter that scrubs each complete line before forwarding it.
pub struct ScrubWriter<W: Write> {
    inner: W,
    pending: Vec<u8>,
}

impl<W: Write> ScrubWriter<W> {
    pub fn new(inner: W) -> Self {
        ScrubWriter { inner, pending: Vec::new() }
    }

    fn flush_line(&mut self, line: &[u8]) -> std::io::Result<()> {
        let text = String::from_utf8_lossy(line);
        self.inner.write_all(scrub(&text).as_bytes())?;
        self.inner.write_all(b"\n")
    }
}

impl<W: Write> Write for ScrubWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while let Some(pos) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            self.flush_line(&line[..line.len() - 1])?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            let text = String::from_utf8_lossy(&line);
            self.inner.write_all(scrub(&text).as_bytes())?;
        }
        self.inner.flush()
    }
}

impl<W: Write> Drop for ScrubWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// `tracing_subscriber` `MakeWriter` wrapper: every writer it hands out scrubs.
pub struct ScrubMakeWriter<M>(pub M);

impl<'a, M> tracing_subscriber::fmt::MakeWriter<'a> for ScrubMakeWriter<M>
where
    M: tracing_subscriber::fmt::MakeWriter<'a>,
{
    type Writer = ScrubWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        ScrubWriter::new(self.0.make_writer())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted_len() {
        assert_eq!(format!("{:?}", Secret::new("abc".to_string())), "[redacted:len=3]");
        assert_eq!(format!("{:?}", Secret::new(vec![1u8, 2, 3, 4])), "[redacted:len=4]");
        assert_eq!(format!("{:?}", Secret::new([0u8; 32])), "[redacted:len=32]");
    }

    #[test]
    fn secret_serializes_transparently() {
        let s = Secret::new("tok".to_string());
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"tok\"");
        let back: Secret<String> = serde_json::from_str("\"tok\"").unwrap();
        assert!(back.ct_eq(b"tok"));
        assert!(!back.ct_eq(b"tok2"));
    }

    #[test]
    fn scrub_sk_ant() {
        let line = "unseal token sk-ant-oat01-SECRETSECRETSECRET done";
        let out = scrub(line);
        assert!(!out.contains("SECRETSECRET"), "{out}");
        assert!(out.contains("sk-ant-[redacted:len="), "{out}");
        assert!(out.ends_with(" done"), "{out}");
    }

    #[test]
    fn scrub_eyj_ge_200_only() {
        let short = format!("eyJ{}", "a".repeat(196)); // 199 chars total
        assert_eq!(scrub(&short), short);
        let long = format!("eyJ{}", "a".repeat(197)); // 200 chars total
        let out = scrub(&long);
        assert_eq!(out, "eyJ[redacted:jwe:len=200]");
        let line = format!("x-aws-proxy-auth: {long} port 8080");
        let out = scrub(&line);
        assert!(!out.contains("aaaaaaaa"), "{out}");
    }

    #[test]
    fn scrub_registered_value() {
        register_secret("hunter2-super-secret");
        let out = scrub("value=hunter2-super-secret;");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("[redacted:len=20]"), "{out}");
        register_secret("short"); // ignored (< 8)
        assert_eq!(scrub("short text"), "short text");
    }

    #[test]
    fn scrub_key_shaped_names() {
        let cases = [
            ("session_token=abcdef0123456789", "abcdef0123456789"),
            ("Authorization: Bearer xyz.123", "xyz.123"),
            ("x-aws-proxy-auth: not-a-jwe-but-secret", "not-a-jwe-but-secret"),
            ("GIT_CONFIG_VALUE_0=http.extraHeader=Authorization: Basic abc", "Basic abc"),
            ("{\"session_token\":\"c2Vj\",\"client\":\"x\"}", "c2Vj"),
        ];
        for (line, secret) in cases {
            let out = scrub(line);
            assert!(!out.contains(secret), "{line} -> {out}");
            assert!(out.contains("[redacted:len="), "{line} -> {out}");
        }
        assert_eq!(scrub("port=8080 owner=mike"), "port=8080 owner=mike");
    }

    #[test]
    fn scrub_writer_masks_per_line() {
        let mut sink = Vec::new();
        {
            let mut w = ScrubWriter::new(&mut sink);
            w.write_all(b"ok line\ntoken=abcdefgh1234\npartial").unwrap();
            w.flush().unwrap();
        }
        let text = String::from_utf8(sink).unwrap();
        assert!(text.starts_with("ok line\n"));
        assert!(!text.contains("abcdefgh1234"), "{text}");
        assert!(text.ends_with("partial"), "{text}");
    }
}
