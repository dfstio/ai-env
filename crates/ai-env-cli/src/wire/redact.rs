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

/// A registered value and how many holders registered it.
type Registered = (zeroize::Zeroizing<String>, usize);

/// The registered values, each with how many holders registered it. A value
/// is masked until its last holder forgets it, and its copy is zeroized then
/// (S7: a setup-token's registration ends with its handle, so the registry
/// never outlives it as a plain copy); one nobody forgets (a session token)
/// stays for the life of the process.
fn registry() -> &'static RwLock<Vec<Registered>> {
    static REG: OnceLock<RwLock<Vec<Registered>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(Vec::new()))
}

/// Register a runtime value (a token, a session secret) so `scrub` masks it
/// wherever it appears, once more per call: two holders of one value each
/// forget it, and the masking lasts until both have. Values shorter than 8
/// bytes are ignored: masking them would shred ordinary text.
pub fn register_secret(value: &str) {
    if value.len() < 8 {
        return;
    }
    let mut reg = registry().write().unwrap_or_else(|e| e.into_inner());
    match reg.iter_mut().find(|(v, _)| v.as_str() == value) {
        Some((_, holders)) => *holders = holders.saturating_add(1),
        None => {
            reg.push((zeroize::Zeroizing::new(value.to_string()), 1));
            reg.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
        }
    }
}

/// One holder of `value` is done with it: when it was the last, `scrub`
/// stops masking it and the registry's copy is zeroized. Whether it was
/// registered.
pub fn forget_secret(value: &str) -> bool {
    let mut reg = registry().write().unwrap_or_else(|e| e.into_inner());
    let Some(i) = reg.iter().position(|(v, _)| v.as_str() == value) else { return false };
    reg[i].1 -= 1;
    if reg[i].1 == 0 {
        reg.remove(i);
    }
    true
}

/// Minimum length of an `eyJ…` token before it is treated as a JWE/JWT.
pub const JWE_MIN_LEN: usize = 200;

const KEY_NAMES: [&str; 7] =
    ["x-aws-proxy-auth", "authorization", "accesstoken", "git_config_value_", "oauth", "token", "secret"];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// Bytes that make up a key name (`session_token`, `x-aws-proxy-auth`, …).
fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Mask secrets in a log line: `sk-ant-…` tokens, `eyJ…` tokens of at least
/// [`JWE_MIN_LEN`] chars, AWS access key ids (`AKIA…`/`ASIA…`), registered
/// values, and the values of key-shaped assignments (`token=`,
/// `Authorization:`, `x-aws-proxy-auth:`, …).
pub fn scrub(text: &str) -> Cow<'_, str> {
    let mut out = String::with_capacity(text.len());
    let mut changed = false;

    // Pass 1: registered values (longest first, so nested matches mask whole).
    let mut current: Cow<'_, str> = Cow::Borrowed(text);
    {
        let reg = registry().read().unwrap_or_else(|e| e.into_inner());
        for (v, _) in reg.iter() {
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
        // AWS access key ids (`AKIA…` long-term, `ASIA…` session): 4 + 16 of
        // `[A-Z0-9]`, not glued to a longer identifier on either side.
        if (rest.starts_with("AKIA") || rest.starts_with("ASIA")) && (i == 0 || !s.as_bytes()[i - 1].is_ascii_alphanumeric()) {
            let b = rest.as_bytes();
            let body_ok = b.len() >= 20 && b[4..20].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
            if body_ok && b.get(20).is_none_or(|c| !c.is_ascii_alphanumeric()) {
                out.push_str(&rest[..4]);
                out.push_str("[redacted:len=20]");
                i += 20;
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
        // Only tried where a key name can start (offset 0 or after a non-identifier
        // byte): a key found mid-identifier would already have matched at its start,
        // and scanning the identifier from every offset is quadratic on long lines.
        let at_ident_start = i == 0 || !is_ident_char(s.as_bytes()[i - 1]);
        if at_ident_start {
            if let Some(m) = key_shaped(rest) {
                let value = &rest[m.value_start..];
                // A quoted value ends at its closing quote; a header value runs to the end of
                // the line (it may hold `,`); a bare `k=v` stops at the next list delimiter.
                let stops: &[char] = if m.quoted || m.header { &['"', '\n', '\r'] } else { &['"', ',', '}', '\n', '\r'] };
                let vlen = value.find(stops).unwrap_or(value.len());
                let raw = &value[..vlen];
                if !raw.trim().is_empty() {
                    out.push_str(&rest[..m.value_start]);
                    out.push_str(&format!("[redacted:len={}]", raw.len()));
                    i += m.value_start + vlen;
                    changed = true;
                    continue;
                }
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

/// A key-shaped assignment found at the start of a slice by [`key_shaped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyMatch {
    /// Offset of the first byte of the secret value: past the separator, the
    /// surrounding whitespace, an opening `"` and a visible auth scheme.
    value_start: usize,
    /// The value opened with `"` (`"token": "…"`), so it ends at the closing
    /// quote rather than at the first `,` or `}`.
    quoted: bool,
    /// HTTP header form `Name: value` (bare key, colon separator): an
    /// `Authorization: Bearer …` / `Basic …` scheme is kept visible, only the
    /// credential after it is masked, and the value runs to the end of the
    /// line (header values may contain `,`).
    header: bool,
}

/// Auth schemes left visible in a header value; the credential follows them.
const AUTH_SCHEMES: [&str; 2] = ["bearer", "basic"];

fn ws_len(s: &str) -> usize {
    s.bytes().take_while(|b| *b == b' ' || *b == b'\t').count()
}

/// If `rest` starts with a key-shaped assignment whose key contains one of the
/// secret-bearing names, describe where its value starts. Forms recognised:
/// `token=abc`, `token: abc`, JSON `"token": "abc"`, and the HTTP headers
/// `Authorization: Bearer abc` / `x-aws-proxy-auth: abc`.
fn key_shaped(rest: &str) -> Option<KeyMatch> {
    let key_len = rest.bytes().take_while(|b| is_ident_char(*b)).count();
    if key_len == 0 {
        return None;
    }
    let lower = rest[..key_len].to_ascii_lowercase();
    if !KEY_NAMES.iter().any(|k| lower.contains(k)) {
        return None;
    }
    // JSON keys are quoted: `"session_token":"…"` — skip the closing quote.
    let json_key = rest[key_len..].starts_with('"');
    let mut pos = key_len + usize::from(json_key);
    pos += ws_len(&rest[pos..]);
    let sep = rest[pos..].chars().next()?;
    if sep != '=' && sep != ':' {
        return None;
    }
    pos += 1;
    pos += ws_len(&rest[pos..]);
    let quoted = rest[pos..].starts_with('"');
    if quoted {
        pos += 1;
    }
    let header = sep == ':' && !json_key;
    if header {
        // `Authorization: Bearer <cred>`: keep the scheme, mask the credential.
        let tail = rest.as_bytes().get(pos..).unwrap_or_default();
        for scheme in AUTH_SCHEMES {
            let n = scheme.len();
            let followed_by_ws = matches!(tail.get(n), Some(b' ' | b'\t'));
            if followed_by_ws && tail[..n].eq_ignore_ascii_case(scheme.as_bytes()) {
                pos += n;
                pos += ws_len(&rest[pos..]);
                break;
            }
        }
    }
    Some(KeyMatch { value_start: pos, quoted, header })
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
    fn aws_access_key_ids_are_masked_unregistered() {
        let long = format!("AKIA{}", "Q7".repeat(8));
        let session = format!("ASIA{}", "Z9".repeat(8));
        let line = format!("access_key_id: \"{long}\", other={session} end");
        let out = scrub(&line);
        assert!(!out.contains(&long[4..]) && !out.contains(&session[4..]), "{out}");
        assert!(out.contains("AKIA[redacted:len=20]") && out.contains("ASIA[redacted:len=20]"), "{out}");
        for keep in [format!("XAKIA{}", "Q7".repeat(8)), format!("AKIA{}X", "Q7".repeat(8)), format!("AKIA{}", "q7".repeat(8)), "AKIA-short".to_string()] {
            assert_eq!(scrub(&keep), keep, "not a standalone key id: {keep}");
        }
    }

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
        let tok = format!("sk-ant-oat01-{}", "X".repeat(20));
        let line = format!("unseal token {tok} done");
        let out = scrub(&line);
        assert!(!out.contains("XXXXXXXX"), "{out}");
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

    /// S7: a forgotten value is masked no more and its registry copy is gone.
    #[test]
    fn forget_secret_ends_the_masking() {
        let value = format!("forgettable-{}", "Q".repeat(12));
        register_secret(&value);
        assert!(!scrub(&format!("x {value} y")).contains(&value));
        assert!(forget_secret(&value));
        assert_eq!(scrub(&format!("x {value} y")), format!("x {value} y"));
        assert!(!forget_secret(&value), "already forgotten");
    }

    /// S7: a value two holders registered stays masked until both forgot it,
    /// so one holder's end never unmasks it for another.
    #[test]
    fn a_value_is_forgotten_with_its_last_holder() {
        let value = format!("held-twice-{}", "R".repeat(12));
        let masked = || !scrub(&format!("x {value} y")).contains(&value);
        register_secret(&value);
        register_secret(&value);
        assert!(forget_secret(&value) && masked(), "one holder left: still masked");
        assert!(forget_secret(&value) && !masked(), "the last holder is gone: masked no more");
        assert!(!forget_secret(&value), "its copy is gone");
    }

    #[test]
    fn scrub_key_shaped_names() {
        // Built at runtime so no `token=<16+ chars>` literal sits in the source.
        let fake = format!("FAKEFAKE{}", "12345678");
        let session = format!("session_token={fake}");
        let cases = [
            (session.as_str(), fake.as_str()),
            ("Authorization: Bearer xyz.123", "xyz.123"),
            ("x-aws-proxy-auth: not-a-jwe-but-secret", "not-a-jwe-but-secret"),
            ("GIT_CONFIG_VALUE_0=http.extraHeader=Authorization: Basic abc", "Basic abc"),
            ("{\"session_token\":\"fakevalue\",\"client\":\"x\"}", "fakevalue"),
        ];
        for (line, secret) in cases {
            let out = scrub(line);
            assert!(!out.contains(secret), "{line} -> {out}");
            assert!(out.contains("[redacted:len="), "{line} -> {out}");
        }
        assert_eq!(scrub("port=8080 owner=mike"), "port=8080 owner=mike");
    }

    /// S7: a `secret` key is masked too: the credential frame's JSON form and
    /// an assignment, whatever the value's shape.
    #[test]
    fn scrub_a_secret_key() {
        let value = format!("v{}", "9".repeat(20));
        for line in [format!("{{\"t\":\"credential\",\"name\":\"X\",\"secret\":\"{value}\"}}"), format!("client_secret={value}")] {
            let out = scrub(&line);
            assert!(!out.contains(&value) && out.contains("[redacted:len="), "{line} -> {out}");
        }
    }

    #[test]
    fn scrub_form_key_equals_value() {
        // A bare `k=v` value runs to the next list delimiter, not to whitespace.
        assert_eq!(scrub("token=abc12345 next=1"), "token=[redacted:len=15]");
        assert_eq!(scrub("token=abc12345,next=1"), "token=[redacted:len=8],next=1");
    }

    #[test]
    fn scrub_form_key_colon_value() {
        assert_eq!(scrub("token: abc12345"), "token: [redacted:len=8]");
        assert_eq!(scrub("token:abc12345\nnext"), "token:[redacted:len=8]\nnext");
    }

    #[test]
    fn scrub_form_json_quoted() {
        assert_eq!(scrub("{\"token\": \"abc12345\", \"n\": 1}"), "{\"token\": \"[redacted:len=8]\", \"n\": 1}");
        // A quoted value keeps going past `,` and `}` up to its closing quote.
        assert_eq!(scrub("{\"token\":\"a,b}c\"}"), "{\"token\":\"[redacted:len=5]\"}");
        // A quoted JSON key is not a header: `Bearer` stays inside the masked value.
        assert_eq!(scrub("{\"authorization\":\"Bearer abc\"}"), "{\"authorization\":\"[redacted:len=10]\"}");
    }

    #[test]
    fn scrub_form_authorization_bearer_header() {
        assert_eq!(scrub("Authorization: Bearer abc12345"), "Authorization: Bearer [redacted:len=8]");
        assert_eq!(scrub("authorization: bearer abc12345"), "authorization: bearer [redacted:len=8]");
        assert_eq!(scrub("Authorization: Basic abc123"), "Authorization: Basic [redacted:len=6]");
        // A bare scheme with nothing after it is left alone (nothing to mask).
        assert_eq!(scrub("Authorization: Bearer "), "Authorization: Bearer ");
        // Header values run to the end of the line.
        assert_eq!(scrub("Authorization: Bearer a, b\nok"), "Authorization: Bearer [redacted:len=4]\nok");
    }

    #[test]
    fn scrub_form_x_aws_proxy_auth_header() {
        assert_eq!(scrub("x-aws-proxy-auth: abc12345"), "x-aws-proxy-auth: [redacted:len=8]");
        assert_eq!(scrub("X-Aws-Proxy-Auth:\tabc12345\r"), "X-Aws-Proxy-Auth:\t[redacted:len=8]\r");
    }

    #[test]
    fn scrub_key_only_matched_at_identifier_start() {
        // `mytoken` matches at its start; the `token` inside it is never re-scanned.
        assert_eq!(scrub("mytoken=abc12345"), "mytoken=[redacted:len=8]");
        // A key after a non-identifier byte is still found.
        assert_eq!(scrub("cfg.token=abc12345"), "cfg.token=[redacted:len=8]");
        assert_eq!(scrub("(token=abc12345)"), "(token=[redacted:len=9]");
        // Non-matching keys are untouched.
        assert_eq!(scrub("tokens_per_second=8080 owner=mike"), "tokens_per_second=[redacted:len=15]");
        assert_eq!(scrub("port=8080 owner=mike token"), "port=8080 owner=mike token");
    }

    #[test]
    fn scrub_64k_line_without_secrets_is_fast() {
        let line = "abcdefgh".repeat(8192);
        assert_eq!(line.len(), 64 * 1024);
        let t = std::time::Instant::now();
        let out = scrub(&line);
        let took = t.elapsed();
        assert_eq!(out, line);
        assert!(took < std::time::Duration::from_millis(500), "scrub took {took:?}");
    }

    #[test]
    fn scrub_64k_line_with_registered_secret_is_fast() {
        let secret = format!("perf-secret-{}", "Z".repeat(20));
        register_secret(&secret);
        let half = "abcdefgh".repeat(4096);
        let line = format!("{half}{secret}{half}");
        assert!(line.len() > 64 * 1024);
        let t = std::time::Instant::now();
        let out = scrub(&line);
        let took = t.elapsed();
        assert!(!out.contains("ZZZZZZZZ"), "secret leaked");
        assert!(out.contains(&format!("[redacted:len={}]", secret.len())), "{}", &out[half.len() - 8..half.len() + 40]);
        assert!(took < std::time::Duration::from_millis(500), "scrub took {took:?}");
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
