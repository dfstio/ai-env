//! Redaction (plans/s13-contracts.md §P-proto-sdk.6.9, P-R65 to P-R74): hand-written scanners, no regex
//! crate (LD-P5). A mask is `[redacted:<rule name>]` and carries no length (LD-P6).

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

/// One built-in rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Rule {
    /// ANSI escape sequences, removed (P-R66).
    Ansi,
    /// PEM blocks (P-R67).
    Pem,
    /// JWT-shaped runs (P-R68).
    Jwt,
    /// `Bearer <token>` (P-R69).
    Bearer,
    /// A password in a URL's userinfo (P-R70).
    Dsn,
    /// 64 hex characters (P-R71).
    Hex64,
}

impl Rule {
    /// Every rule, in the order `Redactor::redact` applies them: ANSI first (P-R72).
    pub const ALL: [Rule; 6] = [Rule::Ansi, Rule::Pem, Rule::Jwt, Rule::Bearer, Rule::Dsn, Rule::Hex64];

    /// `ansi`, `pem`, `jwt`, `bearer`, `dsn`, `hex64`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Rule::Ansi => "ansi",
            Rule::Pem => "pem",
            Rule::Jwt => "jwt",
            Rule::Bearer => "bearer",
            Rule::Dsn => "dsn",
            Rule::Hex64 => "hex64",
        }
    }

    /// The rule's function below.
    #[must_use]
    pub fn apply(self, text: &str) -> Cow<'_, str> {
        match self {
            Rule::Ansi => strip_ansi(text),
            Rule::Pem => mask_pem(text),
            Rule::Jwt => mask_jwt(text),
            Rule::Bearer => mask_bearer(text),
            Rule::Dsn => mask_dsn(text),
            Rule::Hex64 => mask_hex64(text),
        }
    }
}

/// Removes ANSI escape sequences (P-R66): a CSI (`ESC [`, parameters, intermediates, one final), an OSC
/// (`ESC ]` through BEL or `ESC \`), `ESC` and one of U+0040 to U+005F, and a lone ESC. An unterminated CSI or
/// OSC goes to the end of the text; a CSI broken by another character goes up to that character.
#[must_use]
pub fn strip_ansi(text: &str) -> Cow<'_, str> {
    let b = text.as_bytes();
    let mut out = Edits::new(text);
    let mut i = 0;
    while let Some(off) = b[i..].iter().position(|&c| c == ESC) {
        let start = i + off;
        let end = ansi_end(b, start);
        out.replace(start, end, "");
        i = end;
    }
    out.finish()
}

/// Masks PEM blocks as `[redacted:pem]` (P-R67): from a BEGIN marker through the next END marker; with no END
/// after it, over the body that follows (base64, blanks, line breaks, JSON's `\n` and `\r`, armor header lines)
/// and no further.
#[must_use]
pub fn mask_pem(text: &str) -> Cow<'_, str> {
    pem(text).0
}

/// Masks JWT-shaped runs as `[redacted:jwt]` (P-R68): `eyJ` at a boundary, then token characters and dots,
/// at least two dots and 16 characters in all.
#[must_use]
pub fn mask_jwt(text: &str) -> Cow<'_, str> {
    let b = text.as_bytes();
    let mut out = Edits::new(text);
    let mut i = 0;
    while let Some(off) = text[i..].find("eyJ") {
        let start = i + off;
        let glued = start > 0 && (is_token_byte(b[start - 1]) || b[start - 1] == b'.');
        let end = start + b[start..].iter().take_while(|&&c| is_token_byte(c) || c == b'.').count();
        let dots = b[start..end].iter().filter(|&&c| c == b'.').count();
        if !glued && dots >= 2 && end - start >= JWT_MIN {
            out.replace(start, end, "[redacted:jwt]");
        }
        // An `eyJ` later in this run is glued to it.
        i = end;
    }
    out.finish()
}

/// Masks a Bearer token as `[redacted:bearer]`, keeping the scheme word and the blanks (P-R69): a token of at
/// least 8 of `[A-Za-z0-9._~+/=-]` holding a character that is not an ASCII letter.
#[must_use]
pub fn mask_bearer(text: &str) -> Cow<'_, str> {
    let b = text.as_bytes();
    let mut out = Edits::new(text);
    let mut i = 0;
    while let Some(off) = b[i..].windows(BEARER.len()).position(|w| w.eq_ignore_ascii_case(BEARER)) {
        let start = i + off;
        i = start + 1;
        if start > 0 && is_word_byte(b[start - 1]) {
            continue;
        }
        let token_start = start + BEARER.len() + b[start + BEARER.len()..].iter().take_while(|&&c| c == b' ' || c == b'\t').count();
        if token_start == start + BEARER.len() {
            continue;
        }
        let token_end = token_start + b[token_start..].iter().take_while(|&&c| is_bearer_byte(c)).count();
        let token = &b[token_start..token_end];
        if token.len() >= BEARER_TOKEN_MIN && token.iter().any(|c| !c.is_ascii_alphabetic()) {
            out.replace(token_start, token_end, "[redacted:bearer]");
            i = token_end;
        }
    }
    out.finish()
}

/// Masks a URL userinfo's password as `[redacted:dsn]` (P-R70): at a `://` after a scheme, the authority runs to
/// the first `/`, `?`, `#`, blank, line break, quote, `<` or `>`, and the userinfo to the authority's last `@`
/// (a password may hold a raw `@`, and URL parsers end the userinfo at the last one); the part after the
/// userinfo's first `:` is masked. A port is never userinfo.
#[must_use]
pub fn mask_dsn(text: &str) -> Cow<'_, str> {
    let b = text.as_bytes();
    let mut out = Edits::new(text);
    let mut i = 0;
    while let Some(off) = text[i..].find("://") {
        let sep = i + off;
        i = sep + 3;
        let scheme = b[..sep].iter().rev().take_while(|&&c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-')).count();
        if scheme == 0 || !b[sep - scheme].is_ascii_alphabetic() {
            continue;
        }
        let start = sep + 3;
        let authority = start + b[start..].iter().take_while(|&&c| !ends_authority(c)).count();
        let Some(at) = text[start..authority].rfind('@') else { continue };
        let end = start + at;
        let Some(colon) = text[start..end].find(':') else { continue };
        let password = start + colon + 1;
        if password < end && &text[password..end] != DSN_MASK {
            out.replace(password, end, DSN_MASK);
        }
        i = end;
    }
    out.finish()
}

/// Masks 64 hex characters as `[redacted:hex64]`, keeping a `0x` (P-R71): exactly 64, after an optional `0x`
/// or `0X`, with no `[0-9A-Za-z_]` glued before or after.
#[must_use]
pub fn mask_hex64(text: &str) -> Cow<'_, str> {
    let b = text.as_bytes();
    let mut out = Edits::new(text);
    let mut i = 0;
    while i < b.len() {
        if i > 0 && is_word_byte(b[i - 1]) {
            i += 1;
            continue;
        }
        let hex = if b[i] == b'0' && matches!(b.get(i + 1), Some(b'x' | b'X')) { i + 2 } else { i };
        let end = hex + b[hex..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
        if end - hex == HEX64 && !b.get(end).is_some_and(|&c| is_word_byte(c)) {
            out.replace(hex, end, "[redacted:hex64]");
        }
        i = end.max(i + 1);
    }
    out.finish()
}

/// ESC (U+001B).
const ESC: u8 = 0x1b;
/// A JWT-shaped run's shortest length (P-R68).
const JWT_MIN: usize = 16;
/// The scheme word, matched in any case (P-R69).
const BEARER: &[u8] = b"bearer";
/// A Bearer token's shortest length (P-R69).
const BEARER_TOKEN_MIN: usize = 8;
/// The DSN rule's mask.
const DSN_MASK: &str = "[redacted:dsn]";
/// The hex rule's length (P-R71).
const HEX64: usize = 64;
/// A PEM marker's two heads and its closing dashes (P-R67).
const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
const PEM_DASHES: &str = "-----";
/// A PEM marker's longest label.
const PEM_LABEL_MAX: usize = 64;
/// The armor headers a PEM body may open with (P-R67): RFC 1421's, as an encrypted key carries them, and RFC
/// 4880's. Named, so that a log line such as `INFO: done` is never taken for one.
const PEM_HEADERS: [&str; 7] = ["Proc-Type", "DEK-Info", "Version", "Comment", "MessageID", "Hash", "Charset"];

/// P-R65's token characters, `[A-Za-z0-9_-]`.
fn is_token_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// `[A-Za-z0-9_]`: what glues a word to a match (P-R69, P-R71).
fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// A Bearer token's characters, `[A-Za-z0-9._~+/=-]` (P-R69).
fn is_bearer_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

/// What ends a URL's authority (P-R70): `/`, `?`, `#`, a blank or a line break, a quote, `<` or `>`.
fn ends_authority(c: u8) -> bool {
    matches!(c, b'/' | b'?' | b'#' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'`' | b'<' | b'>')
}

/// The end of the escape sequence whose ESC is `b[start]` (P-R66).
fn ansi_end(b: &[u8], start: usize) -> usize {
    match b.get(start + 1) {
        Some(b'[') => {
            let params = b[start + 2..].iter().take_while(|c| (0x30..=0x3f).contains(*c)).count();
            let j = start + 2 + params;
            let j = j + b[j..].iter().take_while(|c| (0x20..=0x2f).contains(*c)).count();
            // A final byte ends it; anything else (or the text's end) stops it before itself.
            if b.get(j).is_some_and(|c| (0x40..=0x7e).contains(c)) {
                j + 1
            } else {
                j
            }
        }
        Some(b']') => {
            let mut j = start + 2;
            while j < b.len() {
                match b[j] {
                    0x07 => return j + 1,
                    ESC if b.get(j + 1) == Some(&b'\\') => return j + 2,
                    _ => j += 1,
                }
            }
            b.len()
        }
        Some(c) if (0x40..=0x5f).contains(c) => start + 2,
        _ => start + 1,
    }
}

/// The end of a PEM marker `<head><label>-----` at `at`, the label 1 to 64 of `[A-Za-z0-9 ]` (P-R67).
fn pem_marker_end(text: &str, at: usize, head: &str) -> Option<usize> {
    if !text[at..].starts_with(head) {
        return None;
    }
    let label = at + head.len();
    let len = text.as_bytes()[label..].iter().take(PEM_LABEL_MAX).take_while(|c| c.is_ascii_alphanumeric() || **c == b' ').count();
    (len > 0 && text[label + len..].starts_with(PEM_DASHES)).then_some(label + len + PEM_DASHES.len())
}

/// The end of the first END marker at or after `from`.
fn pem_end_after(text: &str, from: usize) -> Option<usize> {
    let mut i = from;
    while let Some(off) = text[i..].find(PEM_END) {
        let at = i + off;
        if let Some(end) = pem_marker_end(text, at, PEM_END) {
            return Some(end);
        }
        i = at + 1;
    }
    None
}

/// The end of the PEM body from `from` (P-R67): body characters `[A-Za-z0-9+/=]`, blanks, line breaks, JSON's
/// line-break escapes and, at a line's start, an armor header line; it stops before anything else.
fn pem_body_end(text: &str, from: usize) -> usize {
    let b = text.as_bytes();
    let mut j = from;
    let mut line_start = true;
    loop {
        if std::mem::take(&mut line_start) {
            j = pem_header_end(text, j).unwrap_or(j);
        }
        match b.get(j) {
            Some(b'\n' | b'\r') => {
                j += 1;
                line_start = true;
            }
            Some(b'\\') if matches!(b.get(j + 1), Some(b'n' | b'r')) => {
                j += 2;
                line_start = true;
            }
            Some(c) if c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b' ' | b'\t') => j += 1,
            _ => return j,
        }
    }
}

/// The end of an armor header line at `at`: a `PEM_HEADERS` name, `:`, then every character up to a line break,
/// a quote or a backslash (a JSON escape ends the line, or the string).
fn pem_header_end(text: &str, at: usize) -> Option<usize> {
    let rest = &text[at..];
    let name = PEM_HEADERS.iter().find(|name| rest.strip_prefix(**name).is_some_and(|r| r.starts_with(':')))?;
    let value = at + name.len() + 1;
    Some(value + text.as_bytes()[value..].iter().take_while(|&&c| !matches!(c, b'\n' | b'\r' | b'"' | b'\'' | b'`' | b'\\')).count())
}

/// P-R67, and whether the last mask was a BEGIN without END that reached the text's end (P-R73's open block).
fn pem(text: &str) -> (Cow<'_, str>, bool) {
    let mut out = Edits::new(text);
    let mut open = false;
    let mut i = 0;
    // Where an END search already failed: no later one can succeed, so the scan stays linear.
    let mut no_end_from = usize::MAX;
    while let Some(off) = text[i..].find(PEM_BEGIN) {
        let start = i + off;
        let Some(marker) = pem_marker_end(text, start, PEM_BEGIN) else {
            i = start + 1;
            continue;
        };
        let end = if marker >= no_end_from { None } else { pem_end_after(text, marker) };
        let stop = match end {
            Some(end) => end,
            None => {
                no_end_from = no_end_from.min(marker);
                pem_body_end(text, marker)
            }
        };
        out.replace(start, stop, "[redacted:pem]");
        open = end.is_none() && stop == text.len();
        i = stop;
    }
    (out.finish(), open)
}

/// A text with ranges replaced in order, borrowed when none was.
struct Edits<'a> {
    text: &'a str,
    out: String,
    done: usize,
    changed: bool,
}

impl<'a> Edits<'a> {
    fn new(text: &'a str) -> Self {
        Edits { text, out: String::new(), done: 0, changed: false }
    }

    /// `text[start..end]` becomes `with`; ranges come in order and never overlap.
    fn replace(&mut self, start: usize, end: usize, with: &str) {
        if !self.changed {
            self.out.reserve(self.text.len());
        }
        self.out.push_str(&self.text[self.done..start]);
        self.out.push_str(with);
        self.done = end;
        self.changed = true;
    }

    fn finish(mut self) -> Cow<'a, str> {
        if !self.changed {
            return Cow::Borrowed(self.text);
        }
        self.out.push_str(&self.text[self.done..]);
        Cow::Owned(self.out)
    }
}

/// A source's own masking (a column, a field): `None` leaves the text as it is.
pub type CustomRule = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The masking a worker applies to a source's outputs and error messages (P-R39, P-R72).
#[derive(Clone)]
pub struct Redactor {
    rules: Vec<Rule>,
    custom: Vec<CustomRule>,
}

impl Redactor {
    /// Every rule, no custom one (LD-P7).
    #[must_use]
    pub fn new() -> Self {
        Redactor { rules: Rule::ALL.to_vec(), custom: Vec::new() }
    }

    /// The identity.
    #[must_use]
    pub fn none() -> Self {
        Redactor { rules: Vec::new(), custom: Vec::new() }
    }

    /// These rules, in `Rule::ALL`'s order, once each.
    #[must_use]
    pub fn only(rules: &[Rule]) -> Self {
        Redactor { rules: Rule::ALL.iter().copied().filter(|r| rules.contains(r)).collect(), custom: Vec::new() }
    }

    /// The same redactor without `rule`.
    #[must_use]
    pub fn without(mut self, rule: Rule) -> Self {
        self.rules.retain(|r| *r != rule);
        self
    }

    /// The same redactor with one more custom rule, run after the built-ins and the earlier customs.
    #[must_use]
    pub fn custom(mut self, rule: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        self.custom.push(Arc::new(rule));
        self
    }

    /// The built-in rules it runs, in order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// P-R72: the rules in `Rule::ALL`'s order, then the custom ones in the order added; borrows when
    /// nothing changed.
    #[must_use]
    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.run(text).0
    }

    /// `redact`, and whether the PEM rule left a block open at the text's end (P-R73).
    fn run<'a>(&self, text: &'a str) -> (Cow<'a, str>, bool) {
        let mut out = Cow::Borrowed(text);
        let mut open = false;
        for rule in &self.rules {
            let masked = if *rule == Rule::Pem {
                let (masked, opened) = pem(&out);
                open = opened;
                masked
            } else {
                rule.apply(&out)
            };
            let changed = match masked {
                Cow::Owned(s) => Some(s),
                Cow::Borrowed(_) => None,
            };
            if let Some(s) = changed {
                out = Cow::Owned(s);
            }
        }
        for rule in &self.custom {
            if let Some(s) = rule(&out) {
                out = Cow::Owned(s);
            }
        }
        (out, open)
    }

    /// A stream redactor for one call's items (P-R73).
    #[must_use]
    pub fn stream(&self) -> StreamRedactor {
        StreamRedactor { redactor: self.clone(), pem_open: false }
    }
}

impl Default for Redactor {
    /// `Redactor::new()`.
    fn default() -> Self {
        Redactor::new()
    }
}

impl fmt::Debug for Redactor {
    /// Its rules and how many custom ones.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor").field("rules", &self.rules).field("custom", &self.custom.len()).finish()
    }
}

/// One call's redactor over a stream's items: it keeps whether a PEM block is open (P-R73).
#[derive(Debug)]
pub struct StreamRedactor {
    redactor: Redactor,
    pem_open: bool,
}

impl StreamRedactor {
    /// One item, redacted with the state of the items before it (P-R73). While a PEM block is open, a piece of
    /// body alone (an armor header line included) becomes empty, a piece with an END marker loses everything
    /// through it, and any other piece closes the block; a BEGIN with no END opens it when its mask reached the
    /// piece's end.
    pub fn piece<'a>(&mut self, text: &'a str) -> Cow<'a, str> {
        let rest = if std::mem::take(&mut self.pem_open) {
            if pem_body_end(text, 0) == text.len() {
                self.pem_open = true;
                return Cow::Borrowed("");
            }
            pem_end_after(text, 0).map_or(text, |end| &text[end..])
        } else {
            text
        };
        let (out, open) = self.redactor.run(rest);
        self.pem_open = open;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::sample;

    /// A 62-character three-segment JWT shape, built at run time.
    fn jwt() -> String {
        ["eyJ", &"a".repeat(17), ".", &"b".repeat(20), ".", &"c".repeat(20)].concat()
    }

    fn pem_block() -> String {
        format!("-----BEGIN TEST KEY-----\n{}\n-----END TEST KEY-----", "A".repeat(64))
    }

    fn borrowed(c: Cow<'_, str>) -> bool {
        matches!(c, Cow::Borrowed(_))
    }

    /// Each `(input, output)` through `rule`; an output equal to its input must come back borrowed.
    fn check(rule: fn(&str) -> Cow<'_, str>, rows: &[(String, String)]) {
        for (input, want) in rows {
            let got = rule(input);
            assert_eq!(&*got, want.as_str(), "{input:?}");
            assert_eq!(borrowed(got), input == want, "{input:?}: borrowed when unchanged, owned when changed");
        }
    }

    fn row(input: impl Into<String>, output: impl Into<String>) -> (String, String) {
        (input.into(), output.into())
    }

    fn same(input: impl Into<String>) -> (String, String) {
        let input = input.into();
        (input.clone(), input)
    }

    /// P-T27.
    #[test]
    fn each_rule_masks_its_shape_and_leaves_near_misses() {
        check(
            strip_ansi,
            &[
                row("\u{1b}[31mred\u{1b}[0m plain", "red plain"),
                row("\u{1b}[1;38;5;208mbold\u{1b}[m", "bold"),
                row("\u{1b}]0;a title\u{7}after", "after"),
                row("\u{1b}]0;a title\u{1b}\\after", "after"),
                row("a\u{1b}Mb", "ab"),
                row("text \u{1b}[31", "text "),
                row("a\u{1b}[31\nb", "a\nb"),
                row("a\u{1b}]0;never ends", "a"),
                row("a\u{1b}", "a"),
                row("a\u{1b}\u{e9}", "a\u{e9}"),
                same("no escape here"),
            ],
        );

        let json_text = serde_json::json!({"k": "-----BEGIN TEST KEY-----\nAAAA", "n": 1}).to_string();
        assert_eq!(json_text, r#"{"k":"-----BEGIN TEST KEY-----\nAAAA","n":1}"#);
        check(
            mask_pem,
            &[
                row(format!("before {} after", pem_block()), "before [redacted:pem] after"),
                row(format!("x -----BEGIN TEST KEY-----\n{}\n{}\n", "A".repeat(64), "B".repeat(10)), "x [redacted:pem]"),
                row(format!("x -----BEGIN TEST KEY-----\r\n{}=\r\n", "A".repeat(64)), "x [redacted:pem]"),
                row(json_text.clone(), r#"{"k":"[redacted:pem]","n":1}"#),
                row(format!("-----BEGIN {}-----\nAAAA", "L".repeat(64)), "[redacted:pem]"),
                same(format!("-----BEGIN {}-----\nAAAA", "L".repeat(65))),
                same("-----BEGIN -----\nAAAA"),
                same(format!("-----BEGIN TEST KEY\n{}", "A".repeat(64))),
                row(format!("{} and {}", pem_block(), pem_block()), "[redacted:pem] and [redacted:pem]"),
            ],
        );
        let masked = mask_pem(&json_text);
        let back: serde_json::Value = serde_json::from_str(&masked).expect("still JSON");
        assert_eq!((back["k"].as_str(), back["n"].as_i64()), (Some("[redacted:pem]"), Some(1)));
        // Armor header lines (RFC 1421's encrypted key, RFC 4880's armor) are body; a log line is not.
        let headers = format!("Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,{}\n", "0A".repeat(8));
        let armor = "Version: Test 1\nComment: a test (made up)\n";
        let json_headers = serde_json::json!({"k": format!("-----BEGIN TEST KEY-----\n{headers}\nAAAA"), "n": 1}).to_string();
        check(
            mask_pem,
            &[
                row(format!("x -----BEGIN TEST KEY-----\n{headers}\n{}\n", "A".repeat(64)), "x [redacted:pem]"),
                row(format!("-----BEGIN PGP TEST KEY BLOCK-----\n{armor}\n{}\n=AbCd", "B".repeat(64)), "[redacted:pem]"),
                row(json_headers, r#"{"k":"[redacted:pem]","n":1}"#),
                row(format!("-----BEGIN TEST KEY-----\n{headers}-----END TEST KEY----- after"), "[redacted:pem] after"),
                row("-----BEGIN TEST KEY-----\nINFO: done", "[redacted:pem]: done"),
                row("-----BEGIN TEST KEY-----\nComment: \"quoted\"", "[redacted:pem]\"quoted\""),
            ],
        );

        let jwt = jwt();
        assert_eq!(jwt.len(), 62);
        let one_dot = ["eyJ", &"a".repeat(20), ".", &"b".repeat(20)].concat();
        let short = ["eyJ", "aaaaa", ".", "bbb", ".", "cc"].concat();
        let shortest = ["eyJ", "aaaaaa", ".", "bbb", ".", "cc"].concat();
        assert_eq!((short.len(), shortest.len()), (15, 16));
        check(
            mask_jwt,
            &[
                row(format!("token={jwt}"), "token=[redacted:jwt]"),
                row(format!("{jwt} {jwt}"), "[redacted:jwt] [redacted:jwt]"),
                row(format!("\"{jwt}\","), "\"[redacted:jwt]\","),
                row(shortest.clone(), "[redacted:jwt]"),
                same(one_dot),
                same(short),
                same(format!("x{jwt}")),
                same(format!(".{jwt}")),
                same(format!("_{jwt}")),
            ],
        );

        check(
            mask_bearer,
            &[
                row(format!("Authorization: Bearer {}", "0".repeat(8)), "Authorization: Bearer [redacted:bearer]"),
                row(format!("BEARER\t\t{}x", "1a".repeat(4)), "BEARER\t\t[redacted:bearer]"),
                row(format!("bearer {}/{}=", "a".repeat(8), "b".repeat(8)), "bearer [redacted:bearer]"),
                same("the bearer document"),
                same(format!("Bearer {}", "1".repeat(7))),
                same(format!("xbearer {}", "1".repeat(8))),
                same(format!("Bearer{}", "1".repeat(8))),
            ],
        );

        // The password is built at run time; each URL keeps its userinfo and host in one literal (P-R89).
        let password = ["place", "holder-1"].concat();
        let userinfo = format!("reader:{password}");
        let masked = ["reader", ":[redacted:dsn]"].concat();
        // A raw `@` in the password: the userinfo ends at the authority's last `@`.
        let at_userinfo = ["reader:", "p", "@", "ss-word-1"].concat();
        check(
            mask_dsn,
            &[
                row(format!("scheme://{userinfo}@db.example.com/app"), format!("scheme://{masked}@db.example.com/app")),
                row(format!("scheme://:{password}@db.example.com"), "scheme://:[redacted:dsn]@db.example.com"),
                row(format!("\"x+y.z-1://{userinfo}@db.example.com:5432/app\""), format!("\"x+y.z-1://{masked}@db.example.com:5432/app\"")),
                row(format!("scheme://{at_userinfo}@db.example.com/app"), format!("scheme://{masked}@db.example.com/app")),
                row(format!("scheme://{at_userinfo}@db.example.com/a@b"), format!("scheme://{masked}@db.example.com/a@b")),
                same(format!("scheme://{masked}@db.example.com/app")),
                same("https://db.example.com:8080/a@b"),
                same("scheme://user@db.example.com"),
                same("scheme://user@relay@db.example.com"),
                same(format!("1x://{userinfo}@db.example.com")),
                same(format!("://{userinfo}@db.example.com")),
                same(format!("scheme://{userinfo} @db.example.com")),
                same(format!("scheme://db.example.com:8080\nuser@{password}")),
            ],
        );

        let hex = "ab".repeat(32);
        check(
            mask_hex64,
            &[
                row(format!("key {hex}"), "key [redacted:hex64]"),
                row(format!("0x{}", "AB".repeat(32)), "0x[redacted:hex64]"),
                row(format!("0X{hex}."), "0X[redacted:hex64]."),
                row(format!("{hex}-{hex}"), "[redacted:hex64]-[redacted:hex64]"),
                row(format!("\u{e9}{hex}"), "\u{e9}[redacted:hex64]"),
                same("ab".repeat(31) + "a"),
                same("ab".repeat(32) + "a"),
                same(format!("{hex}g")),
                same(format!("g{hex}")),
                same(format!("_{hex}")),
                same(format!("x0x{hex}")),
            ],
        );
    }

    /// P-T28.
    #[test]
    fn the_redactor_runs_rules_in_order_then_customs() {
        let jwt = jwt();
        let split = format!("{}\u{1b}[0m{}", &jwt[..30], &jwt[30..]);
        assert_eq!(Redactor::new().redact(&split), "[redacted:jwt]", "ANSI first, so a code glued into a token cannot hide it");
        let hex = "cd".repeat(32);
        assert_eq!(Redactor::new().without(Rule::Hex64).redact(&format!("{hex} {jwt}")), format!("{hex} [redacted:jwt]"));
        assert_eq!(Redactor::new().redact(&format!("{hex} {jwt}")), "[redacted:hex64] [redacted:jwt]");
        let text = format!("{jwt}\u{1b}[0m");
        let same = Redactor::none().redact(&text);
        assert_eq!(same, text);
        assert!(borrowed(same));
        assert_eq!(Redactor::only(&[Rule::Jwt, Rule::Ansi, Rule::Jwt]).rules(), [Rule::Ansi, Rule::Jwt]);
        assert_eq!(Redactor::new().rules(), Rule::ALL);
        assert_eq!(Redactor::default().rules(), Rule::ALL);
        let names: Vec<_> = Rule::ALL.iter().map(|r| r.name()).collect();
        assert_eq!(names, ["ansi", "pem", "jwt", "bearer", "dsn", "hex64"]);

        let custom = Redactor::new()
            .custom(|t| t.contains("[redacted:jwt]").then(|| t.replace("[redacted:jwt]", "X")))
            .custom(|t| t.contains('X').then(|| t.replace('X', "Y")));
        assert_eq!(custom.redact(&format!("a {jwt}")), "a Y", "customs run after the built-ins, in the order added");
        assert!(borrowed(custom.redact("clean")));
        assert_eq!(format!("{custom:?}"), "Redactor { rules: [Ansi, Pem, Jwt, Bearer, Dsn, Hex64], custom: 2 }");
        let column = Redactor::none().custom(|t| t.strip_prefix("secret-column:").map(|_| "secret-column:[masked]".to_string()));
        assert_eq!(column.redact("secret-column:value"), "secret-column:[masked]");
    }

    /// P-T29.
    #[test]
    fn the_stream_redactor_masks_a_pem_block_across_pieces() {
        let redactor = Redactor::new();
        let mut stream = redactor.stream();
        let a64 = "A".repeat(64);
        let jwt = jwt();
        let pieces = ["before -----BEGIN TEST KEY-----", a64.as_str(), "-----END TEST KEY----- after", jwt.as_str()];
        let got: Vec<String> = pieces.iter().map(|p| stream.piece(p).into_owned()).collect();
        assert_eq!(got, ["before [redacted:pem]", "", " after", "[redacted:jwt]"]);
        // A body-shaped piece that no rule masks: emptied while a block is open, kept otherwise.
        let body = "QUJD".repeat(16);
        let mut fresh = redactor.stream();
        assert_eq!(fresh.piece(&body), body, "a second stream redactor starts closed");

        let mut stream = redactor.stream();
        let b64 = "B".repeat(64);
        let pieces = ["-----BEGIN TEST KEY-----", a64.as_str(), b64.as_str(), "INFO: done"];
        let got: Vec<String> = pieces.iter().map(|p| stream.piece(p).into_owned()).collect();
        assert_eq!(got, ["[redacted:pem]", "", "", "INFO: done"]);
        assert_eq!(stream.piece(&body), body, "the block closed at the first other piece");

        // A BEGIN whose mask stops before the piece's end opens nothing.
        let mut stream = redactor.stream();
        assert_eq!(stream.piece("{\"k\":\"-----BEGIN TEST KEY-----\\nAAAA\"}"), "{\"k\":\"[redacted:pem]\"}");
        assert_eq!(stream.piece(&body), body);
        // An END piece's rest runs through the rules, and may open a block again.
        let mut stream = redactor.stream();
        assert_eq!(stream.piece("-----BEGIN TEST KEY-----"), "[redacted:pem]");
        assert_eq!(stream.piece("AAAA\\nBBBB\r\n"), "", "JSON's line-break escapes are body too");
        assert_eq!(stream.piece(&format!("{a64}-----END TEST KEY----- {jwt} -----BEGIN TEST KEY-----")), " [redacted:jwt] [redacted:pem]");
        assert_eq!(stream.piece(&b64), "");
        // An encrypted key's and an armored key's header lines are body while the block is open.
        let dek = format!("DEK-Info: AES-128-CBC,{}", "0A".repeat(8));
        for (begin, header_lines, end) in [
            ("-----BEGIN TEST KEY-----", ["Proc-Type: 4,ENCRYPTED", dek.as_str()], "-----END TEST KEY-----"),
            ("-----BEGIN PGP TEST KEY BLOCK-----", ["Version: Test 1", "Comment: a test (made up)"], "-----END PGP TEST KEY BLOCK-----"),
        ] {
            let mut stream = redactor.stream();
            let pieces = [begin, header_lines[0], header_lines[1], "", a64.as_str(), "=AbCd", end];
            let got: Vec<String> = pieces.iter().map(|p| stream.piece(p).into_owned()).collect();
            assert_eq!(got, ["[redacted:pem]", "", "", "", "", "", ""], "{begin}");
            assert_eq!(stream.piece(&body), body, "the END closed the block");
        }
        // A header line that stops at a quote is not body alone: it closes the block.
        let mut stream = redactor.stream();
        assert_eq!(stream.piece("-----BEGIN TEST KEY-----"), "[redacted:pem]");
        assert_eq!(stream.piece("Comment: \"quoted\""), "Comment: \"quoted\"");
        assert_eq!(stream.piece(&body), body);
        // Without the PEM rule no block opens.
        let mut stream = Redactor::new().without(Rule::Pem).stream();
        assert_eq!(stream.piece("-----BEGIN TEST KEY-----"), "-----BEGIN TEST KEY-----");
        assert_eq!(stream.piece(&body), body);
    }

    /// P-T30.
    #[test]
    fn redaction_is_idempotent_and_borrows_clean_text() {
        let redactor = Redactor::new();
        let clean = "The quick brown fox jumps over the lazy dog, twice: 1, 2. ".repeat(1200);
        assert!(clean.len() >= 64 * 1024);
        assert!(borrowed(redactor.redact(&clean)));
        let mut mixed = String::new();
        for rule in Rule::ALL {
            let (raw, masked) = sample(rule);
            let again = redactor.redact(&masked);
            assert_eq!(again, masked, "{rule:?}");
            assert!(borrowed(again), "{rule:?}: a mask is not masked again");
            mixed.push_str(&raw);
            mixed.push(' ');
        }
        let once = redactor.redact(&mixed).into_owned();
        assert_eq!(redactor.redact(&once), once);
        // A password with a raw `@`, masked whole, stays masked.
        let at_dsn = format!("scheme://{}@db.example.com/app", ["reader:", "p", "@", "ss-word-1"].concat());
        let once = redactor.redact(&at_dsn).into_owned();
        assert!(!once.contains("ss-word-1"), "{once}");
        assert!(borrowed(redactor.redact(&once)));
        for rule in Rule::ALL {
            for mask in Rule::ALL.map(|r| format!("[redacted:{}]", r.name())) {
                assert!(borrowed(rule.apply(&mask)), "{rule:?} changed {mask}");
            }
        }
    }
}
