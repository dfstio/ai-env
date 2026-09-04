//! Minimal, STRICT dotenv parser for the *decrypted* plaintext — used by
//! `ai-env run` to inject variables into the child environment.
//!
//! Deliberately small and predictable (the dotenvx quote-mangling bug, their
//! issue #377, is what happens when this surface grows):
//! * `KEY=VALUE`, optional `export ` prefix, `#` comment lines, blank lines
//! * double-quoted values: `\n \r \t \\ \"` escapes processed
//! * single-quoted values: literal
//! * unquoted values: trimmed; NO inline comments, NO `$`-expansion
//! * multi-line values are NOT supported (error, not silent corruption)
use crate::errors::{CliError, Result};
use zeroize::Zeroizing;

/// One line of a .env file, byte-exact (for `ai-env edit`'s round-trip).
///
/// `Entry` lines are stored as `before_eq` + `"="` + `value`, all verbatim —
/// the VALUE keeps its original quoting/escapes untouched (it is sealed and
/// edited as raw text; validation happens against the strict parser on
/// commit). Everything else is kept as the exact original line text.
pub enum RawLine {
    Comment { text: String, crlf: bool },
    Blank { text: String, crlf: bool },
    Entry {
        /// Everything before the first '=' (may include `export ` prefix and
        /// surrounding whitespace), verbatim.
        before_eq: String,
        /// The validated variable name inside `before_eq`.
        name: String,
        /// Everything after the first '=' with the line-terminator `\r`
        /// stripped (secret — Zeroizing). A CRLF ending is recorded in `crlf`
        /// and re-emitted on save, so the editor never embeds a stray CR
        /// inside the secret.
        value: Zeroizing<String>,
        crlf: bool,
    },
}

pub struct RawFile {
    pub lines: Vec<RawLine>,
    pub trailing_newline: bool,
}

/// Is `s` a valid dotenv variable name?
#[must_use]
pub fn is_valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Validate a raw value exactly the way the strict runtime parser would
/// (so a file that `edit` writes is guaranteed to work with `ai-env run`).
///
/// SECURITY: this must never materialize the decoded value — it runs on every
/// editor keystroke-commit, and an owned `String` of the secret would land on
/// the unwiped heap. It therefore uses the scan-only twin of `parse_value`;
/// a unit test asserts the two stay accept/reject-equivalent.
pub fn validate_raw_value(raw: &str) -> Result<()> {
    let trimmed = raw.strip_suffix('\r').unwrap_or(raw).trim();
    check_value_syntax(trimmed, 0)
}

/// Scan-only twin of [`parse_value`]: identical acceptance rules, no output
/// allocation. Keep the two in lock-step (see `tests::checker_matches_parser`).
pub fn check_value_syntax(raw: &str, line_no: usize) -> Result<()> {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let _ = chars.next();
            } else if c == '"' {
                return Err(CliError::Msg(format!(
                    "decrypted .env line {line_no}: unescaped '\"' inside a quoted value"
                )));
            }
        }
        return Ok(());
    }
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        return Ok(());
    }
    if raw.starts_with('"') || raw.starts_with('\'') {
        return Err(CliError::Msg(format!(
            "decrypted .env line {line_no}: unterminated quoted value (multi-line values are \
             not supported)"
        )));
    }
    Ok(())
}

/// Layout-preserving parse for `ai-env edit`. Byte-exact inverse of
/// [`serialize_line`]: joining the serialized lines with `\n` (plus the
/// trailing newline flag) reproduces the input exactly.
pub fn parse_lines(text: &str) -> Result<RawFile> {
    let trailing_newline = text.ends_with('\n');
    let body = if trailing_newline { &text[..text.len() - 1] } else { text };
    let mut lines = Vec::new();
    if body.is_empty() && trailing_newline {
        // A file that is exactly "\n" is one blank line.
        lines.push(RawLine::Blank { text: String::new(), crlf: false });
        return Ok(RawFile { lines, trailing_newline: true });
    }
    if body.is_empty() {
        return Ok(RawFile { lines, trailing_newline });
    }
    for (idx, raw_with_cr) in body.split('\n').enumerate() {
        // The line-terminator `\r` (CRLF checkout) is recorded, not stored in
        // content — sealing it inside a value corrupts edits at line end.
        let crlf = raw_with_cr.ends_with('\r');
        let raw = raw_with_cr.strip_suffix('\r').unwrap_or(raw_with_cr);
        let t = raw.trim_start();
        if t.is_empty() {
            lines.push(RawLine::Blank { text: raw.to_owned(), crlf });
        } else if t.starts_with('#') {
            lines.push(RawLine::Comment { text: raw.to_owned(), crlf });
        } else {
            let eq = raw.find('=').ok_or_else(|| {
                CliError::Msg(format!(
                    ".env line {} is not KEY=VALUE, a comment, or blank — repair the file \
                     first (ai-env decrypt --force)",
                    idx + 1
                ))
            })?;
            let before_eq = &raw[..eq];
            let value = &raw[eq + 1..];
            let name_part = before_eq.trim();
            let name = name_part.strip_prefix("export ").map(str::trim_start).unwrap_or(name_part);
            if !is_valid_name(name) {
                return Err(CliError::Msg(format!(
                    ".env line {} has an invalid variable name {name:?} — repair the file \
                     first (ai-env decrypt --force)",
                    idx + 1
                )));
            }
            validate_raw_value(value).map_err(|e| {
                CliError::Msg(format!(
                    ".env line {}: {e} — repair the file first (ai-env decrypt --force)",
                    idx + 1
                ))
            })?;
            lines.push(RawLine::Entry {
                before_eq: before_eq.to_owned(),
                name: name.to_owned(),
                value: Zeroizing::new(value.to_owned()),
                crlf,
            });
        }
    }
    Ok(RawFile { lines, trailing_newline })
}

pub fn parse(text: &str) -> Result<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let eq = line.find('=').ok_or_else(|| {
            CliError::Msg(format!("decrypted .env line {} has no '='", idx + 1))
        })?;
        let key = line[..eq].trim();
        if key.is_empty()
            || !key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(CliError::Msg(format!(
                "decrypted .env line {} has an invalid variable name {key:?}",
                idx + 1
            )));
        }
        let raw_value = line[eq + 1..].trim();
        let value = parse_value(raw_value, idx + 1)?;
        // Last assignment wins, like every dotenv implementation.
        if let Some(slot) = out.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value;
        } else {
            out.push((key.to_owned(), value));
        }
    }
    Ok(out)
}

fn parse_value(raw: &str, line_no: usize) -> Result<String> {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('\\') => out.push('\\'),
                    Some('"') => out.push('"'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else if c == '"' {
                return Err(CliError::Msg(format!(
                    "decrypted .env line {line_no}: unescaped '\"' inside a quoted value"
                )));
            } else {
                out.push(c);
            }
        }
        return Ok(out);
    }
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        return Ok(raw[1..raw.len() - 1].to_owned());
    }
    if raw.starts_with('"') || raw.starts_with('\'') {
        return Err(CliError::Msg(format!(
            "decrypted .env line {line_no}: unterminated quoted value (multi-line values are \
             not supported)"
        )));
    }
    Ok(raw.to_owned())
}

#[cfg(test)]
mod tests {
    use super::parse;
    use super::{parse_lines, RawLine};

    /// Test-only whole-file serializer proving parse_lines is a byte-exact
    /// inverse. (The real save path streams line-by-line for the same shape.)
    fn serialize(file: &super::RawFile) -> String {
        let mut out = String::new();
        for (i, line) in file.lines.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            let crlf = match line {
                RawLine::Comment { text, crlf } | RawLine::Blank { text, crlf } => {
                    out.push_str(text);
                    *crlf
                }
                RawLine::Entry { before_eq, value, crlf, .. } => {
                    out.push_str(before_eq);
                    out.push('=');
                    out.push_str(value);
                    *crlf
                }
            };
            if crlf {
                out.push('\r');
            }
        }
        if file.trailing_newline {
            out.push('\n');
        }
        out
    }

    #[test]
    fn parse_lines_roundtrips_byte_exact() {
        let cases = [
            "",
            "\n",
            "A=1\n",
            "A=1",
            "# comment\n\nA = 1\nexport B=\"two words\"\n  # indented comment\nC='sq'\n\n",
            "A=unquoted with spaces   \nB=\"pad\"\r\nC=x\n", // CRLF line preserved
            "A=\nB= \n",
            "lower_x=1\n_UND=2\n",
        ];
        for case in cases {
            let parsed = parse_lines(case).unwrap_or_else(|e| panic!("{case:?}: {e}"));
            assert_eq!(serialize(&parsed), case, "round-trip failed for {case:?}");
        }
    }

    #[test]
    fn parse_lines_accepts_everything_strict_parse_accepts() {
        // Any file the strict parser accepts must parse line-preserving too.
        let cases = [
            "# c\nFOO=bar\nexport BAZ=qux\nQUOTED=\"a b\\nc\"\nSINGLE='lit'\nEMPTY=\n",
            "A=1\nA=2\n", // duplicates: strict collapses, raw preserves both
        ];
        for case in cases {
            assert!(parse(case).is_ok());
            let raw = parse_lines(case).unwrap();
            assert_eq!(serialize(&raw), case);
        }
    }

    #[test]
    fn parse_lines_rejects_what_strict_rejects() {
        assert!(parse_lines("no equals\n").is_err());
        assert!(parse_lines("1BAD=x\n").is_err());
        assert!(parse_lines("A=\"unterminated\n").is_err());
    }

    #[test]
    fn parse_lines_extracts_names() {
        let raw = parse_lines("export  SPACED = v\n").unwrap();
        match &raw.lines[0] {
            RawLine::Entry { name, before_eq, .. } => {
                assert_eq!(name, "SPACED");
                assert_eq!(before_eq, "export  SPACED ");
            }
            _ => panic!("expected entry"),
        }
    }

    #[test]
    fn crlf_terminator_is_kept_out_of_values() {
        // Mixed line endings round-trip byte-exact, and the sealed value
        // never contains the terminator CR (audit fix 16).
        let input = "A=one\r\nB=two\nC=three\r\n# note\r\n\r\nD=4\n";
        let raw = parse_lines(input).unwrap();
        assert_eq!(serialize(&raw), input);
        for line in &raw.lines {
            if let RawLine::Entry { value, crlf, name, .. } = line {
                assert!(!value.contains('\r'), "{name}: CR leaked into value");
                match name.as_str() {
                    "A" | "C" => assert!(*crlf),
                    "B" | "D" => assert!(!*crlf),
                    _ => {}
                }
            }
        }
    }

    /// The scan-only checker must accept/reject exactly what parse_value does
    /// (audit fix 2: validation must not materialize the secret).
    #[test]
    fn checker_matches_parser() {
        let corpus = [
            "", "x", "plain value", "  padded  ", "\"quoted\"", "'single'",
            "\"esc \\\" ok\"", "\"inner\"broken\"", "\"unterminated", "'unterminated",
            "\"\"", "''", "\"", "'", "\"a\\\"", "'can't happen'", "a\"b", "a'b",
            "\"tab\\t\\n\"", "\\", "\"\\\\\"", "\"\\q\"", "with # hash", "=",
        ];
        for raw in corpus {
            let parser = super::parse_value(raw, 0).is_ok();
            let checker = super::check_value_syntax(raw, 0).is_ok();
            assert_eq!(parser, checker, "divergence on {raw:?}");
        }
    }

    #[test]
    fn basics() {
        let vars = parse(
            "# comment\n\nFOO=bar\nexport BAZ=qux\nQUOTED=\"a b\\nc\"\nSINGLE='lit $HOME'\nEMPTY=\nSPACED = v \n",
        )
        .unwrap();
        let get = |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("FOO").unwrap(), "bar");
        assert_eq!(get("BAZ").unwrap(), "qux");
        assert_eq!(get("QUOTED").unwrap(), "a b\nc");
        assert_eq!(get("SINGLE").unwrap(), "lit $HOME");
        assert_eq!(get("EMPTY").unwrap(), "");
        assert_eq!(get("SPACED").unwrap(), "v");
    }

    #[test]
    fn last_assignment_wins() {
        let vars = parse("A=1\nA=2\n").unwrap();
        assert_eq!(vars, vec![("A".into(), "2".into())]);
    }

    #[test]
    fn rejects_bad_lines() {
        assert!(parse("no equals sign\n").is_err());
        assert!(parse("1BAD=x\n").is_err());
        assert!(parse("A=\"unterminated\n").is_err());
        assert!(parse("A=\"inner\"quote\"\n").is_err());
    }
}
