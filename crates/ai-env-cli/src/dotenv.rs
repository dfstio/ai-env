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
