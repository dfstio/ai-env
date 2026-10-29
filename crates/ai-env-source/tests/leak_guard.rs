//! P-T9 and P-T10: the leak guard (plans/s13-contracts.md §P-proto-sdk.11, P-R87 to P-R90). ai-env holds no
//! deny-list, which would leak the names it lists: this is an allow-list of what the public crates may name.
//! Every needle and planted value here is built at run time (P-R89), so the guard scans this file too and
//! finds nothing in it.

use std::fmt;
use std::path::{Path, PathBuf};

/// Scanned, and each must exist (P-R87).
const REQUIRED_DIRS: [&str; 7] = [
    "crates/ai-env-relay-proto",
    "crates/ai-env-source",
    "tools/relay-protogen",
    "crates/ai-env-worker",
    "crates/ai-env-relay",
    "templates/worker",
    "crates/ai-env-relay-client",
];
/// The types a public file may implement the trait for (P-R88 (d)): the examples and the test doubles, each
/// named for what it does, never for what it fronts. A slice that adds a double names it in its section.
const ALLOWED_SOURCE_TYPES: [&str; 15] = [
    "EchoSource",
    "ScriptedSource",
    "HttpJsonSource",
    "HandSource",
    "MacroSource",
    "DefaultsSource",
    "InvalidDescriptorSource",
    "UnstableDescriptorSource",
    "LenientOpSource",
    "LenientParamsSource",
    "SlowHealthSource",
    "InternalExampleSource",
    "WrongKindSource",
    "PanickingSource",
    "RecordingSource",
];
/// The names a descriptor's literal name starts with (P-R88 (e)).
const GENERIC_NAMES: [&str; 5] = ["echo", "scripted", "http-json", "example", "test"];
/// The hosts a URL may name besides the reserved and placeholder forms (P-R88 (b)).
/// `ai-env-relay` is the relay certificate's own DNS name (X-3), the name a worker verifies: ai-env's, not a host's.
const ALLOWED_HOSTS: [&str; 9] = ["github.com", "crates.io", "docs.rs", "json-schema.org", "claude.ai", "downloads.claude.ai", "code.claude.com", "age-encryption.org", "ai-env-relay"];
/// The environment names a crate may read besides `AI_ENV_*` and `CARGO_*` (P-R88 (g)).
const ALLOWED_ENV: [&str; 12] = [
    "HOME",
    "RUST_LOG",
    "OUT_DIR",
    "PROTOC",
    "NOTIFY_SOCKET",
    "WATCHDOG_USEC",
    "WATCHDOG_PID",
    "CREDENTIALS_DIRECTORY",
    "STATE_DIRECTORY",
    "RUNTIME_DIRECTORY",
    "LISTEN_FDS",
    "LISTEN_PID",
];
/// Words that make a key credential-shaped (P-R88 (f)).
const CREDENTIAL_WORDS: [&str; 6] = ["token", "secret", "key", "password", "passwd", "credential"];

/// One finding: `<file>:<line>: <check>: <the matched text>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    file: String,
    line: usize,
    check: &'static str,
    text: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}: {}", self.file, self.line, self.check, self.text)
    }
}

fn finding(file: &str, line: usize, check: &'static str, text: impl Into<String>) -> Finding {
    Finding { file: file.to_string(), line, check, text: text.into() }
}

/// The 1-based line of byte `at`.
fn line_of(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

/// Every dotted quad in `line` not glued to a digit or a dot, with its octets (each at most 255). One dot after
/// a run ends a sentence and is no part of it, so an address at a sentence's end is still found.
fn quads(line: &str) -> Vec<(&str, [u8; 4])> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !(b[i].is_ascii_digit() || b[i] == b'.') {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
            i += 1;
        }
        let run = line[start..i].strip_suffix('.').unwrap_or(&line[start..i]);
        let parts: Vec<&str> = run.split('.').collect();
        if parts.len() != 4 || !parts.iter().all(|p| (1..=3).contains(&p.len())) {
            continue;
        }
        let octets: Vec<u8> = parts.iter().filter_map(|p| p.parse::<u8>().ok()).collect();
        if let Ok(octets) = <[u8; 4]>::try_from(octets) {
            out.push((run, octets));
        }
    }
    out
}

/// P-R88 (a)'s ranges: loopback, 0.0.0.0, ai-env's VPC, link-local and the three documentation ranges.
fn allowed_quad(o: [u8; 4]) -> bool {
    o[0] == 127 || o == [0; 4] || o[..2] == [10, 42] || o[..2] == [169, 254] || o[..3] == [192, 0, 2] || o[..3] == [198, 51, 100] || o[..3] == [203, 0, 113]
}

/// (a) `ipv4`.
fn ipv4(file: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        for (quad, octets) in quads(line) {
            if !allowed_quad(octets) {
                out.push(finding(file, n + 1, "ipv4", quad));
            }
        }
    }
    out
}

fn allowed_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host.is_empty() || host.starts_with(['<', '{', '$']) || host == "localhost" || host == "[::1]" {
        return true;
    }
    if let [(quad, octets)] = quads(&host)[..] {
        if quad == host {
            return allowed_quad(octets);
        }
    }
    let reserved = ["example.com", "example.org", "example.net"].iter().any(|d| host == *d || host.ends_with(&format!(".{d}")));
    reserved || [".example", ".invalid", ".test", ".localhost"].iter().any(|s| host.ends_with(s)) || ALLOWED_HOSTS.contains(&host.as_str())
}

/// (b) `url-host`: after `://`, the authority runs to the first `/`, `?`, `#`, blank, quote, `)`, `>`, `,`,
/// backtick or backslash (a string's escape); the host is past its last `@`, up to a `:` (`[…]` whole).
fn url_host(file: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(at) = rest.find("://") {
            let after = &rest[at + 3..];
            let end = after.find(['/', '?', '#', ' ', '\t', '"', '\'', ')', '>', ',', '`', '\\']).unwrap_or(after.len());
            let hostport = after[..end].rsplit('@').next().unwrap_or_default();
            let host = match hostport.find(']') {
                Some(close) if hostport.starts_with('[') => &hostport[..=close],
                _ => hostport.split(':').next().unwrap_or_default(),
            };
            if !allowed_host(host) {
                out.push(finding(file, n + 1, "url-host", host));
            }
            rest = &after[end..];
        }
    }
    out
}

/// (c) `home-path`.
fn home_path(file: &str, text: &str) -> Vec<Finding> {
    let needles = ["Users", "home", "root"].map(|d| ["", d, ""].join("/"));
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        for needle in &needles {
            if line.contains(needle.as_str()) {
                out.push(finding(file, n + 1, "home-path", needle.as_str()));
            }
        }
    }
    out
}

/// (d) `source-type`: an `impl` line naming the trait for a type outside `ALLOWED_SOURCE_TYPES`.
fn source_type(file: &str, text: &str) -> Vec<Finding> {
    let needle = concat!("DataSource", " for ");
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if !line.contains("impl") {
            continue;
        }
        for (at, _) in line.match_indices(needle) {
            let after = &line[at + needle.len()..];
            let ty: String = after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if !ty.is_empty() && !ALLOWED_SOURCE_TYPES.contains(&ty.as_str()) {
                out.push(finding(file, n + 1, "source-type", format!("{needle}{ty}")));
            }
        }
    }
    out
}

/// `(echo|scripted|http-json|example|test)([-.][a-z0-9]+)*`.
fn generic_name(name: &str) -> bool {
    let Some(mut rest) = GENERIC_NAMES.iter().find_map(|p| name.strip_prefix(p)) else { return false };
    while !rest.is_empty() {
        let Some(after) = rest.strip_prefix(['-', '.']) else { return false };
        let n = after.bytes().take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit()).count();
        if n == 0 {
            return false;
        }
        rest = &after[n..];
    }
    true
}

/// (e) `source-name`: a string literal first argument of the descriptor's or `EchoSource`'s constructor.
fn source_name(file: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for needle in [concat!("SourceDescriptor", "::new("), concat!("EchoSource", "::named(")] {
        for (at, _) in text.match_indices(needle) {
            let after = text[at + needle.len()..].trim_start();
            let Some(literal) = after.strip_prefix('"') else { continue };
            let mut end = 0;
            let bytes = literal.as_bytes();
            while end < bytes.len() && (bytes[end] != b'"' || (end > 0 && bytes[end - 1] == b'\\')) {
                end += 1;
            }
            let name = &literal[..end];
            if !generic_name(name) {
                out.push(finding(file, line_of(text, at), "source-name", name));
            }
        }
    }
    out
}

/// `0199a1b2-0000-7000-8000-` and 12 digits: the fixtures' placeholder form.
fn placeholder(value: &str) -> bool {
    value.strip_prefix(["0199a1b2", "0000", "7000", "8000", ""].join("-").as_str()).is_some_and(|tail| tail.len() == 12 && tail.bytes().all(|b| b.is_ascii_digit()))
}

/// A JSON string at the start of `text`: its content (escapes as written) and the text after its closing quote.
fn json_string(text: &str) -> Option<(&str, &str)> {
    let body = text.strip_prefix('"')?;
    let mut escaped = false;
    for (i, c) in body.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Some((&body[..i], &body[i + 1..])),
            _ => {}
        }
    }
    None
}

/// Each `"<key>": <value>` in `line`: a string value's content, any other value up to the next `,`, `}` or `]`.
fn json_pairs(line: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('"') {
        let Some((key, after)) = json_string(&rest[open..]) else { break };
        rest = after;
        let Some(value) = after.trim_start().strip_prefix(':') else { continue };
        let value = value.trim_start();
        let (value, next) = json_string(value).unwrap_or_else(|| value.split_at(value.find([',', '}', ']']).unwrap_or(value.len())));
        out.push((key, value));
        rest = next;
    }
    out
}

/// A key as a pair names it: a bare word, quotes around it removed.
fn bare_key(key: &str) -> Option<&str> {
    let key = key.trim();
    let key = key.strip_prefix('"').and_then(|k| k.strip_suffix('"')).unwrap_or(key);
    (!key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))).then_some(key)
}

/// systemd's `Environment=` value: its blank-separated assignments, each perhaps quoted whole.
fn assignments(value: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = value.trim();
    while !rest.is_empty() {
        let (word, next) = match json_string(rest) {
            Some((quoted, next)) => (quoted, next),
            None => rest.split_at(rest.find([' ', '\t']).unwrap_or(rest.len())),
        };
        if let Some((key, value)) = word.split_once('=').and_then(|(key, value)| bare_key(key).map(|key| (key, value))) {
            out.push((key, value));
        }
        rest = next.trim_start();
    }
    out
}

/// Every `(key, value)` pair of one line (P-R88 (f)): each `"<key>": <value>` in it; else `<key> = <value>`
/// after an optional `export `, systemd's `Environment=` read as its assignments; else, in a YAML file,
/// `<key>: <value>` after an optional `- `.
fn pairs(line: &str, yaml: bool) -> Vec<(&str, &str)> {
    let line = line.trim();
    let json = json_pairs(line);
    if !json.is_empty() {
        return json;
    }
    let assignment = line.strip_prefix("export ").unwrap_or(line);
    if let Some((key, value)) = assignment.split_once('=').and_then(|(key, value)| bare_key(key).map(|key| (key, value))) {
        return if key == "Environment" { assignments(value) } else { vec![(key, value)] };
    }
    let item = line.strip_prefix("- ").unwrap_or(line);
    match item.split_once(':').and_then(|(key, value)| bare_key(key).map(|key| (key, value))) {
        Some(pair) if yaml => vec![pair],
        _ => Vec::new(),
    }
}

/// (f) `credential-value`, outside `.rs` files: every pair of a line (`pairs`) with a credential-shaped key holds
/// a short value, a path, a placeholder or a blank. The finding shows the key, never the value.
fn credential_value(file: &str, text: &str) -> Vec<Finding> {
    let yaml = file.ends_with(".yaml") || file.ends_with(".yml");
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        for (key, value) in pairs(line, yaml) {
            let lower = key.to_ascii_lowercase();
            if !CREDENTIAL_WORDS.iter().any(|w| lower.contains(w)) {
                continue;
            }
            let value: String = value.trim().trim_end_matches(',').trim().chars().filter(|c| !matches!(c, '"' | '\'')).collect();
            if value.chars().count() <= 11 || value.contains(['/', '<', '$', ' ', '\t']) || placeholder(&value) {
                continue;
            }
            out.push(finding(file, n + 1, "credential-value", format!("{key} = <{} characters>", value.chars().count())));
        }
    }
    out
}

/// (g) `env-name`: every name read through the environment readers starts with `AI_ENV_` or `CARGO_`, or is one
/// of `ALLOWED_ENV`.
fn env_name(file: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for needle in [concat!("env", "::var(\""), concat!("env", "::var_os(\""), concat!("env", "!(\"")] {
        for (at, _) in text.match_indices(needle) {
            let after = &text[at + needle.len()..];
            let name = &after[..after.find('"').unwrap_or(after.len())];
            if !(name.starts_with("AI_ENV_") || name.starts_with("CARGO_") || ALLOWED_ENV.contains(&name)) {
                out.push(finding(file, line_of(text, at), "env-name", name));
            }
        }
    }
    out
}

/// Every check that applies to `file` (P-R88): (d) and (g) in `.rs` files, (f) outside them.
fn scan(file: &str, text: &str) -> Vec<Finding> {
    let rust = file.ends_with(".rs");
    let mut out = ipv4(file, text);
    out.extend(url_host(file, text));
    out.extend(home_path(file, text));
    out.extend(source_name(file, text));
    if rust {
        out.extend(source_type(file, text));
        out.extend(env_name(file, text));
    } else {
        out.extend(credential_value(file, text));
    }
    out
}

/// Every file under `dir`, `target/` directories, `Cargo.lock` files and `*.bin` aside.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).map(|e| e.expect("a directory entry").path()).collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if path.is_dir() {
            if name != "target" {
                walk(&path, out);
            }
        } else if name != "Cargo.lock" && !name.ends_with(".bin") {
            out.push(path);
        }
    }
}

/// P-T9.
#[test]
fn public_crates_name_no_concrete_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for dir in REQUIRED_DIRS {
        assert!(root.join(dir).is_dir(), "{dir} exists");
        walk(&root.join(dir), &mut files);
    }
    let mut findings = Vec::new();
    let mut scanned = 0;
    for path in &files {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let Ok(text) = String::from_utf8(bytes) else { continue };
        let file = path.strip_prefix(&root).unwrap_or(path).to_string_lossy().replace('\\', "/");
        findings.extend(scan(&file, &text));
        scanned += 1;
    }
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");
    findings.extend(ipv4("README.md", &readme));
    findings.extend(url_host("README.md", &readme));
    assert!(scanned >= 25, "only {scanned} files scanned: a guard that scans nothing proves nothing");
    let shown: Vec<String> = findings.iter().map(ToString::to_string).collect();
    assert!(findings.is_empty(), "the public crates name what they must not:\n{}", shown.join("\n"));
}

/// P-T10.
#[test]
fn the_leak_checks_fire_on_planted_text() {
    type Check = fn(&str, &str) -> Vec<Finding>;
    let one = |check: Check, name: &str, file: &str, text: &str| {
        let found = check(file, text);
        assert_eq!(found.len(), 1, "{name} on {text:?}: {found:?}");
        assert_eq!(found[0].check, name);
        found.into_iter().next().map(|f| f.text).unwrap_or_default()
    };
    let none = |check: Check, file: &str, text: &str| {
        let found = check(file, text);
        assert!(found.is_empty(), "{text:?}: {found:?}");
    };

    let planted = format!("{} and {}", ["10", "9", "8", "7"].join("."), ["10", "42", "300", "1"].join("."));
    assert_eq!(one(ipv4, "ipv4", "x.rs", &planted), ["10", "9", "8", "7"].join("."));
    for clean in [["127", "0", "0", "1"], ["10", "42", "0", "20"], ["192", "0", "2", "1"], ["169", "254", "169", "254"]] {
        none(ipv4, "x.rs", &format!("addr {}/32", clean.join(".")));
    }
    none(ipv4, "x.rs", &["1", "2", "3", "4", "5"].join("."));
    let planted = format!("the relay at {}.", ["10", "9", "8", "7"].join("."));
    assert_eq!(one(ipv4, "ipv4", "x.md", &planted), ["10", "9", "8", "7"].join("."), "a full stop after it");
    none(ipv4, "x.md", &format!("the relay at {}.", ["10", "42", "0", "20"].join(".")));
    none(ipv4, "x.md", &format!("version {}.", ["1", "2", "3", "4", "5"].join(".")));
    let corp = ["db", "corp", "internal"].join(".");
    assert_eq!(one(url_host, "url-host", "x.md", &format!("see https{}{corp}/x", "://")), corp);
    none(url_host, "x.md", "see https://relay.example.com:443 and https://github.com/dfstio/ai-env");
    none(url_host, "x.rs", "format!(\"https://{host}:443\")");
    let home = [["", "home", ""].join("/"), "someone".to_string()].concat();
    one(home_path, "home-path", "x.rs", &home);
    let impl_line = |ty: &str| format!("impl {}{ty} {{", concat!("DataSource", " for "));
    assert_eq!(one(source_type, "source-type", "x.rs", &impl_line("WarehouseSource")), concat!("DataSource", " for ", "WarehouseSource"));
    none(source_type, "x.rs", &impl_line("EchoSource"));
    let new_call = |name: &str| format!("{}\"{name}\", \"0.1.0\", \"d\")", concat!("SourceDescriptor", "::new("));
    assert_eq!(one(source_name, "source-name", "x.rs", &new_call("billing")), "billing");
    none(source_name, "x.rs", &new_call("test-x"));
    none(source_name, "x.rs", &format!("{}\n    \"echo-2\")", concat!("EchoSource", "::named(")));
    let api_token = format!("api_{} = \"{}\"", "token", ["a1b2", "c3d4", "e5f6", "g7h8"].concat());
    assert_eq!(one(credential_value, "credential-value", "x.toml", &api_token), "api_token = <16 characters>");
    let clean = ["key_file = \"/etc/ai-env-worker/worker.key\"", "token = \"<token>\"", "secret = \"0199a1b2-0000-7000-8000-000000000001\""];
    none(credential_value, "x.toml", &clean.join("\n"));
    // (f) reads every pair of a JSON line, an `export`, systemd's `Environment=` assignments, a quoted TOML key
    // and, in a YAML file, `<key>: <value>`.
    let value = ["a1b2", "c3d4", "e5f6", "g7h8"].concat();
    let token_key = ["api", "token"].join("_");
    let env_key = ["AI", "ENV", "TOKEN"].join("_");
    let forms = [
        ("x.json", format!("{{\"name\": \"worker-a\", \"{token_key}\": \"{value}\"}}"), token_key.clone()),
        ("x.env", format!("export {}={value}", token_key.to_ascii_uppercase()), token_key.to_ascii_uppercase()),
        ("x.service", format!("Environment=AI_ENV_RELAY_URL=https://relay.example.com:443 \"{env_key}={value}\""), env_key.clone()),
        ("x.toml", format!("\"{token_key}\" = \"{value}\""), token_key.clone()),
        ("x.yaml", format!("- {token_key}: {value}"), token_key.clone()),
    ];
    for (file, text, key) in &forms {
        assert_eq!(one(credential_value, "credential-value", file, text), format!("{key} = <16 characters>"), "{file}");
    }
    none(credential_value, "x.md", &format!("{token_key}: {value}"));
    let clean = [
        "{\"worker_id\": \"worker-a\", \"public_key\": \"<base64>\"}",
        "export AI_ENV_KEY_FILE=/etc/ai-env-worker/worker.key",
        "Environment=AI_ENV_RELAY_URL=https://relay.example.com:443 AI_ENV_WORKER_KEY=%d/worker.key",
        "token: <token>",
    ];
    none(credential_value, "x.yaml", &clean.join("\n"));
    let read = |name: &str| format!("{}(\"{name}\")", concat!("env", "::var"));
    assert_eq!(one(env_name, "env-name", "x.rs", &read("SOME_DB_URL")), "SOME_DB_URL");
    none(env_name, "x.rs", &read("AI_ENV_RELAY_URL"));
    // The whole scan keeps (f) out of Rust files, and (d) and (g) out of the others.
    assert!(scan("x.rs", &api_token).is_empty());
    assert!(scan("x.toml", &read("SOME_DB_URL")).is_empty());
    assert_eq!(scan("x.rs", &read("SOME_DB_URL")).len(), 1);
}
