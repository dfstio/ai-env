//! The relay's answers as the socket's (§V-vm.3.6): a `SourceStatus` with its descriptor becomes a [`SourceEntry`]
//! (enums as words, an unknown number `unspecified`; absent limits zeros; a schema or an example parsed when it
//! parses, else its text as a JSON string), a call's bytes a [`Body`] (V-R26), a status or an in-band error a
//! [`Failure`] with its local code and a cleaned message (V-R25).
use crate::dial::{Failure, REQUEST_ID_HEADER};
use crate::local::{code_of_grpc, Body, LimitsEntry, OpEntry, SourceEntry};
use ai_env_relay_proto::v1;
use base64::Engine as _;

/// A message's bound, in characters.
const MESSAGE_MAX: usize = 300;

fn kind_word(kind: i32) -> &'static str {
    match v1::SourceKind::try_from(kind).unwrap_or(v1::SourceKind::Unspecified) {
        v1::SourceKind::Unspecified => "unspecified",
        v1::SourceKind::Sql => "sql",
        v1::SourceKind::HttpApi => "http_api",
        v1::SourceKind::GrpcApi => "grpc_api",
        v1::SourceKind::Logs => "logs",
        v1::SourceKind::Metrics => "metrics",
        v1::SourceKind::HostStats => "host_stats",
        v1::SourceKind::Other => "other",
    }
}

fn sensitivity_word(s: i32) -> &'static str {
    match v1::Sensitivity::try_from(s).unwrap_or(v1::Sensitivity::Unspecified) {
        v1::Sensitivity::Unspecified => "unspecified",
        v1::Sensitivity::Public => "public",
        v1::Sensitivity::Internal => "internal",
        v1::Sensitivity::Restricted => "restricted",
    }
}

fn output_word(o: i32) -> &'static str {
    match v1::OutputKind::try_from(o).unwrap_or(v1::OutputKind::Unspecified) {
        v1::OutputKind::Unspecified => "unspecified",
        v1::OutputKind::Json => "json",
        v1::OutputKind::Text => "text",
        v1::OutputKind::Stream => "stream",
    }
}

/// The text parsed when it parses, else the text as a JSON string.
fn json_or_text(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::Value::String(text.to_string()))
}

fn limits(l: Option<&v1::Limits>) -> LimitsEntry {
    l.map_or(LimitsEntry { max_bytes: 0, max_rows: 0, max_chunks: 0 }, |l| LimitsEntry { max_bytes: l.max_bytes, max_rows: l.max_rows, max_chunks: l.max_chunks })
}

/// One source of `ListSources`, as the socket answers it; `None` without a descriptor.
#[must_use]
pub fn source_entry(s: &v1::SourceStatus) -> Option<SourceEntry> {
    let d = s.descriptor.as_ref()?;
    let ops = d
        .ops
        .iter()
        .map(|op| OpEntry {
            name: op.name.clone(),
            description: op.description.clone(),
            params_schema: json_or_text(&op.params_json_schema),
            output: output_word(op.output).to_string(),
            read_only: op.read_only,
            default_limits: limits(op.default_limits.as_ref()),
            max_limits: limits(op.max_limits.as_ref()),
            examples: op.examples.iter().map(|e| json_or_text(e)).collect(),
        })
        .collect();
    Some(SourceEntry {
        name: d.name.clone(),
        version: d.version.clone(),
        description: d.description.clone(),
        kind: kind_word(d.kind).to_string(),
        env: d.env.clone(),
        sensitivity: sensitivity_word(d.sensitivity).to_string(),
        available: s.available,
        last_seen_unix_ms: s.last_seen_unix_ms,
        ops,
    })
}

/// A JSON content type: `application/json` or a `+json` suffix, parameters aside.
fn json_content(content_type: &str) -> bool {
    let essence = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
}

/// V-R26: a JSON content type whose bytes parse and whose every number reads back as written → `json`; else UTF-8 (a
/// cut ends at the last whole character) → `text`; else → `b64` (standard).
#[must_use]
pub fn body_of(content_type: &str, data: &[u8]) -> Body {
    if json_content(content_type) {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
            if numbers_read_back(data) {
                return Body::Json(v);
            }
        }
    }
    match std::str::from_utf8(data) {
        Ok(text) => Body::Text(text.to_string()),
        // Only an incomplete character at the very end (a cut): the whole ones before it.
        Err(e) if e.error_len().is_none() => Body::Text(String::from_utf8_lossy(&data[..e.valid_up_to()]).into_owned()),
        Err(_) => Body::B64(base64::engine::general_purpose::STANDARD.encode(data)),
    }
}

/// A call's body (V-R26): [`body_of`] when the output was cut (`truncated`: by the client at its limit, or upstream),
/// where an incomplete last character is the cut's; output nothing cut that is not UTF-8 throughout is `b64`, every
/// byte kept.
#[must_use]
pub(crate) fn body_of_output(content_type: &str, data: &[u8], truncated: bool) -> Body {
    if !truncated && std::str::from_utf8(data).is_err() {
        return Body::B64(base64::engine::general_purpose::STANDARD.encode(data));
    }
    body_of(content_type, data)
}

/// Whether every number of `json` (bytes that parse) reads back as written, so a `json` body never reaches the agent
/// rounded. serde_json keeps an integer that fits i64 or u64 exactly and reads any other number as an f64, which the
/// answer line writes in its shortest form and the MCP server reads and writes again: the number reads back when that
/// form has the token's decimal value and the second read leaves it as it is. A big integer
/// (`12345678901234567890123`), a decimal longer than an f64 holds and an underflow (`1e-400`, read as 0) do not.
fn numbers_read_back(json: &[u8]) -> bool {
    /// A number's decimal value: its sign, its digits without leading or trailing zeros and the power of ten of the
    /// last one (saturating: JSON bounds no exponent); zero is `(false, "", 0)`, whatever its sign or exponent.
    fn decimal(number: &str) -> (bool, String, i64) {
        let (negative, rest) = number.strip_prefix('-').map_or((false, number), |r| (true, r));
        let (mantissa, exponent) = rest.split_once(['e', 'E']).unwrap_or((rest, "0"));
        let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let exponent = exponent.strip_prefix('+').unwrap_or(exponent);
        let (below, magnitude) = exponent.strip_prefix('-').map_or((false, exponent), |m| (true, m));
        let magnitude = magnitude.bytes().fold(0i64, |e, b| e.saturating_mul(10).saturating_add(i64::from(b.wrapping_sub(b'0'))));
        let digits = format!("{int}{frac}");
        let significant = digits.trim_start_matches('0');
        let kept = significant.trim_end_matches('0');
        if kept.is_empty() {
            return (false, String::new(), 0);
        }
        let len = |s: &str| i64::try_from(s.len()).unwrap_or(i64::MAX);
        let power = if below { -magnitude } else { magnitude };
        // Each fraction digit lowers the last digit's power; each trailing zero dropped raises it.
        let power = power.saturating_sub(len(frac)).saturating_add(len(significant) - len(kept));
        (negative, kept.to_string(), power)
    }
    let mut i = 0;
    while i < json.len() {
        match json[i] {
            // A string, to its closing quote: the byte after a backslash is skipped (`\"` and `\\` among them).
            b'"' => {
                i += 1;
                while i < json.len() && json[i] != b'"' {
                    i += if json[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                while i < json.len() && matches!(json[i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    i += 1;
                }
                let token = std::str::from_utf8(&json[start..i]).unwrap_or_default();
                if !token.contains(['.', 'e', 'E']) && (token.parse::<i64>().is_ok() || token.parse::<u64>().is_ok()) {
                    continue;
                }
                let Ok(once) = serde_json::from_str::<serde_json::Number>(token).map(|n| n.to_string()) else { return false };
                let again = serde_json::from_str::<serde_json::Number>(&once).map(|n| n.to_string());
                if decimal(&once) != decimal(token) || !again.is_ok_and(|a| a == once) {
                    return false;
                }
            }
            _ => i += 1,
        }
    }
    true
}

/// The relay's request id in `metadata` (R-30), when it holds a non-empty one.
pub(crate) fn request_id_of(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata.get(REQUEST_ID_HEADER).and_then(|v| v.to_str().ok()).filter(|id| !id.is_empty()).map(str::to_string)
}

/// A status's code as its local word, with its cleaned message and the request id the status carries (R-30).
#[must_use]
pub fn failure_of_status(s: &tonic::Status) -> Failure {
    Failure { code: code_of_grpc(s.code() as i32), message: clean_message(s.message()), request_id: request_id_of(s.metadata()) }
}

/// An in-band error (google.rpc.Code) as its local word, with its cleaned message; its chunk's request id is the
/// caller's to add.
#[must_use]
pub fn failure_of_chunk(e: &v1::Error) -> Failure {
    Failure { code: code_of_grpc(e.code), message: clean_message(&e.message), request_id: None }
}

/// Control characters dropped, at most 300 characters.
#[must_use]
pub fn clean_message(m: &str) -> String {
    m.chars().filter(|c| !c.is_control()).take(MESSAGE_MAX).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::Code;

    /// JSON content types that parse are `json` (parameters and `+json` too); invalid JSON is `text`, and so is JSON
    /// with a number that would not read back as written (a big integer, a long decimal, an underflow, a form the
    /// second read changes), while plain numbers stay `json`; a cut in a multibyte character ends before it; bytes
    /// that are not UTF-8 are `b64`, and so is a call's output that nothing cut and that ends in an incomplete
    /// character. Kills M-V62, M-V63.
    #[test]
    fn bodies_are_json_text_or_base64() {
        assert_eq!(body_of("application/json", b"{\"x\":1}"), Body::Json(serde_json::json!({"x": 1})));
        assert_eq!(body_of("application/json; charset=utf-8", b"[1,2]"), Body::Json(serde_json::json!([1, 2])));
        assert_eq!(body_of("application/vnd.example+json", b"true"), Body::Json(serde_json::Value::Bool(true)));
        assert_eq!(body_of("application/json", b"{\"x\":"), Body::Text("{\"x\":".into()), "a cut JSON is text");
        assert_eq!(body_of("text/plain", b"{\"x\":1}"), Body::Text("{\"x\":1}".into()), "JSON bytes under a text type stay text");
        let e_acute = "a\u{e9}".as_bytes();
        assert_eq!(e_acute.len(), 3);
        assert_eq!(body_of("text/plain", &e_acute[..2]), Body::Text("a".into()), "the cut character is dropped");
        assert_eq!(body_of("text/plain", e_acute), Body::Text("a\u{e9}".into()));
        assert_eq!(body_of("application/octet-stream", &[0xff, 0x00, 0x41]), Body::B64("/wBB".into()));
        assert_eq!(body_of("text/plain", &[0x41, 0xff, 0x41]), Body::B64("Qf9B".into()), "invalid in the middle: base64");
        assert_eq!(body_of("", b""), Body::Text(String::new()));
        // A call's output: an incomplete last character is a cut's only when the output was cut.
        assert_eq!(body_of_output("text/plain", &e_acute[..2], true), Body::Text("a".into()), "cut: the whole characters");
        assert_eq!(body_of_output("text/plain", &e_acute[..2], false), Body::B64("YcM=".into()), "nothing cut: not UTF-8, every byte");
        assert_eq!(body_of_output("text/plain", e_acute, false), Body::Text("a\u{e9}".into()));
        assert_eq!(body_of_output("application/json", b"{\"x\":1}", false), Body::Json(serde_json::json!({"x": 1})));
        assert_eq!(body_of_output("application/json", b"{\"x\":", true), Body::Text("{\"x\":".into()), "a cut JSON is text");
        // V-R26: a number the json body would round makes it text, every byte as the source wrote it.
        for rounded in [
            "{\"amount\":12345678901234567890123}",
            "[18446744073709551616]",
            "[-9223372036854775809]",
            "{\"x\":0.1000000000000000055511151231257827}",
            "[3.14159265358979323846]",
            "[1e-400]",
            "{\"a\":[1,{\"b\":-1E-400}]}",
            "[2.6565160879968280e-56]",
        ] {
            assert_eq!(body_of("application/json", rounded.as_bytes()), Body::Text(rounded.into()), "{rounded}");
            assert_eq!(body_of_output("application/json", rounded.as_bytes(), false), Body::Text(rounded.into()), "{rounded}");
        }
        let plain = r#"{"a":1,"b":-2,"c":1.5,"d":0.1,"e":1e3,"f":-0,"g":18446744073709551615,"h":-9223372036854775808,"i":2.5E-3,"j":100.0,"k":0.30000000000000004,"l":1e+20,"m":0e999999999999999999,"n":"12345678901234567890123","o":"a\"1e-400\\","p":[-0.0,7e-1]}"#;
        let Body::Json(v) = body_of("application/json", plain.as_bytes()) else { panic!("plain numbers stay json") };
        assert_eq!(v, serde_json::from_str::<serde_json::Value>(plain).unwrap());
        assert_eq!((v["g"].as_u64(), v["h"].as_i64(), v["n"].as_str(), v["o"].as_str()), (Some(u64::MAX), Some(i64::MIN), Some("12345678901234567890123"), Some("a\"1e-400\\")));
    }

    /// One `SourceStatus` of every field becomes §V-vm.3.6's entry (enums as words, an unknown number
    /// `unspecified`, absent limits zeros, a schema or example that does not parse kept as text); a status without a
    /// descriptor is `None`.
    #[test]
    fn catalog_entries_carry_every_descriptor_field() {
        let op = v1::OpDescriptor {
            name: "echo".into(),
            description: "Return params".into(),
            params_json_schema: "{\"type\":\"object\"}".into(),
            output: v1::OutputKind::Json as i32,
            read_only: true,
            default_limits: Some(v1::Limits { max_bytes: 65_536, max_rows: 0, max_chunks: 0 }),
            max_limits: Some(v1::Limits { max_bytes: 1_048_576, max_rows: 10, max_chunks: 2 }),
            examples: vec!["{\"x\":1}".into(), "not json".into()],
        };
        let bare = v1::OpDescriptor { name: "tail".into(), description: String::new(), params_json_schema: "{".into(), output: 9, read_only: false, default_limits: None, max_limits: None, examples: Vec::new() };
        let status = v1::SourceStatus {
            descriptor: Some(v1::SourceDescriptor { name: "echo".into(), version: "0.1.0".into(), description: "Echo its parameters".into(), kind: v1::SourceKind::Other as i32, env: "test".into(), sensitivity: v1::Sensitivity::Internal as i32, ops: vec![op, bare] }),
            available: true,
            last_seen_unix_ms: 1_761_730_000_000,
        };
        let e = source_entry(&status).unwrap();
        let line = serde_json::to_string(&e).unwrap();
        assert_eq!(
            line,
            r#"{"name":"echo","version":"0.1.0","description":"Echo its parameters","kind":"other","env":"test","sensitivity":"internal","available":true,"last_seen_unix_ms":1761730000000,"ops":[{"name":"echo","description":"Return params","params_schema":{"type":"object"},"output":"json","read_only":true,"default_limits":{"max_bytes":65536,"max_rows":0,"max_chunks":0},"max_limits":{"max_bytes":1048576,"max_rows":10,"max_chunks":2},"examples":[{"x":1},"not json"]},{"name":"tail","description":"","params_schema":"{","output":"unspecified","read_only":false,"default_limits":{"max_bytes":0,"max_rows":0,"max_chunks":0},"max_limits":{"max_bytes":0,"max_rows":0,"max_chunks":0},"examples":[]}]}"#
        );
        let words = |k: i32| {
            let mut s = status.clone();
            s.descriptor.as_mut().unwrap().kind = k;
            source_entry(&s).unwrap().kind
        };
        assert_eq!((0..=8).map(words).collect::<Vec<_>>(), ["unspecified", "sql", "http_api", "grpc_api", "logs", "metrics", "host_stats", "other", "unspecified"]);
        let sens = |k: i32| {
            let mut s = status.clone();
            s.descriptor.as_mut().unwrap().sensitivity = k;
            source_entry(&s).unwrap().sensitivity
        };
        assert_eq!((0..=4).map(sens).collect::<Vec<_>>(), ["unspecified", "public", "internal", "restricted", "unspecified"]);
        assert_eq!(source_entry(&v1::SourceStatus { descriptor: None, available: true, last_seen_unix_ms: 1 }), None);
    }

    /// Statuses and in-band errors keep their code's word and a clean message: control characters dropped, 300
    /// characters at most; a status keeps the relay's request id it carries (R-30), an in-band error none of its own.
    /// Control.
    #[test]
    fn failures_carry_their_code_and_a_clean_message() {
        let f = failure_of_status(&tonic::Status::permission_denied("denied by grant"));
        assert_eq!((f.code, f.message.as_str(), f.request_id), (Code::PermissionDenied, "denied by grant", None));
        let mut named = tonic::Status::permission_denied("denied by grant");
        named.metadata_mut().insert("x-ai-env-request-id", tonic::metadata::MetadataValue::from_static("0199a1b2-0000-7000-8000-00000000000a"));
        assert_eq!(failure_of_status(&named).request_id.as_deref(), Some("0199a1b2-0000-7000-8000-00000000000a"));
        named.metadata_mut().insert("x-ai-env-request-id", tonic::metadata::MetadataValue::from_static(""));
        assert_eq!(failure_of_status(&named).request_id, None, "an empty id is none");
        assert_eq!(failure_of_chunk(&v1::Error { code: 5, message: "no such row".into() }).request_id, None);
        let f = failure_of_chunk(&v1::Error { code: 5, message: "no such\nrow\u{1b}[31m".into() });
        assert_eq!((f.code, f.message.as_str()), (Code::NotFound, "no suchrow[31m"));
        assert_eq!(failure_of_chunk(&v1::Error { code: 0, message: String::new() }).code, Code::Unknown, "an error never carries OK");
        assert_eq!(clean_message(&"x".repeat(400)).len(), 300);
        assert_eq!(clean_message(&"\u{e9}".repeat(400)).chars().count(), 300, "characters, not bytes");
    }
}
