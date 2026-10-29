//! Descriptors, limits and deadlines (plans/s13-contracts.md §P-proto-sdk.6.3, P-R41 to P-R47).

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::names;

/// An op's deadline when the call names none.
pub const DEADLINE_DEFAULT: Duration = Duration::from_secs(30);
/// An op's longest deadline unless it says otherwise.
pub const DEADLINE_OP_MAX: Duration = Duration::from_secs(120);
/// No op's deadline is longer.
pub const DEADLINE_CEILING: Duration = Duration::from_secs(600);

/// What kind of backend a source fronts: a label for the catalog (the proto's `SourceKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceKind {
    /// A SQL database (read-only credentials).
    Sql,
    /// An HTTP API.
    HttpApi,
    /// A gRPC API.
    GrpcApi,
    /// Log files.
    Logs,
    /// Metrics.
    Metrics,
    /// A host's CPU, memory, disks and processes.
    HostStats,
    /// Anything else.
    #[default]
    Other,
}

impl SourceKind {
    /// Every kind, in declaration order.
    pub const ALL: [SourceKind; 7] = [
        SourceKind::Sql,
        SourceKind::HttpApi,
        SourceKind::GrpcApi,
        SourceKind::Logs,
        SourceKind::Metrics,
        SourceKind::HostStats,
        SourceKind::Other,
    ];

    /// The proto's number (P-R31): `Sql` 1 … `Other` 7; none is 0.
    #[must_use]
    pub const fn wire(self) -> i32 {
        match self {
            SourceKind::Sql => 1,
            SourceKind::HttpApi => 2,
            SourceKind::GrpcApi => 3,
            SourceKind::Logs => 4,
            SourceKind::Metrics => 5,
            SourceKind::HostStats => 6,
            SourceKind::Other => 7,
        }
    }

    /// `sql`, `http_api`, `grpc_api`, `logs`, `metrics`, `host_stats`, `other`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            SourceKind::Sql => "sql",
            SourceKind::HttpApi => "http_api",
            SourceKind::GrpcApi => "grpc_api",
            SourceKind::Logs => "logs",
            SourceKind::Metrics => "metrics",
            SourceKind::HostStats => "host_stats",
            SourceKind::Other => "other",
        }
    }
}

/// How sensitive a source's data is: a label for the catalog and the grants (the proto's `Sensitivity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Sensitivity {
    /// Public data.
    Public,
    /// Internal data.
    #[default]
    Internal,
    /// Restricted data: the strictest class, also what an unknown class reads as (LD-P18).
    Restricted,
}

impl Sensitivity {
    /// Every class, in declaration order.
    pub const ALL: [Sensitivity; 3] = [Sensitivity::Public, Sensitivity::Internal, Sensitivity::Restricted];

    /// The proto's number (P-R31): `Public` 1, `Internal` 2, `Restricted` 3.
    #[must_use]
    pub const fn wire(self) -> i32 {
        match self {
            Sensitivity::Public => 1,
            Sensitivity::Internal => 2,
            Sensitivity::Restricted => 3,
        }
    }

    /// `public`, `internal`, `restricted`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Sensitivity::Public => "public",
            Sensitivity::Internal => "internal",
            Sensitivity::Restricted => "restricted",
        }
    }
}

/// What an op answers (the proto's `OutputKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutputKind {
    /// One JSON value.
    #[default]
    Json,
    /// One text.
    Text,
    /// A stream of text items (lines or NDJSON records).
    Stream,
}

impl OutputKind {
    /// Every kind, in declaration order.
    pub const ALL: [OutputKind; 3] = [OutputKind::Json, OutputKind::Text, OutputKind::Stream];

    /// The proto's number (P-R31): `Json` 1, `Text` 2, `Stream` 3.
    #[must_use]
    pub const fn wire(self) -> i32 {
        match self {
            OutputKind::Json => 1,
            OutputKind::Text => 2,
            OutputKind::Stream => 3,
        }
    }

    /// `json`, `text`, `stream`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            OutputKind::Json => "json",
            OutputKind::Text => "text",
            OutputKind::Stream => "stream",
        }
    }
}

/// A call's caps; on the wire a 0 field means "not given" (P-R45).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Limits {
    /// The most bytes of output.
    pub max_bytes: u64,
    /// The most rows (a stream's items).
    pub max_rows: u32,
    /// The most chunks.
    pub max_chunks: u32,
}

impl Limits {
    /// 0, 0, 0: the wire's "not given".
    pub const UNSET: Limits = Limits::new(0, 0, 0);
    /// 1 048 576 bytes, 1 000 rows, 16 chunks (LD-P11).
    pub const DEFAULT: Limits = Limits::new(1_048_576, 1_000, 16);
    /// 16 777 216 bytes, 100 000 rows, 256 chunks (LD-P11).
    pub const CEILING: Limits = Limits::new(16_777_216, 100_000, 256);

    /// Limits of these three values.
    #[must_use]
    pub const fn new(max_bytes: u64, max_rows: u32, max_chunks: u32) -> Limits {
        Limits { max_bytes, max_rows, max_chunks }
    }

    /// The same limits with `max_bytes` set.
    #[must_use]
    pub const fn with_max_bytes(self, n: u64) -> Limits {
        Limits { max_bytes: n, ..self }
    }

    /// The same limits with `max_rows` set.
    #[must_use]
    pub const fn with_max_rows(self, n: u32) -> Limits {
        Limits { max_rows: n, ..self }
    }

    /// The same limits with `max_chunks` set.
    #[must_use]
    pub const fn with_max_chunks(self, n: u32) -> Limits {
        Limits { max_chunks: n, ..self }
    }

    /// P-R45, per field: the cap is `max`'s value (`CEILING`'s when 0, never above `CEILING`); the want is
    /// `requested`'s value, else `default`'s, else `DEFAULT`'s (each "else" when 0); the result is the smaller.
    #[must_use]
    pub fn resolve(requested: Limits, default: Limits, max: Limits) -> Limits {
        fn field<T: Copy + Ord + Default>(requested: T, default: T, max: T, fallback: T, ceiling: T) -> T {
            let zero = T::default();
            let cap = if max == zero { ceiling } else { max.min(ceiling) };
            let want = if requested != zero {
                requested
            } else if default != zero {
                default
            } else {
                fallback
            };
            want.min(cap)
        }
        Limits {
            max_bytes: field(requested.max_bytes, default.max_bytes, max.max_bytes, Limits::DEFAULT.max_bytes, Limits::CEILING.max_bytes),
            max_rows: field(requested.max_rows, default.max_rows, max.max_rows, Limits::DEFAULT.max_rows, Limits::CEILING.max_rows),
            max_chunks: field(requested.max_chunks, default.max_chunks, max.max_chunks, Limits::DEFAULT.max_chunks, Limits::CEILING.max_chunks),
        }
    }
}

impl Default for Limits {
    /// `Limits::DEFAULT`.
    fn default() -> Self {
        Limits::DEFAULT
    }
}

/// What a source advertises in the catalog (P-R33, P-R41).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SourceDescriptor {
    /// The source's name (P-R40).
    pub name: String,
    /// Its version: 1 to 32 of `[0-9A-Za-z.+-]`.
    pub version: String,
    /// What it serves: 1 to 1024 bytes.
    pub description: String,
    /// Its kind.
    pub kind: SourceKind,
    /// A free-form environment tag (`prod`, `test`): 0 to 32 of `[a-z0-9_-]`.
    pub env: String,
    /// Its sensitivity.
    pub sensitivity: Sensitivity,
    /// Its ops: 1 to 64.
    pub ops: Vec<OpDescriptor>,
}

impl SourceDescriptor {
    /// A descriptor of kind `Other`, env empty, sensitivity `Internal` and no op (P-R46).
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>, description: impl Into<String>) -> Self {
        SourceDescriptor {
            name: name.into(),
            version: version.into(),
            description: description.into(),
            kind: SourceKind::default(),
            env: String::new(),
            sensitivity: Sensitivity::default(),
            ops: Vec::new(),
        }
    }

    /// The same descriptor with `kind` set.
    #[must_use]
    pub fn kind(mut self, kind: SourceKind) -> Self {
        self.kind = kind;
        self
    }

    /// The same descriptor with `env` set.
    #[must_use]
    pub fn env(mut self, env: impl Into<String>) -> Self {
        self.env = env.into();
        self
    }

    /// The same descriptor with `sensitivity` set.
    #[must_use]
    pub fn sensitivity(mut self, s: Sensitivity) -> Self {
        self.sensitivity = s;
        self
    }

    /// The same descriptor with `op` added after the others.
    #[must_use]
    pub fn op(mut self, op: OpDescriptor) -> Self {
        self.ops.push(op);
        self
    }

    /// The op of that name, if any.
    #[must_use]
    pub fn op_named(&self, name: &str) -> Option<&OpDescriptor> {
        self.ops.iter().find(|o| o.name == name)
    }

    /// The first structural fault in P-R41's order, then each op's (P-R42); it never calls the source (P-R43).
    pub fn validate(&self) -> Result<(), DescriptorError> {
        let fault = |field: &str, reason: &str| Err(DescriptorError::new(self.name.clone(), field, reason));
        if let Err(reason) = names::check_source_name(&self.name) {
            return fault("name", &reason);
        }
        let version_ok = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-');
        if !(1..=VERSION_MAX).contains(&self.version.len()) || !self.version.bytes().all(version_ok) {
            return fault("version", "1 to 32 of [0-9A-Za-z.+-]");
        }
        if !(1..=DESCRIPTION_MAX).contains(&self.description.len()) {
            return fault("description", "1 to 1024 bytes");
        }
        let env_ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-');
        if self.env.len() > ENV_MAX || !self.env.bytes().all(env_ok) {
            return fault("env", "0 to 32 of [a-z0-9_-]");
        }
        if self.ops.is_empty() {
            return fault("ops", "at least one op");
        }
        if self.ops.len() > OPS_MAX {
            return fault("ops", "at most 64 ops");
        }
        for (i, op) in self.ops.iter().enumerate() {
            if let Err((field, reason)) = op.check(&self.ops[..i]) {
                return fault(&format!("ops[{i}].{field}"), &reason);
            }
        }
        Ok(())
    }
}

/// The longest version (P-R41).
const VERSION_MAX: usize = 32;
/// The longest description, of a source or an op (P-R41, P-R42).
const DESCRIPTION_MAX: usize = 1024;
/// The longest env tag (P-R41).
const ENV_MAX: usize = 32;
/// The most ops of one source (P-R41).
const OPS_MAX: usize = 64;
/// The longest params schema, as compact JSON (P-R42).
const SCHEMA_MAX: usize = 16_384;
/// The most examples of one op (P-R42).
const EXAMPLES_MAX: usize = 8;
/// The longest example, as compact JSON (P-R42).
const EXAMPLE_MAX: usize = 4096;

/// One op of a source (P-R42, P-R46).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OpDescriptor {
    /// The op's name (P-R40).
    pub name: String,
    /// What it does: 1 to 1024 bytes.
    pub description: String,
    /// A JSON Schema (draft 2020-12) object for its params, `"type": "object"`.
    pub params_schema: serde_json::Value,
    /// What it answers.
    pub output: OutputKind,
    /// A label only: read-only is enforced by the source's credentials, never by this flag.
    pub read_only: bool,
    /// The limits of a call that names none.
    pub default_limits: Limits,
    /// The most a call may ask for.
    pub max_limits: Limits,
    /// The deadline of a call that names none.
    #[serde(rename = "default_deadline_ms", with = "ms")]
    pub default_deadline: Duration,
    /// The longest deadline a call may ask for.
    #[serde(rename = "max_deadline_ms", with = "ms")]
    pub max_deadline: Duration,
    /// Example params objects, to help an agent call the op: at most 8.
    pub examples: Vec<serde_json::Value>,
}

impl OpDescriptor {
    /// An op with P-R46's defaults: params `{"type":"object","additionalProperties":false}`, output `Json`,
    /// `read_only` false, limits `DEFAULT` and `CEILING`, deadlines 30 s and 120 s, no example.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        OpDescriptor {
            name: name.into(),
            description: description.into(),
            params_schema: serde_json::json!({"type": "object", "additionalProperties": false}),
            output: OutputKind::Json,
            read_only: false,
            default_limits: Limits::DEFAULT,
            max_limits: Limits::CEILING,
            default_deadline: DEADLINE_DEFAULT,
            max_deadline: DEADLINE_OP_MAX,
            examples: Vec::new(),
        }
    }

    /// The same op with its params schema set.
    #[must_use]
    pub fn params_schema(mut self, schema: serde_json::Value) -> Self {
        self.params_schema = schema;
        self
    }

    /// The same op with its output kind set.
    #[must_use]
    pub fn output(mut self, kind: OutputKind) -> Self {
        self.output = kind;
        self
    }

    /// The same op with its read-only label set.
    #[must_use]
    pub fn read_only(mut self, yes: bool) -> Self {
        self.read_only = yes;
        self
    }

    /// The same op with its default limits set.
    #[must_use]
    pub fn default_limits(mut self, l: Limits) -> Self {
        self.default_limits = l;
        self
    }

    /// The same op with its max limits set.
    #[must_use]
    pub fn max_limits(mut self, l: Limits) -> Self {
        self.max_limits = l;
        self
    }

    /// The same op with its default and max deadlines set.
    #[must_use]
    pub fn deadlines(mut self, default: Duration, max: Duration) -> Self {
        self.default_deadline = default;
        self.max_deadline = max;
        self
    }

    /// The same op with one more example params object.
    #[must_use]
    pub fn example(mut self, params: serde_json::Value) -> Self {
        self.examples.push(params);
        self
    }

    /// `Limits::resolve(requested, default_limits, max_limits)` (P-R45).
    #[must_use]
    pub fn effective_limits(&self, requested: Limits) -> Limits {
        Limits::resolve(requested, self.default_limits, self.max_limits)
    }

    /// P-R47: `requested_ms` 0 is `default_deadline`, else that many milliseconds; then no longer than
    /// `max_deadline` nor `DEADLINE_CEILING`, and at least 1 ms.
    #[must_use]
    pub fn effective_deadline(&self, requested_ms: u32) -> Duration {
        let want = if requested_ms == 0 { self.default_deadline } else { Duration::from_millis(u64::from(requested_ms)) };
        want.min(self.max_deadline).min(DEADLINE_CEILING).max(Duration::from_millis(1))
    }

    /// P-R42 for one op, `earlier` being the ops before it: the first fault as (the field under `ops[<i>]`,
    /// the reason).
    fn check(&self, earlier: &[OpDescriptor]) -> Result<(), (String, String)> {
        let fault = |field: &str, reason: String| Err((field.to_string(), reason));
        if let Err(reason) = names::check_op_name(&self.name) {
            return fault("name", reason);
        }
        if earlier.iter().any(|o| o.name == self.name) {
            return fault("name", format!("\"{}\" twice", self.name));
        }
        if !(1..=DESCRIPTION_MAX).contains(&self.description.len()) {
            return fault("description", "1 to 1024 bytes".to_string());
        }
        let is_object_schema = self.params_schema.as_object().and_then(|m| m.get("type")).and_then(serde_json::Value::as_str) == Some("object");
        if !is_object_schema {
            return fault("params_schema", "a JSON Schema object whose \"type\" is \"object\"".to_string());
        }
        if self.params_schema.to_string().len() > SCHEMA_MAX {
            return fault("params_schema", format!("at most {SCHEMA_MAX} bytes as JSON"));
        }
        if self.examples.len() > EXAMPLES_MAX {
            return fault("examples", format!("at most {EXAMPLES_MAX}"));
        }
        for (j, example) in self.examples.iter().enumerate() {
            if !example.is_object() {
                return fault(&format!("examples[{j}]"), "a JSON object".to_string());
            }
            if example.to_string().len() > EXAMPLE_MAX {
                return fault(&format!("examples[{j}]"), format!("at most {EXAMPLE_MAX} bytes as JSON"));
            }
        }
        let (max, ceiling) = (self.max_limits, Limits::CEILING);
        for (field, value, top) in limit_fields(max, ceiling) {
            if value > top {
                return fault("max_limits", format!("{field} {value} is above the ceiling {top}"));
            }
        }
        // The max as P-R45 resolves it: CEILING's value where max says 0, and never above CEILING.
        let cap = Limits::resolve(ceiling, Limits::UNSET, max);
        for (field, value, top) in limit_fields(self.default_limits, cap) {
            if value != 0 && value > top {
                return fault("default_limits", format!("{field} {value} is above max_limits {top}"));
            }
        }
        let (default, most) = (self.default_deadline, self.max_deadline);
        if default < Duration::from_millis(1) || default > most || most > DEADLINE_CEILING {
            return fault("deadlines", "1 ms <= default <= max <= 600 s".to_string());
        }
        Ok(())
    }
}

/// Each field of `l` beside the same field of `top`, by name, in declaration order.
fn limit_fields(l: Limits, top: Limits) -> [(&'static str, u64, u64); 3] {
    [
        ("max_bytes", l.max_bytes, top.max_bytes),
        ("max_rows", u64::from(l.max_rows), u64::from(top.max_rows)),
        ("max_chunks", u64::from(l.max_chunks), u64::from(top.max_chunks)),
    ]
}

/// A descriptor's first fault (P-R41, P-R44).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DescriptorError {
    /// The descriptor's `name`, as given.
    pub source_name: String,
    /// The field at fault: `name`, `ops[<i>].params_schema`, …
    pub field: String,
    /// Why.
    pub reason: String,
}

impl DescriptorError {
    /// An error of these three texts (for `validate` and for the wire mapping in other crates).
    #[must_use]
    pub fn new(source_name: impl Into<String>, field: impl Into<String>, reason: impl Into<String>) -> Self {
        DescriptorError { source_name: source_name.into(), field: field.into(), reason: reason.into() }
    }
}

impl fmt::Display for DescriptorError {
    /// `descriptor "<source_name>": <field>: <reason>`, the name Debug-quoted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "descriptor {:?}: {}: {}", self.source_name, self.field, self.reason)
    }
}

impl std::error::Error for DescriptorError {}

/// A `Duration` as integer milliseconds.
mod ms {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        u64::deserialize(d).map(Duration::from_millis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::NAME_RULE;
    use serde_json::json;

    fn base() -> SourceDescriptor {
        SourceDescriptor::new("test-validate", "1.0.0", "A test descriptor.").op(OpDescriptor::new("get", "Gets."))
    }

    /// The `(field, reason)` of `d`'s refusal.
    fn refused(d: &SourceDescriptor) -> (String, String) {
        let e = d.validate().expect_err("refused");
        assert_eq!(e.source_name, d.name);
        (e.field, e.reason)
    }

    /// A JSON object of exactly `len` bytes as compact JSON: `{"description":"x…","type":"object"}`.
    fn schema_of(len: usize) -> serde_json::Value {
        let bare = json!({"type": "object", "description": ""}).to_string().len();
        let schema = json!({"type": "object", "description": "x".repeat(len - bare)});
        assert_eq!(schema.to_string().len(), len);
        schema
    }

    /// An example of exactly `len` bytes as compact JSON: `{"text":"x…"}`.
    fn example_of(len: usize) -> serde_json::Value {
        let bare = json!({"text": ""}).to_string().len();
        let example = json!({"text": "x".repeat(len - bare)});
        assert_eq!(example.to_string().len(), len);
        example
    }

    /// P-T11.
    #[test]
    fn descriptor_builders_fill_every_field_and_defaults() {
        let op = OpDescriptor::new("op", "d");
        assert_eq!((op.name.as_str(), op.description.as_str()), ("op", "d"));
        assert_eq!(op.params_schema, json!({"type": "object", "additionalProperties": false}));
        assert_eq!(op.output, OutputKind::Json);
        assert!(!op.read_only, "the label claims nothing until the source says so");
        assert_eq!((op.default_limits, op.max_limits), (Limits::DEFAULT, Limits::CEILING));
        assert_eq!((op.default_deadline, op.max_deadline), (Duration::from_secs(30), Duration::from_secs(120)));
        assert!(op.examples.is_empty());

        let schema = json!({"type": "object", "properties": {"n": {"type": "integer"}}});
        let limits = Limits::new(10, 2, 1);
        type Built = (OpDescriptor, fn(&mut OpDescriptor));
        let rows: [Built; 7] = [
            (op.clone().params_schema(schema.clone()), |o| o.params_schema = json!({"type": "object", "properties": {"n": {"type": "integer"}}})),
            (op.clone().output(OutputKind::Stream), |o| o.output = OutputKind::Stream),
            (op.clone().read_only(true), |o| o.read_only = true),
            (op.clone().default_limits(limits), |o| o.default_limits = Limits::new(10, 2, 1)),
            (op.clone().max_limits(limits), |o| o.max_limits = Limits::new(10, 2, 1)),
            (op.clone().deadlines(Duration::from_secs(1), Duration::from_secs(2)), |o| {
                o.default_deadline = Duration::from_secs(1);
                o.max_deadline = Duration::from_secs(2);
            }),
            (op.clone().example(json!({"n": 1})).example(json!({"n": 2})), |o| o.examples = vec![json!({"n": 1}), json!({"n": 2})]),
        ];
        for (built, set) in rows {
            let mut want = op.clone();
            set(&mut want);
            assert_eq!(built, want);
        }
        assert_eq!(Limits::DEFAULT.with_max_bytes(1).with_max_rows(2).with_max_chunks(3), Limits::new(1, 2, 3));
        assert_eq!(Limits::default(), Limits::DEFAULT);

        let d = SourceDescriptor::new("test-builders", "0.1.0", "A test descriptor.");
        assert_eq!((d.name.as_str(), d.version.as_str(), d.description.as_str()), ("test-builders", "0.1.0", "A test descriptor."));
        assert_eq!((d.kind, d.env.as_str(), d.sensitivity), (SourceKind::Other, "", Sensitivity::Internal));
        assert!(d.ops.is_empty());
        let d = d.kind(SourceKind::Logs).env("test").sensitivity(Sensitivity::Restricted).op(op.clone()).op(OpDescriptor::new("tail", "Tails."));
        assert_eq!((d.kind, d.env.as_str(), d.sensitivity), (SourceKind::Logs, "test", Sensitivity::Restricted));
        assert_eq!(d.op_named("op"), Some(&op));
        assert_eq!(d.op_named("tail").map(|o| o.description.as_str()), Some("Tails."));
        assert_eq!(d.op_named("nope"), None);

        let text = serde_json::to_string(&d).expect("serializes");
        let value: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(value["ops"][0]["default_deadline_ms"], json!(30_000));
        assert_eq!(value["ops"][0]["max_deadline_ms"], json!(120_000));
        assert_eq!(value["kind"], json!("logs"));
        assert_eq!(serde_json::from_str::<SourceDescriptor>(&text).expect("deserializes"), d);
    }

    /// P-T12.
    #[test]
    fn validate_refuses_each_bad_descriptor_with_its_field() {
        assert_eq!(base().validate(), Ok(()));
        let schema_shape = "a JSON Schema object whose \"type\" is \"object\"";
        let deadlines = "1 ms <= default <= max <= 600 s";
        type Refusal = (fn(&mut SourceDescriptor), &'static str, &'static str);
        let rows: &[Refusal] = &[
            (|d| d.name = String::new(), "name", NAME_RULE),
            (|d| d.name = "a".repeat(65), "name", NAME_RULE),
            (|d| d.name = "Echo".into(), "name", NAME_RULE),
            (|d| d.name = "-x".into(), "name", NAME_RULE),
            (|d| d.name = "a*b".into(), "name", NAME_RULE),
            (|d| d.version = String::new(), "version", "1 to 32 of [0-9A-Za-z.+-]"),
            (|d| d.version = "1 0".into(), "version", "1 to 32 of [0-9A-Za-z.+-]"),
            (|d| d.version = "1".repeat(33), "version", "1 to 32 of [0-9A-Za-z.+-]"),
            (|d| d.description = String::new(), "description", "1 to 1024 bytes"),
            (|d| d.description = "d".repeat(1025), "description", "1 to 1024 bytes"),
            (|d| d.env = "Prod".into(), "env", "0 to 32 of [a-z0-9_-]"),
            (|d| d.env = "e".repeat(33), "env", "0 to 32 of [a-z0-9_-]"),
            (|d| d.ops.clear(), "ops", "at least one op"),
            (|d| d.ops = (0..65).map(|i| OpDescriptor::new(format!("op{i}"), "An op.")).collect(), "ops", "at most 64 ops"),
            (|d| d.ops[0].name = "Get".into(), "ops[0].name", NAME_RULE),
            (|d| d.ops.push(OpDescriptor::new("get", "Gets again.")), "ops[1].name", "\"get\" twice"),
            (|d| d.ops[0].description = String::new(), "ops[0].description", "1 to 1024 bytes"),
            (|d| d.ops[0].params_schema = json!([]), "ops[0].params_schema", schema_shape),
            (|d| d.ops[0].params_schema = json!({"type": "array"}), "ops[0].params_schema", schema_shape),
            (|d| d.ops[0].params_schema = schema_of(16_385), "ops[0].params_schema", "at most 16384 bytes as JSON"),
            (|d| d.ops[0].examples = vec![json!({}); 9], "ops[0].examples", "at most 8"),
            (|d| d.ops[0].examples = vec![json!([])], "ops[0].examples[0]", "a JSON object"),
            (|d| d.ops[0].examples = vec![example_of(4097)], "ops[0].examples[0]", "at most 4096 bytes as JSON"),
            (|d| d.ops[0].max_limits = Limits::CEILING.with_max_bytes(16_777_217), "ops[0].max_limits", "max_bytes 16777217 is above the ceiling 16777216"),
            (
                |d| {
                    d.ops[0].default_limits = Limits::DEFAULT.with_max_rows(2000);
                    d.ops[0].max_limits = Limits::CEILING.with_max_rows(1000);
                },
                "ops[0].default_limits",
                "max_rows 2000 is above max_limits 1000",
            ),
            (|d| d.ops[0].default_deadline = Duration::ZERO, "ops[0].deadlines", deadlines),
            (|d| d.ops[0].default_deadline = Duration::from_secs(121), "ops[0].deadlines", deadlines),
            (|d| d.ops[0].max_deadline = Duration::from_secs(601), "ops[0].deadlines", deadlines),
        ];
        for &(change, field, reason) in rows {
            let mut d = base();
            change(&mut d);
            assert_eq!(refused(&d), (field.to_string(), reason.to_string()));
        }

        let passes: [fn(&mut SourceDescriptor); 8] = [
            |d| d.name = "a".repeat(64),
            |d| d.version = "1".repeat(32),
            |d| d.description = "d".repeat(1024),
            |d| d.env = "e".repeat(32),
            |d| d.ops = (0..64).map(|i| OpDescriptor::new(format!("op{i}"), "An op.")).collect(),
            |d| d.ops[0].params_schema = schema_of(16_384),
            |d| d.ops[0].examples = vec![example_of(4096); 8],
            |d| {
                d.ops[0].default_limits = Limits::UNSET.with_max_rows(1000);
                d.ops[0].max_limits = Limits::UNSET.with_max_rows(1000);
                d.ops[0].default_deadline = Duration::from_millis(1);
                d.ops[0].max_deadline = DEADLINE_CEILING;
            },
        ];
        for change in passes {
            let mut d = base();
            change(&mut d);
            assert_eq!(d.validate(), Ok(()), "{d:?}");
        }

        // The first failure in P-R41's order wins: a bad name before a bad version, an op's name before its schema.
        let mut d = base();
        d.version = String::new();
        d.name = String::new();
        assert_eq!(refused(&d).0, "name");
        let mut d = base();
        d.ops[0].params_schema = json!([]);
        d.ops[0].name = "Get".into();
        assert_eq!(refused(&d).0, "ops[0].name");
        let mut d = base();
        d.ops.push(OpDescriptor::new("put", "Puts.").params_schema(json!([])));
        d.ops[0].description = String::new();
        assert_eq!(refused(&d).0, "ops[0].description");

        let mut d = base();
        d.version = "1 0".into();
        assert_eq!(d.validate().expect_err("refused").to_string(), "descriptor \"test-validate\": version: 1 to 32 of [0-9A-Za-z.+-]");
        d.name = String::new();
        assert_eq!(d.validate().expect_err("refused").to_string(), format!("descriptor \"\": name: {NAME_RULE}"));
    }

    /// P-T13.
    #[test]
    fn limits_resolve_per_field() {
        let op_default = Limits::new(100, 10, 2);
        let huge = Limits::new(u64::MAX, u32::MAX, u32::MAX);
        let rows = [
            // All requested 0: the op's default.
            (Limits::UNSET, op_default, Limits::CEILING, op_default),
            // The op's default 0 too: DEFAULT.
            (Limits::UNSET, Limits::UNSET, Limits::CEILING, Limits::DEFAULT),
            // Above the max: the max.
            (Limits::new(5000, 50, 5), Limits::DEFAULT, Limits::new(4000, 40, 4), Limits::new(4000, 40, 4)),
            // A max of 0: CEILING.
            (huge, Limits::DEFAULT, Limits::UNSET, Limits::CEILING),
            // A max above CEILING: CEILING.
            (huge, Limits::DEFAULT, huge, Limits::CEILING),
            // Within: as requested.
            (Limits::new(10, 2, 1), Limits::DEFAULT, Limits::CEILING, Limits::new(10, 2, 1)),
            // One field set, two at 0: each field on its own.
            (Limits::new(0, 7, 0), Limits::new(500, 0, 3), Limits::CEILING, Limits::new(500, 7, 3)),
            (Limits::new(10, 0, 0), Limits::UNSET, Limits::new(0, 5, 0), Limits::new(10, 5, 16)),
        ];
        for (requested, default, max, want) in rows {
            assert_eq!(Limits::resolve(requested, default, max), want, "{requested:?} {default:?} {max:?}");
            let op = OpDescriptor::new("op", "d").default_limits(default).max_limits(max);
            assert_eq!(op.effective_limits(requested), want);
        }
    }

    /// P-T14.
    #[test]
    fn deadlines_resolve_per_op() {
        let op = OpDescriptor::new("op", "d");
        assert_eq!(op.effective_deadline(0), DEADLINE_DEFAULT);
        assert_eq!(op.effective_deadline(5000), Duration::from_secs(5));
        assert_eq!(op.effective_deadline(500_000), Duration::from_secs(120));
        // Built past validate (which refuses a max above 600 s): the ceiling still holds.
        let long = OpDescriptor::new("op", "d").deadlines(DEADLINE_DEFAULT, Duration::from_secs(900));
        assert_eq!(long.effective_deadline(900_000), DEADLINE_CEILING);
        assert_eq!(long.effective_deadline(u32::MAX), Duration::from_secs(600));
        let zero = OpDescriptor::new("op", "d").deadlines(Duration::ZERO, DEADLINE_OP_MAX);
        assert_eq!(zero.effective_deadline(0), Duration::from_millis(1));
    }

    /// P-R31: the proto's numbers, none 0, and each `ALL` in declaration order.
    #[test]
    fn the_enums_name_and_number_themselves() {
        let kinds: Vec<_> = SourceKind::ALL.iter().map(|k| (k.name(), k.wire())).collect();
        assert_eq!(kinds, [("sql", 1), ("http_api", 2), ("grpc_api", 3), ("logs", 4), ("metrics", 5), ("host_stats", 6), ("other", 7)]);
        let classes: Vec<_> = Sensitivity::ALL.iter().map(|s| (s.name(), s.wire())).collect();
        assert_eq!(classes, [("public", 1), ("internal", 2), ("restricted", 3)]);
        let outputs: Vec<_> = OutputKind::ALL.iter().map(|o| (o.name(), o.wire())).collect();
        assert_eq!(outputs, [("json", 1), ("text", 2), ("stream", 3)]);
        assert_eq!(serde_json::to_value(SourceKind::HostStats).expect("serializes"), json!("host_stats"));
    }
}
