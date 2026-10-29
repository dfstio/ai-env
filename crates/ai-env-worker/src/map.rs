//! ai-env-source's types on the wire (plans/s13-contracts.md §P-proto-sdk.5.4, P-R26 to P-R29). Moved here
//! from ai-env-relay-proto by review A-M13, in the always-built half that the relay also depends on, so the
//! proto crate stays the lead's generated code alone. Phase 0 writes it whole (the rules are P's).

use ai_env_relay_proto::v1;
use ai_env_source::{Caller, Code, DescriptorError, Limits, OpDescriptor, OutputKind, Sensitivity, SourceDescriptor, SourceKind};

/// A descriptor as the `Catalog` carries it (P-R26).
#[must_use]
pub fn descriptor(d: &SourceDescriptor) -> v1::SourceDescriptor {
    v1::SourceDescriptor {
        name: d.name.clone(),
        version: d.version.clone(),
        description: d.description.clone(),
        kind: d.kind.wire(),
        env: d.env.clone(),
        sensitivity: d.sensitivity.wire(),
        ops: d.ops.iter().map(op).collect(),
    }
}

/// One op as the `Catalog` carries it (P-R26): schema and examples as compact JSON; the op's two deadlines
/// have no wire field yet (Q-P2) and are left out.
#[must_use]
pub fn op(o: &OpDescriptor) -> v1::OpDescriptor {
    v1::OpDescriptor {
        name: o.name.clone(),
        description: o.description.clone(),
        params_json_schema: o.params_schema.to_string(),
        output: o.output.wire(),
        read_only: o.read_only,
        default_limits: Some(limits(o.default_limits)),
        max_limits: Some(limits(o.max_limits)),
        examples: o.examples.iter().map(ToString::to_string).collect(),
    }
}

/// Limits on the wire, field for field.
#[must_use]
pub fn limits(l: Limits) -> v1::Limits {
    v1::Limits { max_bytes: l.max_bytes, max_rows: l.max_rows, max_chunks: l.max_chunks }
}

/// The wire's limits back; a missing message is `Limits::UNSET` (P-R27).
#[must_use]
pub fn limits_of(l: Option<&v1::Limits>) -> Limits {
    l.map_or(Limits::UNSET, |l| Limits::new(l.max_bytes, l.max_rows, l.max_chunks))
}

/// The relay's caller assertion; a missing message is `Caller::default()` (P-R27).
#[must_use]
pub fn caller_of(c: Option<&v1::Caller>) -> Caller {
    c.map_or_else(Caller::default, |c| Caller::new(c.caller_id.clone(), c.session_id.clone(), c.grant_id.clone(), c.vm_id.clone()))
}

/// An `Error` of `code` with `message` (the caller redacts and cuts it first: `SourceError::wire_message`).
#[must_use]
pub fn error(code: Code, message: impl Into<String>) -> v1::Error {
    v1::Error { code: code.as_i32(), message: message.into() }
}

/// A `Catalog` descriptor back (P-R28): kind 0 or unknown is `Other`; sensitivity 0 or unknown is
/// `Restricted`; output 0 or unknown, or a schema or example that is not JSON, is an error; missing limits are
/// `Limits::UNSET`; the deadlines are the SDK's defaults. It does not call `validate()`.
pub fn descriptor_of(d: &v1::SourceDescriptor) -> Result<SourceDescriptor, DescriptorError> {
    let fault = |field: String, reason: String| DescriptorError::new(d.name.clone(), field, reason);
    let kind = SourceKind::ALL.into_iter().find(|k| k.wire() == d.kind).unwrap_or(SourceKind::Other);
    let sensitivity = Sensitivity::ALL.into_iter().find(|s| s.wire() == d.sensitivity).unwrap_or(Sensitivity::Restricted);
    let mut out = SourceDescriptor::new(d.name.clone(), d.version.clone(), d.description.clone()).kind(kind).env(d.env.clone()).sensitivity(sensitivity);
    for (i, o) in d.ops.iter().enumerate() {
        let output = OutputKind::ALL
            .into_iter()
            .find(|k| k.wire() == o.output)
            .ok_or_else(|| fault(format!("ops[{i}].output"), format!("unknown output kind {}", o.output)))?;
        let schema: serde_json::Value =
            serde_json::from_str(&o.params_json_schema).map_err(|_| fault(format!("ops[{i}].params_schema"), "not JSON".to_string()))?;
        let mut op = OpDescriptor::new(o.name.clone(), o.description.clone())
            .params_schema(schema)
            .output(output)
            .read_only(o.read_only)
            .default_limits(limits_of(o.default_limits.as_ref()))
            .max_limits(limits_of(o.max_limits.as_ref()));
        for (j, example) in o.examples.iter().enumerate() {
            let value: serde_json::Value =
                serde_json::from_str(example).map_err(|_| fault(format!("ops[{i}].examples[{j}]"), "not JSON".to_string()))?;
            op = op.example(value);
        }
        out = out.op(op);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! P-T3, P-T4 and P-T7's enum and code rows, moved here with `map` (review A-M13), and P-T3's EchoSource rows
    //! (added at I1, once the testkit's EchoSource was built).
    use super::*;
    use ai_env_relay_proto::tonic;

    #[test]
    fn the_echo_descriptor_maps_field_by_field_and_back() {
        use ai_env_source::DataSource as _;
        let d = ai_env_source::testkit::EchoSource::new().descriptor();
        let wire = descriptor(&d);
        assert_eq!((wire.name.as_str(), wire.version.as_str(), wire.kind, wire.env.as_str(), wire.sensitivity), ("echo", ai_env_source::VERSION, 7, "test", 1));
        let names: Vec<&str> = wire.ops.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, ["echo", "lines", "sleep", "fail", "sample"], "P-R81's order");
        let echo = &wire.ops[0];
        assert_eq!(echo.params_json_schema, r#"{"additionalProperties":false,"properties":{"text":{"maxLength":4096,"type":"string"}},"required":["text"],"type":"object"}"#);
        assert_eq!((echo.output, echo.read_only), (1, true));
        assert_eq!(echo.default_limits, Some(v1::Limits { max_bytes: 1_048_576, max_rows: 1000, max_chunks: 16 }));
        assert_eq!(echo.max_limits, Some(v1::Limits { max_bytes: 16_777_216, max_rows: 100_000, max_chunks: 256 }));
        assert_eq!(echo.examples, vec![r#"{"text":"hello"}"#.to_string()]);
        assert_eq!((wire.ops[1].output, wire.ops[4].output), (3, 2), "lines streams, sample is text");
        assert_eq!(descriptor_of(&wire), Ok(d));
    }

    fn sample() -> SourceDescriptor {
        SourceDescriptor::new("test-map", "0.1.0", "A test descriptor.")
            .kind(SourceKind::HostStats)
            .env("test")
            .sensitivity(Sensitivity::Public)
            .op(OpDescriptor::new("get", "Gets.")
                .params_schema(serde_json::json!({"type": "object", "properties": {"text": {"type": "string", "maxLength": 4096}}, "required": ["text"], "additionalProperties": false}))
                .read_only(true)
                .example(serde_json::json!({"text": "hello"})))
            .op(OpDescriptor::new("tail", "Tails.").output(OutputKind::Stream))
    }

    #[test]
    fn a_descriptor_maps_field_by_field_and_back() {
        let d = sample();
        let wire = descriptor(&d);
        assert_eq!((wire.kind, wire.sensitivity, wire.env.as_str(), wire.ops.len()), (6, 1, "test", 2));
        let get = &wire.ops[0];
        assert_eq!(get.params_json_schema, r#"{"additionalProperties":false,"properties":{"text":{"maxLength":4096,"type":"string"}},"required":["text"],"type":"object"}"#);
        assert_eq!((get.output, get.read_only), (1, true));
        assert_eq!(get.default_limits, Some(v1::Limits { max_bytes: 1_048_576, max_rows: 1000, max_chunks: 16 }));
        assert_eq!(get.max_limits, Some(v1::Limits { max_bytes: 16_777_216, max_rows: 100_000, max_chunks: 256 }));
        assert_eq!(get.examples, vec![r#"{"text":"hello"}"#.to_string()]);
        assert_eq!(wire.ops[1].output, 3);
        assert_eq!(descriptor_of(&wire), Ok(d));

        let mut odd = wire.clone();
        odd.kind = 99;
        odd.sensitivity = 0;
        let back = descriptor_of(&odd).expect("maps");
        assert_eq!((back.kind, back.sensitivity), (SourceKind::Other, Sensitivity::Restricted));
        odd.sensitivity = 99;
        assert_eq!(descriptor_of(&odd).expect("maps").sensitivity, Sensitivity::Restricted);
        let mut bad = wire.clone();
        bad.ops[0].output = 0;
        let e = descriptor_of(&bad).expect_err("refused");
        assert_eq!((e.field.as_str(), e.reason.as_str()), ("ops[0].output", "unknown output kind 0"));
        let mut bad = wire;
        bad.ops[0].params_json_schema = "{".to_string();
        let e = descriptor_of(&bad).expect_err("refused");
        assert_eq!((e.field.as_str(), e.reason.as_str()), ("ops[0].params_schema", "not JSON"));
    }

    #[test]
    fn limits_callers_and_errors_map_with_unset_as_zero() {
        assert_eq!(limits_of(None), Limits::UNSET);
        for l in [Limits::DEFAULT, Limits::CEILING] {
            assert_eq!(limits_of(Some(&limits(l))), l);
        }
        assert_eq!(caller_of(None), Caller::default());
        let c = v1::Caller { caller_id: "a".into(), session_id: "b".into(), grant_id: "c".into(), vm_id: "d".into() };
        assert_eq!(caller_of(Some(&c)), Caller::new("a", "b", "c", "d"));
        assert_eq!(error(Code::NotFound, "m"), v1::Error { code: 5, message: "m".into() });
    }

    #[test]
    fn the_source_codes_and_enums_equal_the_wires() {
        let pairs = [
            (Code::Ok, tonic::Code::Ok),
            (Code::Cancelled, tonic::Code::Cancelled),
            (Code::Unknown, tonic::Code::Unknown),
            (Code::InvalidArgument, tonic::Code::InvalidArgument),
            (Code::DeadlineExceeded, tonic::Code::DeadlineExceeded),
            (Code::NotFound, tonic::Code::NotFound),
            (Code::AlreadyExists, tonic::Code::AlreadyExists),
            (Code::PermissionDenied, tonic::Code::PermissionDenied),
            (Code::ResourceExhausted, tonic::Code::ResourceExhausted),
            (Code::FailedPrecondition, tonic::Code::FailedPrecondition),
            (Code::Aborted, tonic::Code::Aborted),
            (Code::OutOfRange, tonic::Code::OutOfRange),
            (Code::Unimplemented, tonic::Code::Unimplemented),
            (Code::Internal, tonic::Code::Internal),
            (Code::Unavailable, tonic::Code::Unavailable),
            (Code::DataLoss, tonic::Code::DataLoss),
            (Code::Unauthenticated, tonic::Code::Unauthenticated),
        ];
        for (ours, theirs) in pairs {
            assert_eq!(ours.as_i32(), theirs as i32, "{}", ours.name());
            assert_eq!(Code::from_i32(ours.as_i32()), Some(ours));
        }
        assert_eq!(Code::from_i32(17), None);
        for k in SourceKind::ALL {
            let v = v1::SourceKind::from_str_name(&format!("SOURCE_KIND_{}", k.name().to_uppercase())).expect("a proto value");
            assert_eq!(v as i32, k.wire());
        }
        for s in Sensitivity::ALL {
            let v = v1::Sensitivity::from_str_name(&format!("SENSITIVITY_{}", s.name().to_uppercase())).expect("a proto value");
            assert_eq!(v as i32, s.wire());
        }
        for o in OutputKind::ALL {
            let v = v1::OutputKind::from_str_name(&format!("OUTPUT_KIND_{}", o.name().to_uppercase())).expect("a proto value");
            assert_eq!(v as i32, o.wire());
        }
        assert_eq!(v1::SigAlg::Ed25519 as i32, 1, "wire::transcript's alg number");
    }
}
