//! P-T5 and P-T6: the lead's frozen proto, read back from its committed descriptor set and its generated
//! code (plans/s13-contracts.md §P-proto-sdk.2, §P-proto-sdk.14; X-1 puts these tests here, with the proto
//! crate and prost-types as dev-dependencies only).

use ai_env_relay_proto::prost::Message;
use ai_env_relay_proto::{v1, FILE_DESCRIPTOR_SET};
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, EnumDescriptorProto, FieldDescriptorProto, FileDescriptorSet};

/// The frozen table, 134 lines (§P-proto-sdk.2).
const GOLDEN: &str = include_str!("golden/relay-v1.txt");

/// A type name's last segment: `.ai_env.relay.v1.Challenge` is `Challenge`.
fn short(type_name: &str) -> &str {
    type_name.rsplit('.').next().unwrap_or(type_name)
}

/// A scalar in proto's lowercase name, a message or an enum by its short name.
fn type_of(f: &FieldDescriptorProto) -> String {
    match f.r#type() {
        Type::Message | Type::Enum | Type::Group => short(f.type_name()).to_string(),
        scalar => scalar.as_str_name().trim_start_matches("TYPE_").to_lowercase(),
    }
}

fn message(out: &mut Vec<String>, prefix: &str, m: &DescriptorProto) {
    let name = format!("{prefix}{}", m.name());
    out.push(format!("message {name}"));
    for f in &m.field {
        let mut line = format!("field {name}.{} {} {}", f.name(), f.number(), type_of(f));
        if f.label() == Label::Repeated {
            line.push_str(" repeated");
        }
        if f.proto3_optional() {
            line.push_str(" optional");
        } else if let Some(i) = f.oneof_index {
            let oneof = usize::try_from(i).ok().and_then(|i| m.oneof_decl.get(i)).map_or("?", |o| o.name());
            line.push_str(&format!(" oneof {oneof}"));
        }
        out.push(line);
    }
    // A message's reserved range ends before `end`; it is shown inclusive, as relay.proto would write it.
    for r in &m.reserved_range {
        out.push(format!("reserved {name}.{}..{}", r.start(), r.end() - 1));
    }
    for n in &m.reserved_name {
        out.push(format!("reserved {name}.{n}"));
    }
    for nested in &m.nested_type {
        message(out, &format!("{name}."), nested);
    }
    for e in &m.enum_type {
        enumeration(out, &format!("{name}."), e);
    }
}

fn enumeration(out: &mut Vec<String>, prefix: &str, e: &EnumDescriptorProto) {
    let name = format!("{prefix}{}", e.name());
    out.push(format!("enum {name}"));
    for v in &e.value {
        out.push(format!("value {name}.{} {}", v.name(), v.number()));
    }
    // An enum's reserved range is inclusive in the descriptor already.
    for r in &e.reserved_range {
        out.push(format!("reserved {name}.{}..{}", r.start(), r.end()));
    }
    for n in &e.reserved_name {
        out.push(format!("reserved {name}.{n}"));
    }
}

/// §P-proto-sdk.2's line forms: messages, enums and services in file order, fields in declaration order.
fn render(set: &FileDescriptorSet) -> Vec<String> {
    let stream = |yes: bool| if yes { "stream " } else { "" };
    let mut out = Vec::new();
    for file in &set.file {
        out.push(format!("file {} package {} syntax {}", file.name(), file.package(), file.syntax()));
        for m in &file.message_type {
            message(&mut out, "", m);
        }
        for e in &file.enum_type {
            enumeration(&mut out, "", e);
        }
        for s in &file.service {
            out.push(format!("service {}", s.name()));
            for m in &s.method {
                out.push(format!(
                    "method {}/{} {}{} {}{}",
                    s.name(),
                    m.name(),
                    stream(m.client_streaming()),
                    short(m.input_type()),
                    stream(m.server_streaming()),
                    short(m.output_type())
                ));
            }
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// P-T5.
#[test]
fn the_descriptor_matches_the_frozen_field_table() {
    let set = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("the committed descriptor set decodes");
    let rendered = render(&set);
    assert!(GOLDEN.ends_with('\n'), "tests/golden/relay-v1.txt ends with a newline");
    let golden: Vec<&str> = GOLDEN.lines().collect();
    for (i, (got, want)) in rendered.iter().zip(&golden).enumerate() {
        assert_eq!(got, want, "line {}: the descriptor renders {got:?}, tests/golden/relay-v1.txt holds {want:?}", i + 1);
    }
    assert_eq!(rendered.len(), golden.len(), "the descriptor renders {} lines, the table holds {}", rendered.len(), golden.len());
    assert_eq!(golden.len(), 134);
}

/// P-T6.
#[test]
fn known_frames_encode_to_their_golden_bytes() {
    let request_id = "0199a1b2-0000-7000-8000-000000000001";
    let invoke = v1::RelayFrame {
        msg: Some(v1::relay_frame::Msg::Invoke(v1::Invoke {
            request_id: request_id.into(),
            source: "echo".into(),
            op: "echo".into(),
            params_json: br#"{"text":"hi"}"#.to_vec(),
            caller: Some(v1::Caller {
                caller_id: "vm-session".into(),
                session_id: "0199a1b2-0000-7000-8000-000000000002".into(),
                grant_id: "grant-test".into(),
                vm_id: "vm-test".into(),
            }),
            deadline_ms: 30_000,
            limits: Some(v1::Limits { max_bytes: 1_048_576, max_rows: 1000, max_chunks: 16 }),
        })),
    };
    let bytes = invoke.encode_to_vec();
    assert_eq!(bytes.len(), 156);
    assert_eq!(
        hex(&bytes),
        "1a99010a2430313939613162322d303030302d373030302d383030302d30303030303030303030303112046563686f1a046563686f220d7b2274657874223a226869227d2a470a0a766d2d73657373696f6e122430313939613162322d303030302d373030302d383030302d3030303030303030303030321a0a6772616e742d746573742207766d2d7465737430b0ea013a090880804010e8071810"
    );
    assert_eq!(v1::RelayFrame::decode(bytes.as_slice()).expect("decodes"), invoke);

    // Every field set: an encoding test, not a frame P-R18 allows.
    let chunk = v1::WorkerFrame {
        msg: Some(v1::worker_frame::Msg::Chunk(v1::Chunk {
            request_id: request_id.into(),
            seq: 3,
            data: b"line 3".to_vec(),
            content_type: "text/plain; charset=utf-8".into(),
            r#final: true,
            error: Some(v1::Error { code: 4, message: "deadline exceeded".into() }),
            truncated: true,
        })),
    };
    let bytes = chunk.encode_to_vec();
    assert_eq!(bytes.len(), 104);
    assert_eq!(
        hex(&bytes),
        "22660a2430313939613162322d303030302d373030302d383030302d30303030303030303030303110031a066c696e6520332219746578742f706c61696e3b20636861727365743d7574662d382801321508041211646561646c696e652065786365656465643801"
    );
    assert_eq!(v1::WorkerFrame::decode(bytes.as_slice()).expect("decodes"), chunk);

    // One flag each, so the two tags stay apart (with both set, swapped numbers encode the same bytes: M-P9).
    for (chunk, golden) in [
        (v1::Chunk { request_id: "r".into(), r#final: true, ..Default::default() }, "22050a01722801"),
        (v1::Chunk { request_id: "r".into(), truncated: true, ..Default::default() }, "22050a01723801"),
    ] {
        let frame = v1::WorkerFrame { msg: Some(v1::worker_frame::Msg::Chunk(chunk)) };
        assert_eq!(hex(&frame.encode_to_vec()), golden);
    }
}
