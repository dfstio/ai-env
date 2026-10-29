//! The tests' sources, all from the testkit (P-R80, P-R81; review A-M7): `EchoSource` for echo,
//! `ScriptedSource` for the rest. No `DataSource` type of its own.
#![allow(dead_code)]

use std::sync::Arc;

use ai_env_worker::ai_env_source::testkit::{EchoSource, Scripted, ScriptedSource};
use ai_env_worker::ai_env_source::{OpDescriptor, OutputKind, SourceDescriptor, SourceError};

/// `EchoSource` as `echo`.
pub fn echo() -> Arc<EchoSource> {
    Arc::new(EchoSource::new())
}

/// A descriptor `name` with one op `get` of `output`.
pub fn descriptor(name: &str, output: OutputKind) -> SourceDescriptor {
    SourceDescriptor::new(name, "0.1.0", "A test source.").op(OpDescriptor::new("get", "Gets.").output(output).read_only(true))
}

/// `test-sleeper`: `n` calls that wait in `ctx.within` for their cancel or deadline.
pub fn sleeper(n: usize) -> Arc<ScriptedSource> {
    let source = ScriptedSource::new(descriptor("test-sleeper", OutputKind::Json));
    for _ in 0..n {
        source.push(Scripted::Hang);
    }
    Arc::new(source)
}

/// `name`: one call answering `text`.
pub fn text(name: &str, text: String) -> Arc<ScriptedSource> {
    Arc::new(ScriptedSource::new(descriptor(name, OutputKind::Text)).then(Scripted::Text(text)))
}

/// `name`: one call answering a JSON value.
pub fn json(name: &str, value: serde_json::Value) -> Arc<ScriptedSource> {
    Arc::new(ScriptedSource::new(descriptor(name, OutputKind::Json)).then(Scripted::Json(value)))
}

/// `name`: one call answering a stream of `lines`.
pub fn lines(name: &str, lines: Vec<String>) -> Arc<ScriptedSource> {
    Arc::new(ScriptedSource::new(descriptor(name, OutputKind::Stream)).then(Scripted::Lines(lines)))
}

/// `name`: one call failing with `e`.
pub fn failing(name: &str, e: SourceError) -> Arc<ScriptedSource> {
    Arc::new(ScriptedSource::new(descriptor(name, OutputKind::Json)).then(Scripted::Fail(e)))
}

/// `name`: one call that panics with `message`.
pub fn panicking(name: &str, message: &str) -> Arc<ScriptedSource> {
    Arc::new(ScriptedSource::new(descriptor(name, OutputKind::Json)).then(Scripted::Panic(message.into())))
}
