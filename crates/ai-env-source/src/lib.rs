//! The `DataSource` trait and its types, for the workers behind the ai-env relay
//! (plans/s13-contracts.md §P-proto-sdk.6 to 8).
//!
//! A data source is a name plus ops with JSON parameters: it advertises a [`SourceDescriptor`] and
//! answers [`DataSource::call`] with an [`Output`] or a [`SourceError`]. The crate is generic and
//! holds no gRPC, HTTP or TLS crate: the worker runtime (ai-env-worker) maps these types to the
//! relay protocol. [`wire`] holds the protocol's constants and the handshake's signed bytes, so
//! every peer of the relay shares one definition. The `testkit` feature adds `ScriptedSource`,
//! `EchoSource` and the conformance checks a private repo runs against its own sources.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod call;
mod cursor;
mod descriptor;
mod error;
pub mod names;
mod output;
mod read;
pub mod redact;
mod source;
#[cfg(feature = "testkit")]
pub mod testkit;
pub mod wire;

pub use call::{CallContext, CallRequest, Caller, Cancel};
pub use cursor::Cursor;
pub use descriptor::{
    DescriptorError, Limits, OpDescriptor, OutputKind, Sensitivity, SourceDescriptor, SourceKind, DEADLINE_CEILING, DEADLINE_DEFAULT,
    DEADLINE_OP_MAX,
};
pub use error::{Code, SourceError, MESSAGE_MAX};
pub use output::{stream_iter, Body, ContentType, IterStream, Output, Page, TextStream};
pub use read::{collect_capped, lines_capped, read_capped, text_lines, Capped, LINE_CUT, LINE_MAX};
pub use redact::Redactor;
/// The JSON crate this API speaks: sources use it for params and outputs.
pub use serde_json;
pub use source::{BoxFuture, DataSource, Health};

/// This crate's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
