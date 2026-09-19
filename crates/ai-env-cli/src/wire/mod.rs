//! Network-free protocol pieces shared by the Mac side and the VM shim:
//! versioned frames, the NDJSON line codec, the wrapper's argv router, and
//! clones of the Claude extension's project-slug and transcript-mirror-key
//! functions. Everything here compiles in every feature set (serde and the
//! tungstenite message type only — no sockets, no TLS, no AWS).
pub mod argv;
pub mod frame;
pub mod mirror;
pub mod ndjson;
pub mod redact;
pub mod slug;
pub mod time;
