//! Network-free protocol pieces shared by the Mac side and the VM shim:
//! versioned frames, the NDJSON line codec, the wrapper's argv router,
//! clones of the Claude extension's project-slug and transcript-mirror-key
//! functions, and the S8 workspace data plane's types (`workspace`).
//! Everything here compiles in every feature set (serde and the tungstenite
//! message type only — no sockets, no TLS, no AWS).
pub mod argv;
pub mod chunk;
pub mod claude;
pub mod frame;
pub mod managed;
pub mod mirror;
pub mod ndjson;
pub mod pin;
pub mod redact;
pub mod slug;
pub mod time;
pub mod workspace;
