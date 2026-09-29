//! S4 MicroVM lifecycle (feature `bridge`). In-process: run/select with the
//! workspace and placement locks, pending rows, reuse, termination and the
//! adoption sweep (`vm/select.rs`), and tag-free gc (`vm/gc.rs`), against
//! `FakeMicrovmApi` (control plane and endpoint) and a temp bridge root.
//! As processes: `ai-env vm …` (`vm/cli.rs`) and `ai-env lab …`
//! (`vm/lab.rs`) against the file-backed fake of the debug-build knob
//! `AI_ENV_BRIDGE_LAB_FAKE_API`.
//! Each area lives in its own file under tests/vm/ (declared with `#[path]`,
//! so the undeclared-test lint only sees this root). Nothing here touches
//! AWS, the real bridge directory or the process environment; polls are
//! scaled 1 s → 1 ms.

#[path = "vm/common.rs"]
mod common;
#[path = "vm/select.rs"]
mod select;
#[path = "vm/gc.rs"]
mod gc;
#[path = "vm/cli.rs"]
mod cli;
#[path = "vm/lab.rs"]
mod lab;
#[path = "vm/shell.rs"]
mod shell;
