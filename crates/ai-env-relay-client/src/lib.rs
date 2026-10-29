//! ai-env's VM side of the relay (S13, plans/s13-contracts.md §V-vm): `ai-env-relay-client` (one per relay spawn, as
//! ai-env-net) and `ai-env-relay-mcp` (the stdio MCP server claude starts). Generic: no data source is named here.
//!
//! The shim starts one client per relay spawn, its session (the Mac-minted token, the relay's private address, the
//! name its certificate carries and its CA) on fd 3 alone ([`session`]). The client serves one Unix socket to that
//! spawn's processes ([`serve`], [`local`]), admitting a peer by uid and ancestry ([`peer`]), and dials the relay's
//! private face over TLS 1.3 with the session's CA as its one anchor ([`tls`], [`dial`]); the relay's answers become
//! the socket's ([`convert`]). claude starts the MCP server ([`mcp`]), which finds the socket by its own ancestry and
//! answers `relay_catalog` and `relay_call`: no process of the agent ever holds the token.
pub mod convert;
pub mod dial;
pub mod local;
pub mod mcp;
pub mod peer;
pub mod serve;
pub mod session;
pub mod tls;

/// One line on stderr, written whole (a reader that went away is ignored): the client's log lines (§V-vm.3.8) and the
/// MCP server's one error line.
pub(crate) fn line(text: &str) {
    use std::io::Write as _;
    let mut l = String::with_capacity(text.len() + 1);
    l.push_str(text);
    l.push('\n');
    let _ = std::io::stderr().lock().write_all(l.as_bytes());
}
