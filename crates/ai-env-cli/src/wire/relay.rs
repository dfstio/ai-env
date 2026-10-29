//! S13 (plans/s13-contracts.md §V-vm): the relay's VM side as the wire and the image name it. A spawn may carry a
//! relay session ([`RelaySpawn`], `Frame::Spawn.relay`, sent only to a shim naming `frame::CAP_RELAY_V1`). The shim
//! hands it, as [`RelaySpawn::session`]'s JSON on fd 3 alone, to the relay client it starts as `ai-env-net` for that
//! spawn, and gives a `claude` argv[0] [`mcp_config_arg`] as its argv[1]. claude then starts the image's MCP server
//! ([`MCP_BIN`], [`MCP_SERVER`] in [`MCP_CONFIG`]), which reaches the client at [`socket_path`] under
//! [`SOCKET_DIR`]. The token is opaque here (the Mac mints it, the relay checks it); it never reaches the agent, an
//! argv, an environment, a file or a log line. Not S11's claude relay (`shim::claudebin::relay`), which moves claude
//! binaries between VMs.
use crate::wire::redact::Secret;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

/// The MCP server's name in [`MCP_CONFIG_JSON`]: claude names its tools `mcp__ai-env-relay__relay_catalog` and
/// `mcp__ai-env-relay__relay_call`.
pub const MCP_SERVER: &str = "ai-env-relay";
/// The two tools the MCP server lists.
pub const TOOL_CATALOG: &str = "relay_catalog";
pub const TOOL_CALL: &str = "relay_call";
/// The image's relay client (root's, 0755; MANIFEST `ai-env-relay-client`): the shim's `--relay-client` default.
pub const CLIENT_BIN: &str = "/usr/local/bin/ai-env-relay-client";
/// The image's MCP server (root's, 0755; MANIFEST `ai-env-relay-mcp`).
pub const MCP_BIN: &str = "/usr/local/bin/ai-env-relay-mcp";
/// The image's MCP config (root's, 0644; MANIFEST `relay-mcp.json`): the shim's `--relay-mcp-config` default.
pub const MCP_CONFIG: &str = "/etc/ai-env/relay-mcp.json";
/// [`MCP_CONFIG`]'s bytes but its trailing newline: one stdio server, [`MCP_BIN`], no argument, no environment.
pub const MCP_CONFIG_JSON: &str = r#"{"mcpServers":{"ai-env-relay":{"type":"stdio","command":"/usr/local/bin/ai-env-relay-mcp","args":[],"env":{}}}}"#;
/// Made by the shim at its first relay spawn (root's, 0755); absent from the image (`/validate` V4).
pub const RUN_DIR: &str = "/run/ai-env";
/// The relay clients' sockets, `<leader pid>.sock` ([`socket_path`]): `ai-env-net`'s, the agent's group, 0750.
pub const SOCKET_DIR: &str = "/run/ai-env/relay";
/// [`RelaySpawn::session`]'s `v`.
pub const SESSION_V: u32 = 1;
/// A token is 1 to [`TOKEN_MAX`] bytes, each in [`TOKEN_BYTES`].
pub const TOKEN_MAX: usize = 2048;
/// The bytes a token may hold: base64, base64url, and the dots between a signed token's parts.
pub const TOKEN_BYTES: &str = "A-Za-z0-9._~+/=-";
/// A CA certificate's DER is 1 to this many bytes.
pub const CA_DER_MAX: usize = 4096;
/// A server name's bound (a DNS name's).
pub const SERVER_NAME_MAX: usize = 253;
/// The session JSON's bound: the largest valid fields fit under it; the client refuses more.
pub const SESSION_MAX: usize = 8192;

/// [`MCP_CONFIG_JSON`] parsed.
#[must_use]
pub fn mcp_config() -> serde_json::Value {
    serde_json::from_str(MCP_CONFIG_JSON).expect("MCP_CONFIG_JSON is JSON")
}

/// The one argv token a relay spawn's claude gets as its argv[1]: `--mcp-config=<path>`.
#[must_use]
pub fn mcp_config_arg(path: &Path) -> String {
    format!("--mcp-config={}", path.display())
}

/// `<dir>/<leader>.sock`.
#[must_use]
pub fn socket_path(dir: &Path, leader: u32) -> PathBuf {
    dir.join(format!("{leader}.sock"))
}

/// A spawn's relay session (`spawn.relay`). `Debug` is written by hand: never the token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySpawn {
    /// The Mac-minted session token, opaque here: 1 to [`TOKEN_MAX`] bytes of [`TOKEN_BYTES`].
    pub token: Secret<String>,
    /// The relay's private face, `<IPv4>:<port>`: a private or loopback address, a port that is not 0.
    pub addr: String,
    /// The name the relay's certificate must carry: an IPv4 literal (an IP SAN) or a DNS name.
    pub server_name: String,
    /// The relay CA's certificate, DER, standard base64 with padding: the client's one trust anchor.
    pub ca_der_b64: String,
}

/// One byte of [`TOKEN_BYTES`].
fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

/// 1 to [`SERVER_NAME_MAX`] bytes of labels `[A-Za-z0-9-]{1,63}` joined by single dots, none starting or ending
/// with `-`.
fn dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= SERVER_NAME_MAX
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

impl RelaySpawn {
    /// The `bad_request` rules (V-R3), in field order; the message names the field, never a value.
    pub fn check(&self) -> Result<(), String> {
        let token = self.token.expose().as_bytes();
        if token.is_empty() || token.len() > TOKEN_MAX {
            return Err(format!("token is {} bytes (1 to {TOKEN_MAX})", token.len()));
        }
        if !token.iter().all(|&b| token_byte(b)) {
            return Err(format!("token holds a byte outside {TOKEN_BYTES}"));
        }
        let addr: SocketAddrV4 = self.addr.parse().map_err(|_| "addr is not <IPv4>:<port>".to_string())?;
        if addr.port() == 0 {
            return Err("addr has port 0".into());
        }
        if !(addr.ip().is_private() || addr.ip().is_loopback()) {
            return Err("addr is not a private or loopback IPv4 address".into());
        }
        if self.server_name.parse::<Ipv4Addr>().is_err() && !dns_name(&self.server_name) {
            return Err(format!("server_name is not an IPv4 address or a DNS name of at most {SERVER_NAME_MAX} bytes"));
        }
        let der = zeroize::Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(&self.ca_der_b64)
                .map_err(|_| "ca_der_b64 is not standard base64".to_string())?,
        );
        if der.is_empty() || der.len() > CA_DER_MAX {
            return Err(format!("ca_der_b64 decodes to {} bytes (1 to {CA_DER_MAX})", der.len()));
        }
        if der[0] != 0x30 {
            return Err("ca_der_b64 is not a DER certificate".into());
        }
        Ok(())
    }

    /// The client's fd-3 payload (V-R4): `v`, `token`, `addr`, `server_name`, `ca_der_b64`, compact, no newline;
    /// zeroized when dropped.
    #[must_use]
    pub fn session(&self) -> zeroize::Zeroizing<Vec<u8>> {
        #[derive(Serialize)]
        struct Session<'a> {
            v: u32,
            token: &'a str,
            addr: &'a str,
            server_name: &'a str,
            ca_der_b64: &'a str,
        }
        let s = Session {
            v: SESSION_V,
            token: self.token.expose(),
            addr: &self.addr,
            server_name: &self.server_name,
            ca_der_b64: &self.ca_der_b64,
        };
        // Sized for every checked session (V-R3's bounds), so no reallocation frees a block that holds the token.
        let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(SESSION_MAX));
        serde_json::to_writer(&mut *buf, &s).expect("a session serializes");
        buf
    }
}

/// `RelaySpawn(addr=<addr>, server_name=<server_name>, ca=<n> chars)`.
impl std::fmt::Debug for RelaySpawn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RelaySpawn(addr={}, server_name={}, ca={} chars)", self.addr, self.server_name, self.ca_der_b64.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client's fixture (`crates/ai-env-relay-client/tests/fixtures/session-v1.json`): one line and its newline.
    const FIXTURE: &str = include_str!("../../../ai-env-relay-client/tests/fixtures/session-v1.json");
    /// The fixture's placeholder (GitGuardian: a low-entropy value under `token`).
    const PLACEHOLDER: &str = "0199a1b2-0000-7000-8000-000000000001";

    fn fixture() -> RelaySpawn {
        RelaySpawn { token: Secret::new(PLACEHOLDER.to_string()), addr: "10.42.0.20:7443".into(), server_name: "10.42.0.20".into(), ca_der_b64: "MA==".into() }
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// V-R3 in field order: the fixture's values are `Ok`, and so are a loopback, 172.16/12 and 192.168/16 address
    /// (built at run time, P-R89's pattern) and a DNS server name; each bad field is `Err` naming its field, and no
    /// message holds the token.
    #[test]
    fn relay_spawn_check_names_each_bad_field() {
        assert_eq!(fixture().check(), Ok(()));
        let quad = |p: [&str; 4]| p.join(".");
        for addr in ["127.0.0.1:1".to_string(), format!("{}:7443", quad(["172", "16", "0", "1"])), format!("{}:7443", quad(["192", "168", "0", "10"]))] {
            assert_eq!(RelaySpawn { addr: addr.clone(), ..fixture() }.check(), Ok(()), "{addr}");
        }
        assert_eq!(RelaySpawn { server_name: "relay.internal.test".into(), ..fixture() }.check(), Ok(()));
        assert_eq!(RelaySpawn { token: Secret::new("A".repeat(TOKEN_MAX)), ..fixture() }.check(), Ok(()), "2048 bytes");
        assert_eq!(RelaySpawn { ca_der_b64: b64(&[0x30; CA_DER_MAX]), ..fixture() }.check(), Ok(()), "4096 bytes");
        let token = format!("relay-test-{}", "0199a1b2-0000-7000-8000-00000000000c");
        let with_token = |t: &str| RelaySpawn { token: Secret::new(t.to_string()), ..fixture() };
        let cases: Vec<(RelaySpawn, &str)> = vec![
            (with_token(""), "token is 0 bytes (1 to 2048)"),
            (with_token(&"A".repeat(TOKEN_MAX + 1)), "token is 2049 bytes (1 to 2048)"),
            (with_token(&format!("{token} x")), "token holds a byte outside A-Za-z0-9._~+/=-"),
            (with_token(&format!("{token}\"")), "token holds a byte outside A-Za-z0-9._~+/=-"),
            (RelaySpawn { addr: "10.42.0.20".into(), ..fixture() }, "addr is not <IPv4>:<port>"),
            (RelaySpawn { addr: "10.42.0.20:0".into(), ..fixture() }, "addr has port 0"),
            (RelaySpawn { addr: "203.0.113.7:443".into(), ..fixture() }, "addr is not a private or loopback IPv4 address"),
            (RelaySpawn { addr: "[::1]:7443".into(), ..fixture() }, "addr is not <IPv4>:<port>"),
            (RelaySpawn { addr: "relay.example.test:7443".into(), ..fixture() }, "addr is not <IPv4>:<port>"),
            (RelaySpawn { server_name: String::new(), ..fixture() }, "server_name is not an IPv4 address or a DNS name of at most 253 bytes"),
            (RelaySpawn { server_name: "a".repeat(SERVER_NAME_MAX + 1), ..fixture() }, "server_name is not an IPv4 address or a DNS name of at most 253 bytes"),
            (RelaySpawn { server_name: "a..b".into(), ..fixture() }, "server_name is not"),
            (RelaySpawn { server_name: "-a.test".into(), ..fixture() }, "server_name is not"),
            (RelaySpawn { server_name: "a-.test".into(), ..fixture() }, "server_name is not"),
            (RelaySpawn { ca_der_b64: String::new(), ..fixture() }, "ca_der_b64 decodes to 0 bytes (1 to 4096)"),
            (RelaySpawn { ca_der_b64: "%%%".into(), ..fixture() }, "ca_der_b64 is not standard base64"),
            (RelaySpawn { ca_der_b64: b64(&[0x30; CA_DER_MAX + 1]), ..fixture() }, "ca_der_b64 decodes to 4097 bytes (1 to 4096)"),
            (RelaySpawn { ca_der_b64: b64(&[0x31]), ..fixture() }, "ca_der_b64 is not a DER certificate"),
        ];
        for (r, want) in cases {
            let e = r.check().unwrap_err();
            assert!(e.starts_with(want), "{want}: {e}");
            let t = r.token.expose();
            assert!(!e.contains(&token) && (t.is_empty() || !e.contains(t.as_str())), "no message holds the token: {e}");
        }
    }

    /// A `RelaySpawn` of §V-vm.3.5's values gives `session()` equal byte for byte to the client's fixture, its
    /// newline trimmed.
    #[test]
    fn the_session_payload_is_the_clients_fixture() {
        assert!(FIXTURE.ends_with("}\n"), "{FIXTURE:?}");
        assert_eq!(fixture().session().as_slice(), FIXTURE.trim_end_matches('\n').as_bytes());
        assert!(FIXTURE.trim_end_matches('\n').len() <= SESSION_MAX);
        // The largest valid session still fits the client's bound.
        let big = RelaySpawn { token: Secret::new("A".repeat(TOKEN_MAX)), addr: "10.42.255.255:65535".into(), server_name: "a".repeat(63), ca_der_b64: b64(&[0x30; CA_DER_MAX]) };
        assert!(big.session().len() <= SESSION_MAX, "{}", big.session().len());
    }

    /// `Debug` holds the address, the server name and the CA's length, never the token.
    #[test]
    fn relay_spawn_debug_hides_the_token() {
        let d = format!("{:?}", fixture());
        assert_eq!(d, "RelaySpawn(addr=10.42.0.20:7443, server_name=10.42.0.20, ca=4 chars)");
        assert!(!d.contains(PLACEHOLDER), "{d}");
    }

    /// `image/relay-mcp.json` is `MCP_CONFIG_JSON` and a newline; `mcp_config()` has one server, `MCP_SERVER`, whose
    /// command is `MCP_BIN`, no argument, no environment; the argv token, the socket path and every path are §V-vm.3.1's
    /// literals.
    #[test]
    fn the_image_relay_config_is_the_shims() {
        let image = include_str!("../../../../image/relay-mcp.json");
        assert_eq!(image, format!("{MCP_CONFIG_JSON}\n"));
        let servers = mcp_config()["mcpServers"].as_object().unwrap().clone();
        assert_eq!(servers.keys().collect::<Vec<_>>(), [MCP_SERVER]);
        let server = &servers[MCP_SERVER];
        assert_eq!((server["type"].as_str(), server["command"].as_str()), (Some("stdio"), Some(MCP_BIN)));
        assert_eq!((server["args"].clone(), server["env"].clone()), (serde_json::json!([]), serde_json::json!({})));
        assert_eq!(server.as_object().unwrap().len(), 4, "type, command, args, env alone");
        assert_eq!(mcp_config_arg(Path::new(MCP_CONFIG)), "--mcp-config=/etc/ai-env/relay-mcp.json");
        assert_eq!(socket_path(Path::new(SOCKET_DIR), 42), PathBuf::from("/run/ai-env/relay/42.sock"));
        assert_eq!(
            (MCP_SERVER, TOOL_CATALOG, TOOL_CALL, CLIENT_BIN, MCP_BIN, MCP_CONFIG, RUN_DIR, SOCKET_DIR),
            ("ai-env-relay", "relay_catalog", "relay_call", "/usr/local/bin/ai-env-relay-client", "/usr/local/bin/ai-env-relay-mcp", "/etc/ai-env/relay-mcp.json", "/run/ai-env", "/run/ai-env/relay")
        );
        assert_eq!((SESSION_V, TOKEN_MAX, TOKEN_BYTES, CA_DER_MAX, SERVER_NAME_MAX, SESSION_MAX), (1, 2048, "A-Za-z0-9._~+/=-", 4096, 253, 8192), "the client's bounds (its own test pins the same literals)");
    }
}
