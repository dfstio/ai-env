//! The fd-3 payload (§V-vm.3.5): the one compact JSON object `ai_env_cli::wire::relay::RelaySpawn::session` writes,
//! `v`, `token`, `addr`, `server_name`, `ca_der_b64`. The client reads it once, to its end, closes fd 3 and checks it
//! with V-R3's shapes on its own side (V-R16): the same bounds, each refusal naming its field, never a value. The
//! token lives in a [`zeroize::Zeroizing`] string, and `Debug` never shows it.
use base64::Engine as _;
use serde::Deserialize;
use sha2::Digest as _;
use std::net::{Ipv4Addr, SocketAddrV4};

/// The payload's `v`.
pub const SESSION_V: u32 = 1;
/// A token is 1 to this many bytes of `A-Za-z0-9._~+/=-` (= `wire::relay::TOKEN_MAX`).
pub const TOKEN_MAX: usize = 2048;
/// A CA certificate's DER is 1 to this many bytes (= `wire::relay::CA_DER_MAX`).
pub const CA_DER_MAX: usize = 4096;
/// A server name's bound, a DNS name's (= `wire::relay::SERVER_NAME_MAX`).
pub const SERVER_NAME_MAX: usize = 253;
/// The payload's bound (= `wire::relay::SESSION_MAX`): more is refused.
pub const SESSION_MAX: usize = 8192;

/// A relay session, as the client holds it.
pub struct Session {
    token: zeroize::Zeroizing<String>,
    /// The relay's private face: a private or loopback IPv4 address, a port that is not 0.
    pub addr: SocketAddrV4,
    /// The name the relay's certificate must carry: an IPv4 literal or a DNS name.
    pub server_name: String,
    /// The relay CA's certificate (DER): the one trust anchor.
    pub ca_der: Vec<u8>,
}

/// Why a payload was refused: its field, never its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    TooLarge,
    NotJson,
    Version,
    Token,
    Addr,
    ServerName,
    Ca,
}

impl SessionError {
    /// The refusal's field: `refused: session <field>`.
    #[must_use]
    pub fn field(self) -> &'static str {
        match self {
            SessionError::TooLarge => "size",
            SessionError::NotJson => "json",
            SessionError::Version => "v",
            SessionError::Token => "token",
            SessionError::Addr => "addr",
            SessionError::ServerName => "server_name",
            SessionError::Ca => "ca_der_b64",
        }
    }
}

/// The payload's keys, exactly (any other is `NotJson`). The token is read straight into a zeroized string, so a
/// payload refused after it (a later key of the wrong type, a key twice) leaves no copy behind.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    v: u32,
    #[serde(deserialize_with = "zeroized")]
    token: zeroize::Zeroizing<String>,
    addr: String,
    server_name: String,
    ca_der_b64: String,
}

/// A JSON string as a [`zeroize::Zeroizing`] string: the deserializer's own `String` taken as it is, a borrowed one
/// copied into a buffer of its exact size (it never grows, so no reallocation leaves a copy).
fn zeroized<'de, D: serde::Deserializer<'de>>(d: D) -> Result<zeroize::Zeroizing<String>, D::Error> {
    struct Zeroized;
    impl serde::de::Visitor<'_> for Zeroized {
        type Value = zeroize::Zeroizing<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a string")
        }
        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
            let mut z = zeroize::Zeroizing::new(String::with_capacity(s.len()));
            z.push_str(s);
            Ok(z)
        }
        fn visit_string<E: serde::de::Error>(self, s: String) -> Result<Self::Value, E> {
            Ok(zeroize::Zeroizing::new(s))
        }
    }
    d.deserialize_string(Zeroized)
}

/// One byte of a token: base64, base64url and the dots between a signed token's parts.
fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

/// 1 to [`SERVER_NAME_MAX`] bytes of labels `[A-Za-z0-9-]{1,63}` joined by single dots, none starting or ending with
/// `-`.
fn dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= SERVER_NAME_MAX
        && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') && !l.starts_with('-') && !l.ends_with('-'))
}

impl Session {
    /// V-R16's checks, in field order: the size, the JSON, `v`, then V-R3's shapes.
    pub fn parse(bytes: &[u8]) -> Result<Session, SessionError> {
        if bytes.len() > SESSION_MAX {
            return Err(SessionError::TooLarge);
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| SessionError::NotJson)?;
        let Wire { v, token, addr, server_name, ca_der_b64 } = wire;
        if v != SESSION_V {
            return Err(SessionError::Version);
        }
        if token.is_empty() || token.len() > TOKEN_MAX || !token.bytes().all(token_byte) {
            return Err(SessionError::Token);
        }
        let addr: SocketAddrV4 = addr.parse().map_err(|_| SessionError::Addr)?;
        if addr.port() == 0 || !(addr.ip().is_private() || addr.ip().is_loopback()) {
            return Err(SessionError::Addr);
        }
        if server_name.parse::<Ipv4Addr>().is_err() && !dns_name(&server_name) {
            return Err(SessionError::ServerName);
        }
        let ca_der = base64::engine::general_purpose::STANDARD.decode(&ca_der_b64).map_err(|_| SessionError::Ca)?;
        if ca_der.is_empty() || ca_der.len() > CA_DER_MAX || ca_der[0] != 0x30 {
            return Err(SessionError::Ca);
        }
        Ok(Session { token, addr, server_name, ca_der })
    }

    /// fd 3 to its end (at most [`SESSION_MAX`] + 1 bytes), then closed; [`Session::parse`]. A read error is
    /// `NotJson` (the client's `main` reads fd 3 itself first, to name such an error `fd 3 <why>`).
    pub fn read_fd3() -> Result<Session, SessionError> {
        let bytes = read_fd(3).map_err(|_| SessionError::NotJson)?;
        Session::parse(&bytes)
    }

    /// The token, for the one metadata value of V-R21.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The CA's `<sha12>`, for the ready line.
    #[must_use]
    pub fn ca_fingerprint(&self) -> String {
        hex::encode(sha2::Sha256::digest(&self.ca_der))[..12].to_string()
    }
}

/// `Session(addr=<addr>, server_name=<server_name>, ca=<sha12>)`: never the token.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session(addr={}, server_name={}, ca={})", self.addr, self.server_name, self.ca_fingerprint())
    }
}

/// `fd` read to its end, at most [`SESSION_MAX`] + 1 bytes (so a longer payload is told from one at the bound), into
/// a buffer zeroized when dropped; then `fd` is closed (once read, whatever the outcome). `Err` when `fd` is not
/// open or a read fails.
pub(crate) fn read_fd(fd: libc::c_int) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;
    // SAFETY: F_GETFD only reads the descriptor's flags; EBADF says it is not open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the descriptor is open (checked above) and nothing else in this process owns it: the shim hands it to
    // the client alone, and the File closes it when dropped.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(SESSION_MAX + 1));
    let limit = u64::try_from(SESSION_MAX + 1).unwrap_or(u64::MAX);
    file.take(limit).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/session-v1.json");
    /// The fixture's placeholder (GitGuardian: a low-entropy value under `token`).
    const PLACEHOLDER: &str = "0199a1b2-0000-7000-8000-000000000001";

    /// The fixture with `key` set to `value` (a JSON value's text).
    fn with(key: &str, value: &str) -> String {
        let mut m: serde_json::Map<String, serde_json::Value> = serde_json::from_str(FIXTURE.trim_end()).unwrap();
        m.insert(key.to_string(), serde_json::from_str(value).unwrap());
        serde_json::to_string(&m).unwrap()
    }

    fn b64(bytes: &[u8]) -> String {
        format!("\"{}\"", base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// V-R3's table on the client's side, each the right [`SessionError`]: 8193 bytes is `TooLarge`, `v` 2 is
    /// `Version`; `Debug` never holds the token. The private positives outside 10.42.0.0/16 are built at run time
    /// (P-R88 (a): the leak guard scans this crate); the public negative is a documentation address.
    #[test]
    fn session_parse_refuses_each_bad_field() {
        let ok = Session::parse(FIXTURE.trim_end().as_bytes()).unwrap();
        let shown = format!("{ok:?}");
        assert!(!shown.contains(PLACEHOLDER) && shown.contains("addr=10.42.0.20:7443") && shown.contains("server_name=10.42.0.20"), "{shown}");
        let quad = |p: [&str; 4]| p.join(".");
        for addr in [format!("{}:7443", quad(["172", "16", "0", "1"])), format!("{}:7443", quad(["192", "168", "0", "10"])), "127.0.0.1:1".to_string()] {
            assert!(Session::parse(with("addr", &format!("\"{addr}\"")).as_bytes()).is_ok(), "{addr}");
        }
        assert!(Session::parse(with("server_name", "\"relay.internal.test\"").as_bytes()).is_ok());
        assert!(Session::parse(with("token", &format!("\"{}\"", "A".repeat(TOKEN_MAX))).as_bytes()).is_ok(), "2048 bytes");
        assert!(Session::parse(with("ca_der_b64", &b64(&[0x30; CA_DER_MAX])).as_bytes()).is_ok(), "4096 bytes");
        let token = format!("relay-test-{}", "0199a1b2-0000-7000-8000-00000000000b");
        let cases: Vec<(String, SessionError)> = vec![
            (format!("{}{}", FIXTURE.trim_end(), " ".repeat(SESSION_MAX + 1 - FIXTURE.trim_end().len())), SessionError::TooLarge),
            ("{".to_string(), SessionError::NotJson),
            ("[]".to_string(), SessionError::NotJson),
            (with("extra", "1"), SessionError::NotJson),
            // Refused after the token was read (the fixture's key order): a later key of the wrong type, the token twice.
            (FIXTURE.trim_end().replacen("\"ca_der_b64\":\"MA==\"", "\"ca_der_b64\":1", 1), SessionError::NotJson),
            (FIXTURE.trim_end().replacen(",\"addr\"", &format!(",\"token\":\"{PLACEHOLDER}\",\"addr\""), 1), SessionError::NotJson),
            (with("v", "2"), SessionError::Version),
            (with("token", "\"\""), SessionError::Token),
            (with("token", &format!("\"{}\"", "A".repeat(TOKEN_MAX + 1))), SessionError::Token),
            (with("token", &format!("\"{token} x\"")), SessionError::Token),
            (with("token", &format!("\"{token}\\\"\"")), SessionError::Token),
            (with("addr", "\"10.42.0.20\""), SessionError::Addr),
            (with("addr", "\"10.42.0.20:0\""), SessionError::Addr),
            (with("addr", "\"203.0.113.7:443\""), SessionError::Addr),
            (with("addr", "\"[::1]:7443\""), SessionError::Addr),
            (with("addr", "\"relay.example.test:7443\""), SessionError::Addr),
            (with("server_name", "\"\""), SessionError::ServerName),
            (with("server_name", &format!("\"{}\"", "a".repeat(SERVER_NAME_MAX + 1))), SessionError::ServerName),
            (with("server_name", "\"a..b\""), SessionError::ServerName),
            (with("server_name", "\"-a.test\""), SessionError::ServerName),
            (with("server_name", "\"a-.test\""), SessionError::ServerName),
            (with("ca_der_b64", "\"\""), SessionError::Ca),
            (with("ca_der_b64", "\"%%%\""), SessionError::Ca),
            (with("ca_der_b64", &b64(&[0x30; CA_DER_MAX + 1])), SessionError::Ca),
            (with("ca_der_b64", &b64(&[0x31])), SessionError::Ca),
        ];
        for (payload, want) in cases {
            match Session::parse(payload.as_bytes()) {
                Err(e) => assert_eq!(e, want, "{payload:.80}"),
                Ok(s) => panic!("accepted {s:?}: {payload:.80}"),
            }
        }
        // Exactly at the bound: parsed (a longer one is TooLarge above).
        let padded = format!("{}{}", FIXTURE.trim_end(), " ".repeat(SESSION_MAX - FIXTURE.trim_end().len()));
        assert_eq!(padded.len(), SESSION_MAX);
        assert!(Session::parse(padded.as_bytes()).is_ok());
        let words: Vec<&str> = [SessionError::TooLarge, SessionError::NotJson, SessionError::Version, SessionError::Token, SessionError::Addr, SessionError::ServerName, SessionError::Ca].map(SessionError::field).to_vec();
        assert_eq!(words, ["size", "json", "v", "token", "addr", "server_name", "ca_der_b64"]);
    }

    /// The fixture gives the placeholder, `10.42.0.20:7443`, `10.42.0.20` and `[0x30]`; the client's bounds are
    /// ai-env-cli's (`wire::relay`), literals pinned on both sides.
    #[test]
    fn the_session_fixture_parses() {
        let s = Session::parse(FIXTURE.trim_end().as_bytes()).unwrap();
        assert_eq!(s.token(), PLACEHOLDER);
        assert_eq!(s.addr, "10.42.0.20:7443".parse::<SocketAddrV4>().unwrap());
        assert_eq!(s.server_name, "10.42.0.20");
        assert_eq!(s.ca_der, [0x30]);
        assert_eq!(s.ca_fingerprint(), hex::encode(sha2::Sha256::digest([0x30]))[..12]);
        assert_eq!((SESSION_V, TOKEN_MAX, CA_DER_MAX, SERVER_NAME_MAX, SESSION_MAX), (1, 2048, 4096, 253, 8192));
        assert_eq!(crate::local::SOCKET_DIR, "/run/ai-env/relay");
        assert!(FIXTURE.ends_with("}\n") && FIXTURE.matches('\n').count() == 1, "one line and its newline");
    }

    /// A pipe's bytes to its end (the descriptor is `read_fd`'s from then on: it closes it). Control: the binary's
    /// fd-3 refusals are `a_bad_session_on_fd_3_refuses_to_start`'s.
    #[test]
    fn read_fd_takes_a_pipe_to_its_end() {
        use std::io::Write as _;
        let mut fds: [libc::c_int; 2] = [-1, -1];
        // SAFETY: `fds` is an array of two ints for pipe(2) to fill.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the write end was just made and is ours.
        let mut w = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[1]) };
        w.write_all(FIXTURE.trim_end().as_bytes()).unwrap();
        drop(w);
        let bytes = read_fd(fds[0]).unwrap();
        assert_eq!(&bytes[..], FIXTURE.trim_end().as_bytes());
    }
}
