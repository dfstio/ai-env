//! The tests' relay PKI, made at run time with the OpenSSL 3+ CLI (Homebrew's when present, as
//! `crates/ai-env-cli/tests/tls_policy.rs` finds it): two P-256 CAs, A and B, and leaf certificates under
//! them, all kept in memory once per test process (WM-I5: a relay of R's tests terminates TLS the same way).
//! No key is committed: every key here is made by `openssl genpkey` in a temp dir that is gone at once.
#![allow(dead_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Every wait on the openssl CLI.
const LIMIT: Duration = Duration::from_secs(30);

/// A certificate and its PKCS#8 key, both PEM.
#[derive(Clone)]
pub struct Pair {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// The test PKI.
pub struct Pki {
    /// CA A's certificate: what a worker pins.
    pub ca_a: Vec<u8>,
    /// CA B's certificate: another CA nobody pins.
    pub ca_b: Vec<u8>,
    /// A relay leaf for `ai-env-relay` under CA A.
    pub relay_a: Pair,
    /// The same name under CA B.
    pub relay_b: Pair,
    /// A leaf for `relay.example.test` under CA A.
    pub other_name_a: Pair,
}

/// The PKI, made once per test process.
pub fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let dir = tempfile::tempdir().expect("a temp dir");
        let d = dir.path();
        let ca_a = ca(d, "ca-a", "ai-env test relay CA A");
        let ca_b = ca(d, "ca-b", "ai-env test relay CA B");
        Pki {
            relay_a: leaf(d, "relay-a", &ca_a, "ai-env-relay", "DNS:ai-env-relay"),
            relay_b: leaf(d, "relay-b", &ca_b, "ai-env-relay", "DNS:ai-env-relay"),
            other_name_a: leaf(d, "other-a", &ca_a, "relay.example.test", "DNS:relay.example.test"),
            ca_a: std::fs::read(&ca_a.0).expect("CA A"),
            ca_b: std::fs::read(&ca_b.0).expect("CA B"),
        }
    })
}

/// The program and its arguments, never the environment.
fn shown(cmd: &Command) -> String {
    std::iter::once(cmd.get_program()).chain(cmd.get_args()).map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" ")
}

/// `cmd` to its end within `LIMIT`, stdout and stderr collected.
pub fn output_within(cmd: &mut Command) -> Output {
    output_within_for(cmd, LIMIT)
}

/// `cmd` to its end within `limit`, stdout and stderr collected; killed and failed past it.
pub fn output_within_for(cmd: &mut Command, limit: Duration) -> Output {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap_or_else(|e| panic!("{}: {e}", shown(cmd)));
    let drain = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.read_to_end(&mut buf);
            buf
        })
    };
    let (out, err) = (drain(Box::new(child.stdout.take().expect("stdout"))), drain(Box::new(child.stderr.take().expect("stderr"))));
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(s) = child.try_wait().expect("wait") {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{} did not finish within {limit:?}", shown(cmd));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output { status, stdout: out.join().expect("stdout"), stderr: err.join().expect("stderr") }
}

fn run_ok(cmd: &mut Command) {
    let out = output_within(cmd);
    assert!(out.status.success(), "{}: {}", shown(cmd), String::from_utf8_lossy(&out.stderr));
}

/// The openssl CLI: Homebrew's when present, else the PATH's; OpenSSL 3 or later (macOS's own `openssl`
/// is LibreSSL). Checked once per process.
pub fn openssl() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let brew = Path::new("/opt/homebrew/bin/openssl");
        let bin = if brew.is_file() { brew.to_path_buf() } else { PathBuf::from("openssl") };
        let out = output_within(Command::new(&bin).arg("version"));
        let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let major: u32 = version.strip_prefix("OpenSSL ").and_then(|v| v.split('.').next()).and_then(|m| m.parse().ok()).unwrap_or(0);
        assert!(major >= 3, "{} is {version:?}: the relay tests need the OpenSSL 3+ CLI (brew install openssl)", bin.display());
        bin
    })
}

/// A P-256 key at `path`.
fn key(path: &Path) {
    run_ok(Command::new(openssl()).args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out"]).arg(path));
}

/// A CA (pathlen 0) named `cn`: (its certificate's path, its key's path).
fn ca(dir: &Path, name: &str, cn: &str) -> (PathBuf, PathBuf) {
    let (cert, k) = (dir.join(format!("{name}.pem")), dir.join(format!("{name}.key")));
    key(&k);
    run_ok(
        Command::new(openssl())
            .args(["req", "-x509", "-new", "-key"])
            .arg(&k)
            .arg("-out")
            .arg(&cert)
            .args(["-days", "2", "-subj", &format!("/CN={cn}")])
            .args(["-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]),
    );
    (cert, k)
}

/// A server leaf for `cn` with the SAN `san`, signed by `ca`.
fn leaf(dir: &Path, name: &str, ca: &(PathBuf, PathBuf), cn: &str, san: &str) -> Pair {
    let (cert, k, csr, cnf) = (dir.join(format!("{name}.pem")), dir.join(format!("{name}.key")), dir.join(format!("{name}.csr")), dir.join(format!("{name}.cnf")));
    key(&k);
    std::fs::write(&cnf, format!("[leaf]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\nsubjectAltName = {san}\n")).expect("cnf");
    run_ok(Command::new(openssl()).args(["req", "-new", "-key"]).arg(&k).arg("-out").arg(&csr).args(["-subj", &format!("/CN={cn}")]));
    run_ok(
        Command::new(openssl())
            .args(["x509", "-req", "-in"])
            .arg(&csr)
            .arg("-CA")
            .arg(&ca.0)
            .arg("-CAkey")
            .arg(&ca.1)
            .args(["-set_serial", &format!("{}", 1000 + name.len() * 7 + usize::from(name.as_bytes()[0])), "-days", "2", "-extensions", "leaf", "-extfile"])
            .arg(&cnf)
            .arg("-out")
            .arg(&cert),
    );
    Pair { cert_pem: std::fs::read(&cert).expect("cert"), key_pem: std::fs::read(&k).expect("key") }
}
