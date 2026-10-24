//! S11 part A (wave 1, A2): `ai-env claude` through the real binary under the
//! fake API: `admit` (the release's manifest and signature through the lab
//! knobs' fake curl and gpgv, the Linux bytes, the markers, the Docker tests
//! through the fake make), `stage` (an internet VM's relay, a stand-in relay
//! server until I1), `update`, `gc`, `forget`, `status` and `manifest`.
//! Never downloads.claude.ai, the real gpgv, the real make or Docker; never
//! the developer's claude.
//!
//! The world: a temp HOME with `bridge/` (bridge.toml naming the fake image),
//! `bin/` (the fakes: `release-curl` is tests/fakes/curl.sh, `gpgv`,
//! `admit-make`, `docker` first on PATH, a `cargo` that does nothing), the
//! release files the fake curl serves, and `fake.json`, the file-backed fake
//! API. The release curl, gpgv and make run with a cleared or scrubbed
//! environment: their knobs live in `<fake>.knobs`. The stager's VM answers
//! `/health` from the fake's state; its `POST /claude/relay` reaches a
//! stand-in relay ([`Relay`]) through the routed fake endpoint (its token
//! checked there), which PUTs the bytes to the tests' S3 with the presigned
//! URL it was handed, as the shim's relay does (LD-21).
#![cfg(all(feature = "bridge", feature = "shim"))]

mod common;

use ai_env_cli::bridge::api::{Call, FakeState, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::claude::{AdmissionRow, Phase, Record, SignatureRow, StagingRow};
use ai_env_cli::bridge::config::Paths;
use ai_env_cli::wire::pin::RELEASE_KEY_FPR;
use ai_env_cli::bridge::claude::admit::VersionLock;
use ai_env_cli::wire::workspace::{ClaudeRelay, APP_PORT};
use common::fake_endpoint::FakeEndpoint;
use common::fake_s3::FakeS3;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const V: &str = "2.1.308";
const LIMIT: Duration = Duration::from_secs(120);

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn all(o: &Output) -> String {
    format!("{}{}", text(&o.stdout), text(&o.stderr))
}

/// A Linux "binary" holding every `V_MARKERS` marker: claude-v2.sh reporting `version`, the markers in a comment.
fn claude_bytes(version: &str) -> Vec<u8> {
    let mut b = common::fake_claude_bytes(version, None, &[]);
    b.extend_from_slice(b"\n# the admission's markers:");
    for m in ai_env_cli::wire::claude::V_MARKERS {
        b.push(b' ');
        b.extend_from_slice(m.forms[0].as_bytes());
    }
    b.push(b'\n');
    b
}

/// A release manifest for `version` naming `bytes` as its linux-arm64 build.
fn manifest(version: &str, bytes: &[u8]) -> String {
    serde_json::json!({
        "version": version,
        "buildDate": "2026-10-22T01:39:37Z",
        "platforms": {
            "darwin-arm64": {"binary": "claude", "checksum": "ef".repeat(32), "size": 7},
            "linux-arm64": {"binary": "claude", "checksum": sha(bytes), "size": bytes.len()}
        }
    })
    .to_string()
}

/// One isolated world (the module doc).
struct W {
    tmp: tempfile::TempDir,
}

impl W {
    fn new() -> W {
        let tmp = tempfile::tempdir().unwrap();
        let w = W { tmp };
        let root = w.root();
        for d in ["bridge", "keys", "bin", "release"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let toml = format!("[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\nexecution_role_arn = \"arn:aws:iam::123456789012:role/ai-env-exec\"\n\n[vm]\nmax_concurrent = 3\n");
        std::fs::write(root.join("bridge/bridge.toml"), toml).unwrap();
        w.update(|s| s.auto_advance = true);
        for (src, name) in [("curl.sh", "release-curl"), ("gpgv.sh", "gpgv"), ("admit-make.sh", "admit-make"), ("docker.sh", "docker")] {
            let dst = root.join("bin").join(name);
            std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes").join(src), &dst).unwrap();
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cargo = root.join("bin/cargo");
        std::fs::write(&cargo, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The fakes' knobs: curl serves the release dir, gpgv verifies by the release key, make passes.
        w.curl_knobs(&[]);
        w.gpgv_knobs(&[("FAKE_GPGV_VERIFY", "good")]);
        w.make_knobs(&[]);
        w
    }

    fn root(&self) -> PathBuf {
        std::fs::canonicalize(self.tmp.path()).unwrap()
    }

    fn bin(&self, name: &str) -> PathBuf {
        self.root().join("bin").join(name)
    }

    fn log(&self, name: &str) -> PathBuf {
        self.root().join(format!("{name}.log"))
    }

    fn lines(&self, name: &str) -> Vec<String> {
        std::fs::read_to_string(self.log(name)).unwrap_or_default().lines().map(str::to_string).collect()
    }

    fn paths(&self) -> Paths {
        Paths::from_root_and_env(self.root().join("bridge"), None)
    }

    fn fake(&self) -> PathBuf {
        self.root().join("fake.json")
    }

    fn state(&self) -> FakeState {
        serde_json::from_str(&std::fs::read_to_string(self.fake()).unwrap()).unwrap()
    }

    fn update(&self, f: impl FnOnce(&mut FakeState)) {
        let mut s = std::fs::read_to_string(self.fake()).ok().filter(|t| !t.trim().is_empty()).map_or_else(FakeState::new, |t| serde_json::from_str(&t).unwrap());
        f(&mut s);
        std::fs::write(self.fake(), serde_json::to_string_pretty(&s).unwrap()).unwrap();
    }

    fn curl_knobs(&self, extra: &[(&str, &str)]) {
        let (dir, log, env) = (self.root().join("release").display().to_string(), self.log("curl").display().to_string(), self.log("curl-env").display().to_string());
        let mut k = vec![("FAKE_CURL_DIR", dir.as_str()), ("FAKE_CURL_LOG", log.as_str()), ("FAKE_CURL_ENV_LOG", env.as_str())];
        k.extend_from_slice(extra);
        common::write_knobs(&PathBuf::from(format!("{}.knobs", self.bin("release-curl").display())), &k);
    }

    fn gpgv_knobs(&self, extra: &[(&str, &str)]) {
        let log = self.log("gpgv").display().to_string();
        let mut k = vec![("FAKE_GPGV_PRIMARY", RELEASE_KEY_FPR), ("FAKE_GPGV_LOG", log.as_str())];
        k.extend_from_slice(extra);
        common::write_knobs(&PathBuf::from(format!("{}.knobs", self.bin("gpgv").display())), &k);
    }

    fn make_knobs(&self, extra: &[(&str, &str)]) {
        let (log, env) = (self.log("make").display().to_string(), self.log("make-env").display().to_string());
        let mut k = vec![("FAKE_MAKE_LOG", log.as_str()), ("FAKE_MAKE_ENV_LOG", env.as_str())];
        k.extend_from_slice(extra);
        common::write_knobs(&PathBuf::from(format!("{}.knobs", self.bin("admit-make").display())), &k);
    }

    /// The release files of `version` the fake curl serves: its manifest (naming `bytes`), the signature unless
    /// `!sig`, and the binary `served` (`bytes` unless given).
    fn serve(&self, version: &str, bytes: &[u8], sig: bool, served: Option<&[u8]>) {
        let rel = self.root().join("release");
        std::fs::write(rel.join("manifest.json"), manifest(version, bytes)).unwrap();
        if sig {
            std::fs::write(rel.join("manifest.json.sig"), "a detached signature\n").unwrap();
        } else {
            let _ = std::fs::remove_file(rel.join("manifest.json.sig"));
        }
        std::fs::write(rel.join("claude"), served.unwrap_or(bytes)).unwrap();
    }

    /// `ai-env <args>` in this world: the fake API, the S11 knobs, the fakes first on PATH, Docker answering with
    /// the local image there, nothing of the developer's shell.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ai-env"));
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().to_string();
            if k.starts_with("AWS_") || k.starts_with("PULUMI_") || k.starts_with("AI_ENV_") || k.starts_with("CLAUDE_CODE_") || k.starts_with("FAKE_") || k == "RUST_LOG" {
                c.env_remove(&k);
            }
        }
        let root = self.root();
        c.args(args)
            .env("HOME", &root)
            .env("AI_ENV_BRIDGE_DIR", root.join("bridge"))
            .env("AI_ENV_DIR", root.join("keys"))
            .env("PATH", format!("{}:/usr/bin:/bin", root.join("bin").display()))
            .env("AI_ENV_BRIDGE_LAB_FAKE_API", self.fake())
            .env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1")
            .env("AI_ENV_BRIDGE_LAB_RELEASE_CURL", self.bin("release-curl"))
            .env("AI_ENV_BRIDGE_LAB_GPGV", self.bin("gpgv"))
            .env("AI_ENV_BRIDGE_LAB_ADMIT_MAKE", self.bin("admit-make"))
            .env("FAKE_DOCKER_VERSION", "29.8.0 arm64")
            .env("FAKE_DOCKER_IMAGE_ID", "sha256:0123456789abcdef")
            .env("AI_ENV_AUDIT_STRICT", "1")
            .stdin(Stdio::null());
        c
    }

    fn run(&self, cmd: Command) -> Output {
        common::bounded::run_within(cmd, None, LIMIT, "ai-env claude")
    }

    fn ai(&self, args: &[&str]) -> Output {
        self.run(self.cmd(args))
    }

    fn record(&self, version: &str) -> Option<Record> {
        Record::load(&self.paths(), version).unwrap()
    }

    /// V's record as an admission leaves it for `bytes` (staging `state` when given).
    fn admitted(&self, version: &str, bytes: &[u8], state: Option<&str>) {
        let key = format!("v1/_claude/mac/{version}/{}", sha(bytes));
        Record::update(&self.paths(), version, |r| {
            r.signature = Some(SignatureRow { outcome: "ok".into(), signer: Some(RELEASE_KEY_FPR.into()), linux_sha256: Some(sha(bytes)), linux_size: Some(bytes.len() as u64), at: "t".into(), ..SignatureRow::default() });
            r.admission = Some(AdmissionRow { outcome: "admitted".into(), markers: Some("ok".into()), ai_env: "0.1.0".into(), at: "t".into(), ..AdmissionRow::default() });
            r.staging = state.map(|s| StagingRow { state: s.into(), s3_key: key.clone(), at: "t".into(), ..StagingRow::default() });
        })
        .unwrap();
    }

    fn audit(&self, event: &str) -> Vec<Value> {
        std::fs::read_to_string(self.root().join("bridge/audit.jsonl")).unwrap_or_default().lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|r| r["event"] == event).collect()
    }

    fn runs(&self) -> usize {
        self.state().calls.iter().filter(|c| matches!(c, Call::Run { .. })).count()
    }

    fn terminated(&self) -> Vec<String> {
        self.state().calls.into_iter().filter_map(|c| if let Call::Terminate(id) = c { Some(id) } else { None }).collect()
    }

    /// A Cursor bundle of `version` installed (the default V of every command).
    fn bundle(&self, version: &str) {
        std::fs::create_dir_all(self.root().join(format!(".cursor/extensions/anthropic.claude-code-{version}-darwin-arm64"))).unwrap();
    }

    /// A live Cursor window on extension `version`: a census row whose host is this test process.
    fn window(&self, version: &str) {
        let logs = self.root().join("bridge/logs");
        std::fs::create_dir_all(&logs).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
        let row = serde_json::json!({"ppid": std::process::id(), "start": now as u64, "ext": version});
        std::fs::OpenOptions::new().create(true).append(true).open(logs.join("census.jsonl")).unwrap().write_all(format!("{row}\n").as_bytes()).unwrap();
    }

    /// A stager's world: the tests' S3, the stand-in relay behind the routed fake endpoint, the VM's `/health`
    /// naming `claude_stage_v1` unless `!cap`.
    fn stager(&self, relay: Relaying, cap: bool) -> Stager {
        let s3 = FakeS3::start();
        let relay = Relay::start(relay);
        let endpoint = FakeEndpoint::start_routed(&self.fake(), &[(APP_PORT, relay.addr)], None);
        let mut caps: Vec<String> = ["workspace_v1", "transcript_s3_v1"].map(str::to_string).to_vec();
        if cap {
            caps.push(ai_env_cli::wire::frame::CAP_CLAUDE_STAGE_V1.to_string());
        }
        self.update(|s| s.health_caps = caps);
        Stager { s3, relay, endpoint }
    }

    /// `ai-env <args>` against a stager's world.
    fn staged(&self, st: &Stager, args: &[&str]) -> Output {
        let mut c = self.cmd(args);
        c.env("AI_ENV_BRIDGE_LAB_S3_ADDR", st.s3.addr().to_string()).env("AI_ENV_BRIDGE_LAB_AGENT_ADDR", st.endpoint.addr.to_string());
        self.run(c)
    }
}

/// What the stand-in relay does with a `POST /claude/relay`.
#[derive(Clone)]
enum Relaying {
    /// PUT these bytes to the presigned URL it was handed (the tests' S3 judges it), and answer S3's status.
    Put(Vec<u8>),
    /// Answer this S3 status without a PUT.
    Answer(u16),
}

/// A stager's world (the tests' S3, the relay, the endpoint in front of it).
struct Stager {
    s3: FakeS3,
    relay: Relay,
    endpoint: FakeEndpoint,
}

/// The stand-in relay (LD-21): an HTTP/1.1 listener on loopback answering `POST /claude/relay` as the shim does,
/// every request kept.
struct Relay {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Relay {
    fn start(how: Relaying) -> Relay {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let kept = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = serve_relay(stream, &how, &kept);
            }
        });
        Relay { addr, requests }
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
}

/// One HTTP request: its request line, its headers (lowercase names) and its body.
type Request = (String, Vec<(String, String)>, Vec<u8>);

/// One HTTP request off `stream`.
fn read_request(stream: &mut TcpStream) -> std::io::Result<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::other("closed before the head"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = text(&buf[..head_end]);
    let mut lines = head.split("\r\n");
    let line = lines.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok((line, headers, body))
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    write!(stream, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
    stream.flush()
}

fn serve_relay(mut stream: TcpStream, how: &Relaying, kept: &Mutex<Vec<Value>>) -> std::io::Result<()> {
    let (line, _, body) = read_request(&mut stream)?;
    if !line.starts_with("POST /claude/relay ") {
        return respond(&mut stream, 404, "{\"code\":\"not_found\",\"message\":\"no route\"}");
    }
    let req: Value = serde_json::from_slice(&body).map_err(std::io::Error::other)?;
    kept.lock().unwrap().push(req.clone());
    // The shim's own check first (its handler answers 400 on it): what the Mac sends must pass it.
    let checked = serde_json::from_slice::<ClaudeRelay>(&body).map_err(|e| e.to_string()).and_then(|r| r.check());
    if let Err(e) = checked {
        return respond(&mut stream, 400, &serde_json::json!({"code": "bad_request", "message": e}).to_string());
    }
    let (len, sha256) = (req["size"].as_u64().unwrap_or(0), req["sha256"].as_str().unwrap_or_default().to_string());
    let answer = match how {
        Relaying::Put(bytes) => {
            let (status, version_id) = put_presigned(req["put"].as_str().unwrap(), bytes, &sha256, req["owner"].as_str().unwrap())?;
            serde_json::json!({"s3_status": status, "version_id": version_id, "len": bytes.len(), "sha256": sha(bytes)})
        }
        Relaying::Answer(412) => serde_json::json!({"s3_status": 412, "s3_code": "PreconditionFailed", "len": len, "sha256": sha256}),
        Relaying::Answer(s) => serde_json::json!({"s3_status": s, "s3_code": "AccessDenied", "len": 0, "sha256": "0".repeat(64)}),
    };
    respond(&mut stream, 200, &answer.to_string())
}

/// The relay's PUT as the shim's curl sends it: the presigned URL with exactly the headers it signed.
fn put_presigned(url: &str, bytes: &[u8], sha256: &str, owner: &str) -> std::io::Result<(u16, Option<String>)> {
    let rest = url.strip_prefix("http://").expect("a lab URL");
    let (host, path) = rest.split_once('/').unwrap();
    let mut s = TcpStream::connect(host)?;
    let checksum = ai_env_cli::wire::s3::sha256_b64(sha256).unwrap();
    write!(s, "PUT /{path} HTTP/1.1\r\nhost: {host}\r\ncontent-length: {}\r\nx-amz-checksum-sha256: {checksum}\r\nif-none-match: *\r\nx-amz-expected-bucket-owner: {owner}\r\nconnection: close\r\n\r\n", bytes.len())?;
    s.write_all(bytes)?;
    let mut answer = Vec::new();
    s.read_to_end(&mut answer)?;
    let answer = text(&answer);
    let status = answer.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let version_id = answer.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("x-amz-version-id:").map(|v| v.trim().to_string()));
    Ok((status, version_id))
}

// ---- admit and manifest ----------------------------------------------------------------------------------------

/// The release curl runs `-q` first (no `.curlrc`), https only, with a cleared environment: a `.curlrc` in HOME and
/// an `https_proxy` in the environment are planted and never reach it.
#[test]
fn the_release_curl_is_q_with_a_cleared_env() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    std::fs::write(w.root().join(".curlrc"), "proxy = \"http://127.0.0.1:9\"\n").unwrap();
    let out = w.run({
        let mut c = w.cmd(&["claude", "manifest", V, "--out", w.root().join("m").to_str().unwrap()]);
        c.env("https_proxy", "http://127.0.0.1:9").env("HTTPS_PROXY", "http://127.0.0.1:9").env("CURL_HOME", w.root());
        c
    });
    assert!(out.status.success(), "{}", all(&out));
    let curl = w.lines("curl");
    assert_eq!(curl.len(), 2, "{curl:?}");
    let m = w.root().join("m");
    for (line, file) in curl.iter().zip(["manifest.json", "manifest.json.sig"]) {
        assert!(line.starts_with("-q --proto =https --tlsv1.2 -fsSL --max-time 60 --max-filesize 1048576 -o "), "{line}");
        assert!(line.ends_with(&format!(" https://downloads.claude.ai/claude-code-releases/{V}/{file}")), "{line}");
        assert!(!line.contains(&m.display().to_string()), "fetched into a temp dir first, never straight into --out: {line}");
    }
    // Only PATH and LC_ALL: no HOME (its .curlrc), no proxy, no CURL_HOME, no knob, nothing of the parent's.
    assert_eq!(w.lines("curl-env"), ["LC_ALL PATH", "LC_ALL PATH"]);
}

/// A full admission: the signed manifest (its files kept 0600 as evidence), the binary (0755, its size and sha256
/// the manifest's), the markers, the Docker tests through make (argv pinned, no credential, knob or runner marker
/// in its environment), the local image's id; one `claude_admit` row; exit 0. Again without --redo: printed, exit 0,
/// nothing run.
#[test]
fn admit_records_signed_downloaded_admitted() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    w.bundle(V);
    let out = w.run({
        let mut c = w.cmd(&["claude", "admit"]);
        // A2: make's own flags and the image's binding never reach it (`admit::MAKE_ENV_DROPPED`).
        c.env("ANTHROPIC_API_KEY", "x").env("SOME_TOKEN", "y").env("AI_ENV_BRIDGE_AS", "ops:9002").env("KEEP_ME", "1").env("MAKEFLAGS", "-n").env("LOCAL_IMAGE", "x");
        c
    });
    assert!(out.status.success(), "{}", all(&out));
    assert!(text(&out.stdout).contains(&format!("claude {V}: admitted: signed by the release key ({RELEASE_KEY_FPR})")), "{}", all(&out));
    let r = w.record(V).expect("a record");
    assert_eq!(r.phase(), Phase::Admitted);
    let sig = r.signature.clone().unwrap();
    assert_eq!((sig.outcome.as_str(), sig.signer.as_deref(), sig.linux_sha256.clone(), sig.linux_size), ("ok", Some(RELEASE_KEY_FPR), Some(sha(&bytes)), Some(bytes.len() as u64)));
    assert_eq!(sig.darwin_sha256, Some("ef".repeat(32)));
    let dl = r.download.clone().unwrap();
    assert_eq!((dl.sha256, dl.size), (sha(&bytes), bytes.len() as u64));
    let adm = r.admission.clone().unwrap();
    assert_eq!((adm.outcome.as_str(), adm.markers.as_deref(), adm.docker.as_deref(), adm.docker_image.as_deref(), adm.auto), ("admitted", Some("ok"), Some("test result: ok. 3 passed"), Some("sha256:0123456789abcdef"), false));
    assert_eq!(adm.ai_env, env!("CARGO_PKG_VERSION"));
    let p = w.paths();
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(std::fs::read(p.claude_bin(V)).unwrap(), bytes);
    assert_eq!(mode(&p.claude_bin(V)), 0o755, "the container's uid 1000 runs it through the bind mount");
    assert_eq!((mode(&p.claude_bin_dir(V).join("manifest.json")), mode(&p.claude_bin_dir(V).join("manifest.json.sig"))), (0o600, 0o600));
    assert_eq!(std::fs::read_to_string(p.claude_bin_dir(V).join("manifest.json")).unwrap(), manifest(V, &bytes));
    // The download: --max-filesize the signed size, 900 s.
    let curl = w.lines("curl");
    assert_eq!(curl.len(), 3, "{curl:?}");
    assert!(curl[2].starts_with(&format!("-q --proto =https --tlsv1.2 -fsSL --max-time 900 --max-filesize {} -o ", bytes.len())) && curl[2].ends_with(&format!("/{V}/linux-arm64/claude")), "{curl:?}");
    // make: the checkout, the target, the binary, its version and sha256.
    let repo = std::fs::canonicalize(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).unwrap();
    let make = w.lines("make");
    assert_eq!(make.len(), 1, "{make:?}");
    let argv: Vec<&str> = make[0].split(' ').collect();
    assert_eq!(argv[0], "-C");
    assert_eq!(std::fs::canonicalize(argv[1]).unwrap(), repo);
    assert_eq!(argv[2..], ["claude-admit-docker".to_string(), format!("CLAUDE_BIN={}", p.claude_bin(V).display()), format!("CLAUDE_VERSION={V}"), format!("CLAUDE_SHA256={}", sha(&bytes))]);
    let env = w.lines("make-env");
    let names: Vec<&str> = env[0].split(' ').collect();
    assert!(names.contains(&"KEEP_ME") && names.contains(&"PATH") && names.contains(&"FAKE_DOCKER_VERSION"), "the process's environment: {names:?}");
    for gone in ["ANTHROPIC_API_KEY", "SOME_TOKEN", "AI_ENV_BRIDGE_AS", "AI_ENV_BRIDGE_LAB_FAKE_API", "AI_ENV_BRIDGE_LAB_ADMIT_MAKE", "AI_ENV_BRIDGE_LAB_GPGV", "MAKEFLAGS", "LOCAL_IMAGE"] {
        assert!(!names.contains(&gone), "{gone} reached make: {names:?}");
    }
    let log = p.logs().join(format!("claude-admit-{V}.log"));
    assert_eq!(mode(&log), 0o600);
    assert!(std::fs::read_to_string(&log).unwrap().ends_with("test result: ok. 3 passed\n"));
    let rows = w.audit("claude_admit");
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0]["detail"];
    assert_eq!((d["version"].as_str(), d["outcome"].as_str(), d["auto"].as_str(), d["markers"].as_str()), (Some(V), Some("admitted"), Some("false"), Some("ok")));
    assert_eq!((d["sha256"].as_str(), d["signer"].as_str(), d["docker_image"].as_str()), (Some(sha(&bytes).as_str()), Some(RELEASE_KEY_FPR), Some("sha256:0123456789abcdef")));
    assert!(d["ms"].as_str().is_some_and(|ms| ms.parse::<u64>().is_ok()), "{d}");
    // Admitted already: printed, exit 0, nothing fetched or run again.
    let out = w.ai(&["claude", "admit", V, "--json"]);
    assert!(out.status.success(), "{}", all(&out));
    assert!(text(&out.stdout).starts_with("{\n  \"outcome\""), "outcome first: {}", all(&out));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((doc["outcome"].as_str(), doc["phase"].as_str(), doc["sha256"].as_str()), (Some("admitted"), Some("admitted"), Some(sha(&bytes).as_str())));
    assert_eq!((w.lines("curl").len(), w.lines("make").len(), w.audit("claude_admit").len()), (3, 1, 1));
}

/// A refused signature is recorded and refused (exit 9) until --redo; a missing signature (a fetch that may pass
/// again) records nothing (exit 1). Neither downloads the binary nor runs make. A good signature by a key the vendored
/// keyring lacks is gpgv's NO_PUBKEY (`no_pubkey`), as the real gpgv reports it.
#[test]
fn admit_fails_closed_on_a_bad_or_missing_signature() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, false, None);
    let out = w.ai(&["claude", "admit", V]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    assert!(text(&out.stderr).contains("manifest.json.sig: curl exit 22") && text(&out.stderr).contains("nothing recorded"), "{}", all(&out));
    assert_eq!(w.record(V), None, "a failed fetch records nothing");
    assert_eq!(w.audit("claude_admit")[0]["detail"]["outcome"], "error");
    for (verify, primary, word) in [("bad", RELEASE_KEY_FPR, "bad"), ("good", "0123456789ABCDEF0123456789ABCDEF01234567", "no_pubkey"), ("revoked", RELEASE_KEY_FPR, "revoked"), ("no_pubkey", RELEASE_KEY_FPR, "no_pubkey")] {
        let w = W::new();
        w.serve(V, &bytes, true, None);
        w.gpgv_knobs(&[("FAKE_GPGV_VERIFY", verify), ("FAKE_GPGV_PRIMARY", primary)]);
        let out = w.ai(&["claude", "admit", V]);
        assert_eq!(out.status.code(), Some(9), "{verify}: {}", all(&out));
        assert!(text(&out.stderr).contains(&format!("claude {V}: the release manifest's signature is not the release key's ({word}): not admitted")), "{verify}: {}", all(&out));
        let r = w.record(V).unwrap();
        assert_eq!((r.phase().word(), r.signature.unwrap().why), ("failed(signature)".to_string(), Some(word.to_string())), "{verify}");
        assert_eq!(w.lines("curl").len(), 2, "{verify}: no download");
        assert!(w.lines("make").is_empty(), "{verify}: no Docker tests");
        // Recorded: shown, exit 1, until --redo.
        w.gpgv_knobs(&[("FAKE_GPGV_VERIFY", "good")]);
        let again = w.ai(&["claude", "admit", V]);
        assert_eq!(again.status.code(), Some(1), "{}", all(&again));
        assert!(text(&again.stderr).contains("admission failed at signature") && text(&again.stderr).contains("--redo"), "{}", all(&again));
        assert_eq!(w.lines("curl").len(), 2, "{verify}: nothing fetched without --redo");
        let redo = w.ai(&["claude", "admit", V, "--redo"]);
        assert!(redo.status.success(), "{verify}: {}", all(&redo));
        assert_eq!(w.record(V).unwrap().phase(), Phase::Admitted);
    }
}

/// Bytes that are not the signed manifest's (another sha256, here a flipped byte) are refused (exit 9,
/// `failed(download)`), removed, and never reach make.
#[test]
fn admit_refuses_bytes_that_are_not_the_manifests() {
    let w = W::new();
    let bytes = claude_bytes(V);
    let mut other = bytes.clone();
    other[10] ^= 1;
    w.serve(V, &bytes, true, Some(&other));
    let out = w.ai(&["claude", "admit", V]);
    assert_eq!(out.status.code(), Some(9), "{}", all(&out));
    assert!(text(&out.stderr).contains("not the signed manifest's") && text(&out.stderr).contains("not admitted"), "{}", all(&out));
    let r = w.record(V).unwrap();
    assert_eq!((r.phase().word(), r.signature.unwrap().outcome), ("failed(download)".to_string(), "ok".to_string()));
    let p = w.paths();
    assert!(!p.claude_bin(V).exists() && !p.claude_bin_dir(V).join(".partial").exists(), "nothing kept");
    assert!(w.lines("make").is_empty());
    assert_eq!(w.audit("claude_admit")[0]["detail"]["step"], "download");
}

/// A Linux binary longer than the signed size: curl, told `--max-filesize`, refuses it on the Content-Length before
/// the transfer (exit 63, nothing written, as the real curl): `error(download)`, exit 1, nothing recorded past the
/// signature and nothing kept; once the signed bytes are served, a retry admits it without --redo.
#[test]
fn admit_stops_an_oversized_download_without_a_refusal() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, Some(&[&bytes[..], &b"#"[..]].concat()));
    let out = w.ai(&["claude", "admit", V]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    let err = text(&out.stderr);
    assert!(err.contains("the download failed") && err.contains("curl exit 63") && err.contains("a retry needs no --redo"), "{}", all(&out));
    let r = w.record(V).unwrap();
    assert_eq!((r.phase(), r.signature.as_ref().map(|s| s.outcome.as_str())), (Phase::Signed, Some("ok")));
    assert!(r.download.is_none() && r.admission.is_none(), "nothing recorded past the signature: {r:?}");
    let p = w.paths();
    assert!(!p.claude_bin(V).exists() && !p.claude_bin_dir(V).join(".partial").exists(), "nothing kept");
    assert!(w.lines("make").is_empty(), "no Docker tests");
    let rows = w.audit("claude_admit");
    assert_eq!((rows[0]["detail"]["outcome"].as_str(), rows[0]["detail"]["step"].as_str()), (Some("error"), Some("download")), "{rows:?}");
    w.serve(V, &bytes, true, None);
    let again = w.ai(&["claude", "admit", V]);
    assert!(again.status.success(), "{}", all(&again));
    assert_eq!(w.record(V).unwrap().phase(), Phase::Admitted);
}

/// A Linux binary without a marker the code relies on stops before Docker: exit 9, `failed(markers)`, the marker
/// named by its code word.
#[test]
fn admit_fails_on_a_missing_marker_before_docker() {
    let w = W::new();
    let bytes: Vec<u8> = text(&claude_bytes(V)).replace("--session-id", "--session-xd").into_bytes();
    w.serve(V, &bytes, true, None);
    let out = w.ai(&["claude", "admit", V]);
    assert_eq!(out.status.code(), Some(9), "{}", all(&out));
    assert!(text(&out.stderr).contains("lacks the marker session_id"), "{}", all(&out));
    let r = w.record(V).unwrap();
    assert_eq!((r.phase().word(), r.admission.unwrap().markers), ("failed(markers)".to_string(), Some("missing:session_id".to_string())));
    assert!(w.lines("make").is_empty(), "no Docker tests");
    assert_eq!(w.audit("claude_admit")[0]["detail"]["markers"], "missing:session_id");
}

/// The Docker tests failing: exit 1, `failed(docker)`, the run's last line recorded; its log kept 0600. In
/// passthrough (this world's mode) no wrapper runs it again: the error and `status` name the attempt and promise no
/// automatic retry (doctor's T6).
#[test]
fn admit_records_a_docker_failure() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    w.make_knobs(&[("FAKE_MAKE_EXIT", "2"), ("FAKE_MAKE_OUT", "test l2_claude_version_matches_the_lock ... FAILED")]);
    let out = w.ai(&["claude", "admit", V]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    assert!(text(&out.stderr).contains("its Docker tests failed: test l2_claude_version_matches_the_lock ... FAILED"), "{}", all(&out));
    assert!(text(&out.stderr).contains(&format!("not admitted (test l2_claude_version_matches_the_lock failed; attempt 1 of 3); fix it, then ai-env claude admit {V} --redo")), "{}", all(&out));
    let status = text(&w.ai(&["claude", "status"]).stdout);
    assert!(status.contains(&format!("claude {V}: failed(docker) (test l2_claude_version_matches_the_lock failed; attempt 1 of 3)")), "{status}");
    let r = w.record(V).unwrap();
    let adm = r.admission.clone().unwrap();
    assert_eq!((r.phase().word(), adm.docker.as_deref()), ("failed(docker)".to_string(), Some("test l2_claude_version_matches_the_lock ... FAILED")));
    assert!(!r.nameable());
    let d = &w.audit("claude_admit")[0]["detail"];
    assert_eq!((d["outcome"].as_str(), d["step"].as_str()), (Some("failed"), Some("docker")));
    assert_eq!(std::fs::metadata(w.paths().logs().join(format!("claude-admit-{V}.log"))).unwrap().permissions().mode() & 0o777, 0o600);
}

/// The fake make's output when a Docker test fails, as cargo and libtest print it (24 Oct, B4 (a): the record kept
/// make's last line alone, which names no test).
const CARGO_FAILURE: &str = "test l2_claude_auth_status_json_is_logged_out_with_no_network ... ok
test l2_x ... FAILED

failures:

---- l2_x stdout ----

thread 'l2_x' panicked at tests/docker_exec.rs:123:5:
assertion `left == right` failed: the pinned claude did not answer
  left: None
 right: Some(\"2.1.308\")
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    l2_x

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 120.04s

error: test failed, to rerun pass `-p ai-env-cli --test docker_exec`
make: *** [claude-admit-docker] Error 101";

/// V's last Docker failure moved back past its cooldown, as if 16 minutes had gone by.
fn backdate(w: &W) {
    let then = ai_env_cli::wire::time::rfc3339_utc(ai_env_cli::wire::time::unix_now() - 16 * 60);
    Record::update(&w.paths(), V, |r| r.admission.as_mut().expect("an admission").at = then).unwrap();
}

/// Mike's rule (24 Oct): a Docker failure is counted (by hand or `--auto`) with the failing test and its panic kept
/// in the record (`--json`, `status`), audited with its attempt and test; `--auto` runs it again, every step checked
/// again (the signed manifest fetched and verified anew), only once its cooldown is over and until 3 failures are
/// recorded; then it stands until `--redo`, which runs whatever the count, and an admission clears the count.
#[test]
fn admit_auto_retries_a_docker_failure_until_its_tries_are_spent() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    let toml = w.root().join("bridge/bridge.toml");
    let mut cfg = std::fs::read_to_string(&toml).unwrap();
    cfg.push_str("\n[wrapper]\nmode = \"remote\"\n");
    std::fs::write(&toml, cfg).unwrap();
    w.make_knobs(&[("FAKE_MAKE_EXIT", "2"), ("FAKE_MAKE_OUT", CARGO_FAILURE)]);
    let p = w.paths();
    let out = w.ai(&["claude", "admit", V]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    let r = w.record(V).unwrap();
    let adm = r.admission.clone().unwrap();
    assert_eq!((r.phase().word(), adm.docker_failures, adm.docker_test.as_deref(), adm.docker.as_deref()), ("failed(docker)".to_string(), 1, Some("l2_x"), Some("make: *** [claude-admit-docker] Error 101")));
    assert_eq!(adm.docker_excerpt, ["test l2_x ... FAILED", "thread 'l2_x' panicked at tests/docker_exec.rs:123:5:", "assertion `left == right` failed: the pinned claude did not answer"]);
    let from = ai_env_cli::wire::time::rfc3339_utc(ai_env_cli::wire::time::parse_rfc3339_utc(&adm.at).unwrap() + 15 * 60);
    let err = text(&out.stderr);
    assert!(err.contains(&format!("claude {V}: its Docker tests failed: make: *** [claude-admit-docker] Error 101 (the log: ")), "{err}");
    assert!(err.contains(&format!("not admitted (test l2_x failed; attempt 1 of 3); an automatic retry from {from} (the next remote wrapper starts it), or fix it, then ai-env claude admit {V} --redo")), "{err}");
    let d = &w.audit("claude_admit")[0]["detail"];
    assert_eq!((d["outcome"].as_str(), d["step"].as_str(), d["attempt"].as_str(), d["test"].as_str(), d["auto"].as_str()), (Some("failed"), Some("docker"), Some("1"), Some("l2_x"), Some("false")));
    let doc: Value = serde_json::from_slice(&w.ai(&["claude", "admit", V, "--json"]).stdout).unwrap();
    assert_eq!((doc["outcome"].as_str(), doc["docker_failures"].as_u64(), doc["docker_test"].as_str()), (Some("failed"), Some(1), Some("l2_x")));
    assert_eq!(doc["docker_excerpt"], serde_json::json!(adm.docker_excerpt));
    let status = text(&w.ai(&["claude", "status"]).stdout);
    assert!(status.contains(&format!("claude {V}: failed(docker) (test l2_x failed; attempt 1 of 3; an automatic retry from {from} (the next remote wrapper starts it))")), "{status}");
    // --auto within the failure's cooldown: nothing fetched or run; its lock says the record stands.
    let out = w.ai(&["claude", "admit", V, "--auto"]);
    assert_eq!(out.status.code(), Some(0), "{}", all(&out));
    assert_eq!((w.lines("curl").len(), w.lines("make").len()), (3, 1), "within the cooldown");
    assert!(std::fs::read_to_string(p.claude_lock(V)).unwrap().ends_with("\noutcome=failed(docker)\n"));
    // Past it: run again, the manifest and its signature fetched and verified anew, the kept binary (the signed
    // bytes) not fetched again; counted, audited with `auto`, until 3 are recorded.
    for attempt in [2u32, 3] {
        backdate(&w);
        let curl = w.lines("curl").len();
        let out = w.ai(&["claude", "admit", V, "--auto"]);
        assert_eq!(out.status.code(), Some(0), "{}", all(&out));
        assert_eq!((w.lines("make").len(), w.lines("curl").len()), (attempt as usize, curl + 2), "attempt {attempt}");
        let r = w.record(V).unwrap();
        let adm = r.admission.clone().unwrap();
        assert_eq!((r.phase().word(), adm.docker_failures, adm.auto, adm.docker_test.as_deref()), ("failed(docker)".to_string(), attempt, true, Some("l2_x")));
        assert_eq!(adm.docker_excerpt, ["test l2_x ... FAILED", "thread 'l2_x' panicked at tests/docker_exec.rs:123:5:", "assertion `left == right` failed: the pinned claude did not answer"], "attempt {attempt}");
        let rows = w.audit("claude_admit");
        let d = &rows.last().unwrap()["detail"];
        assert_eq!((d["attempt"].as_str(), d["test"].as_str(), d["auto"].as_str()), (Some(attempt.to_string().as_str()), Some("l2_x"), Some("true")), "{rows:?}");
        assert!(std::fs::read_to_string(p.claude_lock(V)).unwrap().ends_with("\noutcome=failed(docker)\n"));
    }
    // Spent: --auto runs nothing, whatever the time; status names the --redo.
    backdate(&w);
    let out = w.ai(&["claude", "admit", V, "--auto"]);
    assert_eq!(out.status.code(), Some(0), "{}", all(&out));
    assert_eq!((w.lines("make").len(), w.record(V).unwrap().docker_failures()), (3, 3), "no fourth automatic run");
    let status = text(&w.ai(&["claude", "status"]).stdout);
    assert!(status.contains(&format!("claude {V}: failed(docker) (test l2_x failed; attempt 3 of 3, no automatic retry left: fix it, then ai-env claude admit {V} --redo)")), "{status}");
    // --redo runs whatever the count: a fourth failure, then an admission, which clears the count and the excerpt.
    let out = w.ai(&["claude", "admit", V, "--redo"]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    assert!(text(&out.stderr).contains(&format!("not admitted (test l2_x failed; attempt 4, no automatic retry left); fix it, then ai-env claude admit {V} --redo")), "{}", all(&out));
    assert_eq!((w.lines("make").len(), w.record(V).unwrap().docker_failures()), (4, 4));
    w.make_knobs(&[]);
    let out = w.ai(&["claude", "admit", V, "--redo"]);
    assert!(out.status.success(), "{}", all(&out));
    let r = w.record(V).unwrap();
    let adm = r.admission.clone().unwrap();
    assert_eq!((r.phase(), adm.docker_failures, adm.docker_test, adm.docker_excerpt.len()), (Phase::Admitted, 0, None, 0));
    let file = std::fs::read_to_string(p.claude_record(V)).unwrap();
    assert!(!file.contains("docker_failures") && !file.contains("docker_excerpt"), "an older ai-env reads it: {file}");
    let rows = w.audit("claude_admit");
    let d = &rows.last().unwrap()["detail"];
    assert_eq!((d["outcome"].as_str(), d.get("attempt"), d.get("test")), (Some("admitted"), None, None));
}

/// The automatic retry keeps custody (Mike's rule, 24 Oct): a kept binary that is not the signed manifest's is
/// downloaded again and checked, so the Docker tests run only on bytes this run verified; bytes the release serves
/// that are not the manifest's are `failed(download)`, which, like a refused signature or a missing marker, the
/// automatic path never runs again; a fetch that may pass again records nothing and counts nothing.
#[test]
fn admit_auto_retry_tests_only_bytes_it_verified() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    w.make_knobs(&[("FAKE_MAKE_EXIT", "2"), ("FAKE_MAKE_OUT", CARGO_FAILURE)]);
    let p = w.paths();
    assert_eq!(w.ai(&["claude", "admit", V]).status.code(), Some(1));
    // The kept binary changed since (a flipped byte): the retry downloads the signed bytes again before make.
    let mut changed = bytes.clone();
    changed[10] ^= 1;
    std::fs::write(p.claude_bin(V), &changed).unwrap();
    backdate(&w);
    w.make_knobs(&[]);
    let out = w.ai(&["claude", "admit", V, "--auto"]);
    assert_eq!(out.status.code(), Some(0), "{}", all(&out));
    let curl = w.lines("curl");
    assert_eq!(curl.len(), 6, "the manifest, its signature and the binary, again: {curl:?}");
    assert!(curl[5].ends_with(&format!("/{V}/linux-arm64/claude")), "{curl:?}");
    assert_eq!(std::fs::read(p.claude_bin(V)).unwrap(), bytes, "the signed bytes");
    let make = w.lines("make");
    assert_eq!(make.len(), 2);
    assert!(make[1].ends_with(&format!("CLAUDE_SHA256={}", sha(&bytes))), "{make:?}");
    let r = w.record(V).unwrap();
    assert_eq!((r.phase(), r.download.clone().unwrap().sha256, r.docker_failures()), (Phase::Admitted, sha(&bytes), 0));
    // Another world: after a Docker failure the release serves bytes that are not the manifest's, and the kept
    // binary is gone: the retry refuses them (failed(download)), runs no Docker test, and is never retried.
    let w = W::new();
    w.serve(V, &bytes, true, None);
    w.make_knobs(&[("FAKE_MAKE_EXIT", "2"), ("FAKE_MAKE_OUT", CARGO_FAILURE)]);
    let p = w.paths();
    assert_eq!(w.ai(&["claude", "admit", V]).status.code(), Some(1));
    w.serve(V, &bytes, true, Some(&changed));
    std::fs::remove_file(p.claude_bin(V)).unwrap();
    backdate(&w);
    assert_eq!(w.ai(&["claude", "admit", V, "--auto"]).status.code(), Some(0));
    let r = w.record(V).unwrap();
    assert_eq!((r.phase().word(), r.docker_failures(), r.auto_retry()), ("failed(download)".to_string(), 1, false));
    assert!(!p.claude_bin(V).exists() && w.lines("make").len() == 1, "nothing kept, no Docker test");
    assert!(std::fs::read_to_string(p.claude_lock(V)).unwrap().ends_with("\noutcome=failed(download)\n"));
    let curl = w.lines("curl").len();
    backdate(&w);
    assert_eq!(w.ai(&["claude", "admit", V, "--auto"]).status.code(), Some(0));
    assert_eq!((w.lines("curl").len(), w.lines("make").len()), (curl, 1), "final for the automatic path");
    // A retry whose signature cannot be fetched records nothing (it may pass again): failed(docker) as it was, its
    // failure not counted again, still due. One whose signature gpgv refuses is failed(signature), which no retry
    // runs again, though the Docker failure's row stands under it.
    let w = W::new();
    w.serve(V, &bytes, true, None);
    w.make_knobs(&[("FAKE_MAKE_EXIT", "2"), ("FAKE_MAKE_OUT", CARGO_FAILURE)]);
    assert_eq!(w.ai(&["claude", "admit", V]).status.code(), Some(1));
    w.serve(V, &bytes, false, None);
    backdate(&w);
    assert_eq!(w.ai(&["claude", "admit", V, "--auto"]).status.code(), Some(0));
    let r = w.record(V).unwrap();
    assert_eq!((r.phase().word(), r.docker_failures(), r.auto_retry(), w.lines("make").len()), ("failed(docker)".to_string(), 1, true, 1), "a fetch that may pass again");
    w.serve(V, &bytes, true, None);
    w.gpgv_knobs(&[("FAKE_GPGV_VERIFY", "bad")]);
    assert_eq!(w.ai(&["claude", "admit", V, "--auto"]).status.code(), Some(0));
    let r = w.record(V).unwrap();
    assert_eq!((r.phase().word(), r.auto_retry(), r.admission.as_ref().map(|a| (a.step.clone(), a.docker_failures))), ("failed(signature)".to_string(), false, Some((Some("docker".to_string()), 1))));
    assert!(std::fs::read_to_string(w.paths().claude_lock(V)).unwrap().ends_with("\noutcome=failed(signature)\n"));
    let curl = w.lines("curl").len();
    w.gpgv_knobs(&[("FAKE_GPGV_VERIFY", "good")]);
    backdate(&w);
    assert_eq!(w.ai(&["claude", "admit", V, "--auto"]).status.code(), Some(0));
    assert_eq!((w.lines("curl").len(), w.lines("make").len()), (curl, 1), "a refused signature is final for the automatic path");
    // A missing marker is final for it too.
    let w = W::new();
    let unmarked: Vec<u8> = text(&claude_bytes(V)).replace("--session-id", "--session-xd").into_bytes();
    w.serve(V, &unmarked, true, None);
    assert_eq!(w.ai(&["claude", "admit", V]).status.code(), Some(9));
    backdate(&w);
    assert_eq!(w.ai(&["claude", "admit", V, "--auto"]).status.code(), Some(0));
    assert_eq!((w.lines("curl").len(), w.lines("make").len()), (3, 0), "nothing fetched again, no Docker test");
    assert!(std::fs::read_to_string(w.paths().claude_lock(V)).unwrap().ends_with("\noutcome=failed(markers)\n"));
}

/// `--auto` (D5's child): without Docker it records nothing, writes `finished_at=` and `outcome=skipped(no_docker)`
/// into its lock, audits `claude_admit` `skipped` (`auto` true), prints nothing and exits 0; a failure is exit 0 too.
#[test]
fn admit_auto_skips_without_docker_and_writes_its_lock() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    let out = w.run({
        let mut c = w.cmd(&["claude", "admit", V, "--auto"]);
        c.env_remove("FAKE_DOCKER_VERSION");
        c
    });
    assert_eq!(out.status.code(), Some(0), "{}", all(&out));
    assert_eq!((text(&out.stdout).as_str(), text(&out.stderr).as_str()), ("", ""), "quiet");
    assert_eq!(w.record(V), None, "no record");
    let lock = std::fs::read_to_string(w.paths().claude_lock(V)).unwrap();
    let mut lines = lock.lines();
    assert!(lines.next().unwrap().strip_prefix("finished_at=").is_some_and(|t| t.parse::<u64>().is_ok()), "{lock}");
    assert_eq!(lines.next(), Some("outcome=skipped(no_docker)"), "{lock}");
    let d = &w.audit("claude_admit")[0]["detail"];
    assert_eq!((d["outcome"].as_str(), d["why"].as_str(), d["auto"].as_str()), (Some("skipped"), Some("no_docker"), Some("true")));
    assert_eq!(d["actor"], "cli", "an ai-env process: its rows say cli, `auto` tells their origin (index X-5)");
    assert!(w.lines("curl").is_empty(), "nothing fetched");
    // No local image: skipped(no_image). A refused signature: failed(signature) in the lock, exit 0 all the same.
    let out = w.run({
        let mut c = w.cmd(&["claude", "admit", V, "--auto"]);
        c.env_remove("FAKE_DOCKER_IMAGE_ID");
        c
    });
    assert_eq!(out.status.code(), Some(0));
    assert!(std::fs::read_to_string(w.paths().claude_lock(V)).unwrap().ends_with("outcome=skipped(no_image)\n"));
    w.gpgv_knobs(&[("FAKE_GPGV_VERIFY", "bad")]);
    let out = w.ai(&["claude", "admit", V, "--auto"]);
    assert_eq!(out.status.code(), Some(0), "{}", all(&out));
    assert!(std::fs::read_to_string(w.paths().claude_lock(V)).unwrap().ends_with("outcome=failed(signature)\n"));
    assert_eq!(w.record(V).unwrap().admission, None);
    assert_eq!(w.record(V).unwrap().phase().word(), "failed(signature)");
    // An exit with no outcome of its own (here the evidence's directory cannot be made: a file stands there) still
    // ends the lock (D5's cooldown): finished_at, error(<step>), exit 0, nothing recorded past the signature.
    let w = W::new();
    w.serve(V, &bytes, true, None);
    let p = w.paths();
    std::fs::create_dir_all(p.claude_dir()).unwrap();
    std::fs::write(p.claude_bin_dir(V), b"not a directory").unwrap();
    let out = w.ai(&["claude", "admit", V, "--auto"]);
    assert_eq!(out.status.code(), Some(0), "{}", all(&out));
    let lock = std::fs::read_to_string(p.claude_lock(V)).unwrap();
    assert!(lock.starts_with("finished_at=") && lock.ends_with("\noutcome=error(signature)\n"), "{lock}");
    assert_eq!(w.record(V).unwrap().phase(), Phase::Signed);
}

/// `--auto` adopts the lock D5's trigger hands it on fd 3 (the same open file, the trigger's flock on it): the
/// admission runs while the test's copy still holds the lock (a lock of its own would be refused), and once that
/// copy is closed the child alone keeps it until its end, writing its outcome through that file.
#[test]
fn admit_auto_adopts_the_lock_on_fd_3_and_holds_it_to_its_end() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    let pid_file = w.root().join("make.pid");
    let pid = pid_file.display().to_string();
    w.make_knobs(&[("FAKE_MAKE_SLEEP", "3"), ("FAKE_MAKE_PID_FILE", pid.as_str())]);
    let p = w.paths();
    let lock = VersionLock::take(&p, V).unwrap().expect("free");
    let fd = lock.as_raw_fd();
    let mut c = w.cmd(&["claude", "admit", V, "--auto"]);
    c.stdout(Stdio::null()).stderr(Stdio::null());
    // SAFETY: fcntl(2) or dup2(2) only, between fork and exec: the lock's open file on the child's fd 3, inheritable.
    unsafe {
        c.pre_exec(move || {
            let rc = if fd == 3 { libc::fcntl(3, libc::F_SETFD, 0) } else { libc::dup2(fd, 3) };
            if rc < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = c.spawn().unwrap();
    let until = std::time::Instant::now() + LIMIT;
    while !pid_file.exists() {
        assert!(child.try_wait().unwrap().is_none(), "the admission ended before make ran (no adoption?): {:?}", std::fs::read_to_string(p.wrapper_log()));
        assert!(std::time::Instant::now() < until, "make never ran");
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(lock);
    assert!(VersionLock::take(&p, V).unwrap().is_none(), "the child's fd 3 keeps the lock once the test's copy is closed");
    let out = common::bounded::finish_within(child, LIMIT, "ai-env claude admit --auto");
    assert_eq!(out.status.code(), Some(0));
    let text = std::fs::read_to_string(p.claude_lock(V)).unwrap();
    assert!(text.starts_with("finished_at=") && text.ends_with("\noutcome=admitted\n"), "{text}");
    assert_eq!(w.record(V).unwrap().phase(), Phase::Admitted);
    assert!(VersionLock::take(&p, V).unwrap().is_some(), "released with the child");
}

/// A stop signal while the Docker tests run ends make's whole process group (its sleeping child too), records
/// nothing past the signature (`claude_admit` `error`, step docker) and exits 143 naming it (130 for SIGINT).
#[test]
fn admit_ends_the_docker_tests_on_a_stop_signal() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    let pid_file = w.root().join("make.pid");
    let pid = pid_file.display().to_string();
    w.make_knobs(&[("FAKE_MAKE_SLEEP", "60"), ("FAKE_MAKE_PID_FILE", pid.as_str())]);
    let mut c = w.cmd(&["claude", "admit", V]);
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    let until = std::time::Instant::now() + LIMIT;
    while !pid_file.exists() {
        assert!(child.try_wait().unwrap().is_none(), "the admission ended before make ran");
        assert!(std::time::Instant::now() < until, "make never ran");
        std::thread::sleep(Duration::from_millis(50));
    }
    let sleeper: u32 = std::fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
    // SAFETY: kill(2) of the ai-env this test spawned (still running: try_wait above).
    assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) }, 0);
    let out = common::bounded::finish_within(child, LIMIT, "ai-env claude admit");
    assert_eq!(out.status.code(), Some(143), "{}", all(&out));
    assert!(text(&out.stderr).contains(&format!("ai-env: terminated (SIGTERM): claude {V}'s Docker tests ended, nothing recorded")), "{}", all(&out));
    let gone = std::time::Instant::now() + Duration::from_secs(10);
    while common::pid_alive(sleeper) && std::time::Instant::now() < gone {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!common::pid_alive(sleeper), "make's group ended, its child too");
    assert_eq!(w.record(V).unwrap().phase(), Phase::Signed, "nothing recorded past the signature");
    let d = &w.audit("claude_admit")[0]["detail"];
    assert_eq!((d["outcome"].as_str(), d["step"].as_str(), d["why"].as_str()), (Some("error"), Some("docker"), Some("terminated")));
    assert!(VersionLock::take(&w.paths(), V).unwrap().is_some(), "the lock went with ai-env");
}

/// Another process holding V's lock: exit 1 naming it, nothing fetched or recorded.
#[test]
fn admit_refuses_while_another_holds_the_lock() {
    use std::os::fd::AsRawFd;
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    let p = w.paths();
    std::fs::create_dir_all(p.claude_dir()).unwrap();
    let held = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(p.claude_lock(V)).unwrap();
    // SAFETY: flock(2) on a descriptor this test owns.
    assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    let out = w.ai(&["claude", "admit", V]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    assert!(text(&out.stderr).contains(&format!("another admission or staging of claude {V} is running: wait for it (ai-env claude status)")), "{}", all(&out));
    assert_eq!(w.record(V), None);
    assert!(w.lines("curl").is_empty());
    drop(held);
    assert!(w.ai(&["claude", "admit", V]).status.success(), "the lock released");
}

/// `ai-env claude manifest` writes the two files (0644) only once verified; refused, nothing (exit 9); under the
/// fake API without a knob, nothing run (exit 1 naming it).
#[test]
fn manifest_writes_only_a_verified_manifest() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    let out_dir = w.root().join("pin");
    let o = w.ai(&["claude", "manifest", V, "--out", out_dir.to_str().unwrap()]);
    assert!(o.status.success(), "{}", all(&o));
    assert_eq!(std::fs::read_to_string(out_dir.join("manifest.json")).unwrap(), manifest(V, &bytes));
    assert_eq!(std::fs::read_to_string(out_dir.join("manifest.json.sig")).unwrap(), "a detached signature\n");
    assert_eq!(std::fs::metadata(out_dir.join("manifest.json")).unwrap().permissions().mode() & 0o777, 0o644);
    assert_eq!(w.record(V), None, "manifest records nothing");
    let refused = w.root().join("refused");
    w.gpgv_knobs(&[("FAKE_GPGV_VERIFY", "expired")]);
    let o = w.ai(&["claude", "manifest", V, "--out", refused.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(9), "{}", all(&o));
    assert!(text(&o.stderr).contains("(expired)") && text(&o.stderr).contains("nothing written"), "{}", all(&o));
    assert!(!refused.exists(), "nothing written");
    let o = w.run({
        let mut c = w.cmd(&["claude", "manifest", V, "--out", refused.to_str().unwrap()]);
        c.env_remove("AI_ENV_BRIDGE_LAB_GPGV");
        c
    });
    assert_eq!(o.status.code(), Some(1), "{}", all(&o));
    assert!(text(&o.stderr).contains("set AI_ENV_BRIDGE_LAB_GPGV"), "{}", all(&o));
    assert!(!refused.exists());
    // A manifest of another version is refused, however well signed.
    w.gpgv_knobs(&[("FAKE_GPGV_VERIFY", "good")]);
    w.serve("2.1.307", &bytes, true, None);
    let o = w.ai(&["claude", "manifest", V, "--out", refused.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(9), "{}", all(&o));
    assert!(text(&o.stderr).contains("claude 2.1.308: the signed manifest is for version 2.1.307, not 2.1.308: nothing written"), "{}", all(&o));
    assert!(!text(&o.stderr).contains("claude 2.1.308: claude 2.1.308"), "the version named once: {}", all(&o));
}

// ---- stage --------------------------------------------------------------------------------------------------------

/// `ai-env claude stage`: one ListObjectsV2, a fresh internet VM (purpose and label claude-stage, `[vm]`'s quota,
/// no workspace), its `/health` naming the cap, the relay handed a presigned PUT of exactly V's object, the VM
/// terminated by claude-stage, S3's listing; the record `staged` (version id, stager), one `claude_stage` row. Again:
/// already staged, no VM.
#[test]
fn stage_runs_an_internet_vm_relays_and_terminates_it() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.admitted(V, &bytes, None);
    let st = w.stager(Relaying::Put(bytes.clone()), true);
    let out = w.staged(&st, &["claude", "stage", V, "--json"]);
    assert!(out.status.success(), "{}", all(&out));
    assert!(text(&out.stdout).starts_with("{\n  \"outcome\""), "outcome first: {}", all(&out));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", all(&out)));
    let key = format!("v1/_claude/mac/{V}/{}", sha(&bytes));
    assert_eq!((doc["outcome"].as_str(), doc["key"].as_str(), doc["version_id"].as_str()), (Some("staged"), Some(key.as_str()), Some("fv1")), "{doc}");
    assert_eq!(st.s3.get(&key), Some(bytes.clone()), "S3 holds exactly the bytes");
    // The relay's request: V's ref, its signed size, the owner, a PUT URL of exactly its key (checked by the Mac).
    let reqs = st.relay.requests();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    assert_eq!((reqs[0]["version"].as_str(), reqs[0]["sha256"].as_str(), reqs[0]["size"].as_u64(), reqs[0]["owner"].as_str()), (Some(V), Some(sha(&bytes).as_str()), Some(bytes.len() as u64), Some("123456789012")));
    assert!(reqs[0]["put"].as_str().unwrap().contains(&format!("/{key}?")), "{reqs:?}");
    let relay: ClaudeRelay = serde_json::from_value(reqs[0].clone()).unwrap();
    assert_eq!(relay.check(), Ok(()), "the shim's check passes it");
    // The VM: internet egress, no connector, the stager's label; terminated by claude-stage whatever came of it.
    let state = w.state();
    assert_eq!(w.runs(), 1);
    let spec = &state.specs[0];
    assert_eq!(spec.max_duration_s, 900, "the stager's wall (STAGER_MAX_DURATION_S)");
    assert!(spec.egress_connectors.is_empty() || spec.egress_connectors.iter().all(|c| !c.contains("network-connector:ai-env")), "an internet VM: {:?}", spec.egress_connectors);
    let vm = doc["vm"].as_str().unwrap().to_string();
    assert_eq!(w.terminated(), std::slice::from_ref(&vm));
    let row = ai_env_cli::bridge::vm::registry::read_row(&w.paths(), &vm).unwrap().unwrap();
    assert_eq!((row.label.as_deref(), row.workspace.as_deref(), row.terminated_by.as_deref()), (Some(format!("claude-stage:{V}").as_str()), None, Some("claude-stage")));
    let runs = w.audit("vm_run");
    assert_eq!(runs[0]["detail"]["purpose"], "claude-stage");
    let r = w.record(V).unwrap();
    let s = r.staging.clone().unwrap();
    assert_eq!((r.phase(), s.s3_key.as_str(), s.s3_version_id.as_deref(), s.stager_vm.as_deref()), (Phase::Staged, key.as_str(), Some("fv1"), Some(vm.as_str())));
    let rows = w.audit("claude_stage");
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0]["detail"];
    assert_eq!((d["outcome"].as_str(), d["vm"].as_str(), d["s3_status"].as_str(), d["version"].as_str()), (Some("staged"), Some(vm.as_str()), Some("200"), Some(V)));
    // Staged: the listing holds it, no VM.
    let again = w.staged(&st, &["claude", "stage", V]);
    assert!(again.status.success(), "{}", all(&again));
    assert!(text(&again.stdout).contains(&format!("claude {V}: already staged ({key})")), "{}", all(&again));
    assert_eq!(w.runs(), 1, "no second VM");
}

/// S3's 412 (the key holds an object already) counts as staged, unverified: no version id.
#[test]
fn stage_counts_412_as_staged_unverified() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.admitted(V, &bytes, None);
    let st = w.stager(Relaying::Answer(412), true);
    let out = w.staged(&st, &["claude", "stage", V]);
    assert!(out.status.success(), "{}", all(&out));
    assert!(text(&out.stdout).contains("(412): counted as staged, unverified"), "{}", all(&out));
    let r = w.record(V).unwrap();
    assert_eq!((r.phase(), r.staging.unwrap().s3_version_id), (Phase::Staged, None));
    assert_eq!(w.audit("claude_stage")[0]["detail"]["outcome"], "exists");
    // Any other answer of S3: exit 1 naming it, the record unchanged.
    let w = W::new();
    w.admitted(V, &bytes, None);
    let st = w.stager(Relaying::Answer(403), true);
    let out = w.staged(&st, &["claude", "stage", V]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    assert!(text(&out.stderr).contains("S3 answered HTTP 403 AccessDenied to the relay's PUT"), "{}", all(&out));
    assert_eq!(w.record(V).unwrap().phase(), Phase::Admitted);
    assert_eq!(w.terminated().len(), 1, "the stager ended all the same");
}

/// A stale object (a VM refused it) is deleted first (`claude_stage` `deleted`, why `bad`), then staged again; and
/// `--force` deletes a staged one (why `force`). `bad_stages` is kept for the admission's two-strikes rule.
#[test]
fn stage_deletes_and_restages_a_stale_object() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.admitted(V, &bytes, Some("stale"));
    Record::update(&w.paths(), V, |r| r.staging.as_mut().unwrap().bad_stages = 1).unwrap();
    let st = w.stager(Relaying::Put(bytes.clone()), true);
    let key = format!("v1/_claude/mac/{V}/{}", sha(&bytes));
    st.s3.put(&key, &bytes);
    let out = w.staged(&st, &["claude", "stage", V]);
    assert!(out.status.success(), "{}", all(&out));
    let reqs = st.s3.requests();
    let del = reqs.iter().position(|r| r.method == "DELETE" && r.key == key).expect("a DELETE");
    let put = reqs.iter().position(|r| r.method == "PUT" && r.key == key).expect("the relay's PUT");
    assert!(del < put, "deleted first: {reqs:?}");
    let r = w.record(V).unwrap();
    assert_eq!((r.phase(), r.staging.clone().unwrap().bad_stages), (Phase::Staged, 1));
    let rows = w.audit("claude_stage");
    assert_eq!((rows[0]["detail"]["outcome"].as_str(), rows[0]["detail"]["why"].as_str()), (Some("deleted"), Some("bad")));
    assert_eq!(rows[1]["detail"]["outcome"], "staged");
    let out = w.staged(&st, &["claude", "stage", V, "--force"]);
    assert!(out.status.success(), "{}", all(&out));
    let rows = w.audit("claude_stage");
    assert_eq!((rows[2]["detail"]["why"].as_str(), rows[3]["detail"]["outcome"].as_str()), (Some("force"), Some("staged")));
    assert_eq!(w.runs(), 2);
    // --force whose restage fails: the object is deleted, so the record no longer says staged (no VM is offered it).
    let st = w.stager(Relaying::Answer(403), true);
    let out = w.staged(&st, &["claude", "stage", V, "--force"]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    let r = w.record(V).unwrap();
    assert_eq!((r.phase(), r.staging.unwrap().state.as_str()), (Phase::Admitted, "absent"));
}

/// A version not admitted (none, seen, signed or failed) is refused before anything: exit 9 naming the commands
/// that admit it (a failed one: its step and the `--redo`), no API call (no Touch ID), no S3 request.
#[test]
fn stage_refuses_an_unadmitted_version_before_any_touch_id() {
    let w = W::new();
    let bytes = claude_bytes(V);
    let st = w.stager(Relaying::Put(bytes.clone()), true);
    for setup in ["none", "signed", "failed"] {
        match setup {
            "signed" => {
                Record::update(&w.paths(), V, |r| r.signature = Some(SignatureRow { outcome: "ok".into(), linux_sha256: Some(sha(&bytes)), linux_size: Some(9), at: "t".into(), ..SignatureRow::default() })).unwrap();
            }
            "failed" => {
                Record::update(&w.paths(), V, |r| r.admission = Some(AdmissionRow { outcome: "failed".into(), step: Some("docker".into()), at: "t".into(), ..AdmissionRow::default() })).unwrap();
            }
            _ => {}
        }
        let out = w.staged(&st, &["claude", "stage", V]);
        assert_eq!(out.status.code(), Some(9), "{setup}: {}", all(&out));
        let says = if setup == "failed" {
            format!("claude {V}: admission failed at docker: fix it, then ai-env claude admit {V} --redo")
        } else {
            format!("claude {V} is not admitted: ai-env claude admit {V} (or ai-env claude update {V})")
        };
        assert!(text(&out.stderr).contains(&says), "{setup}: {}", all(&out));
    }
    assert!(w.state().calls.is_empty(), "no API call: {:?}", w.state().calls);
    assert!(st.s3.requests().is_empty() && st.relay.requests().is_empty());
}

/// A VM whose image does not serve the relay: exit 7 naming `make deploy`, the VM terminated, the record unchanged.
#[test]
fn stage_refuses_an_image_without_the_cap() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.admitted(V, &bytes, None);
    let st = w.stager(Relaying::Put(bytes.clone()), false);
    let out = w.staged(&st, &["claude", "stage", V]);
    assert_eq!(out.status.code(), Some(7), "{}", all(&out));
    assert!(text(&out.stderr).contains("claude_stage_v1") && text(&out.stderr).contains("make deploy"), "{}", all(&out));
    assert_eq!(w.terminated().len(), 1, "the stager terminated");
    assert!(st.relay.requests().is_empty(), "no relay");
    assert_eq!(w.record(V).unwrap().phase(), Phase::Admitted);
    let d = &w.audit("claude_stage")[0]["detail"];
    assert_eq!((d["outcome"].as_str(), d["step"].as_str()), (Some("failed"), Some("cap")));
}

/// One stager per version: a held lock is exit 1 before the Touch ID, no VM.
#[test]
fn stagers_are_single_flight() {
    use std::os::fd::AsRawFd;
    let w = W::new();
    let bytes = claude_bytes(V);
    w.admitted(V, &bytes, None);
    let st = w.stager(Relaying::Put(bytes.clone()), true);
    let p = w.paths();
    let held = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(p.claude_lock(V)).unwrap();
    // SAFETY: flock(2) on a descriptor this test owns.
    assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    let out = w.staged(&st, &["claude", "stage", V]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    assert!(text(&out.stderr).contains(&format!("another admission or staging of claude {V} is running")), "{}", all(&out));
    assert!(w.state().calls.is_empty(), "nothing asked of the API");
    drop(held);
    assert!(w.staged(&st, &["claude", "stage", V]).status.success());
}

/// `ai-env claude update` (the installed bundle's version by default): admits (no Touch ID), then stages.
#[test]
fn update_admits_then_stages() {
    let w = W::new();
    let bytes = claude_bytes(V);
    w.serve(V, &bytes, true, None);
    w.bundle(V);
    let st = w.stager(Relaying::Put(bytes.clone()), true);
    let out = w.staged(&st, &["claude", "update", "--json"]);
    assert!(out.status.success(), "{}", all(&out));
    assert!(text(&out.stdout).starts_with("{\n  \"outcome\""), "outcome first: {}", all(&out));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", all(&out)));
    assert_eq!((doc["outcome"].as_str(), doc["admitted"].as_str(), doc["version"].as_str()), (Some("staged"), Some("now"), Some(V)), "{doc}");
    assert_eq!(w.record(V).unwrap().phase(), Phase::Staged);
    assert_eq!((w.audit("claude_admit")[0]["detail"]["outcome"].as_str(), w.audit("claude_stage")[0]["detail"]["outcome"].as_str()), (Some("admitted"), Some("staged")));
    // Admitted and staged: nothing admitted again, nothing relayed again.
    let out = w.staged(&st, &["claude", "update", V, "--json"]);
    assert!(out.status.success(), "{}", all(&out));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((doc["outcome"].as_str(), doc["admitted"].as_str()), (Some("already_staged"), Some("already")));
    assert_eq!((w.lines("make").len(), w.runs()), (1, 1));
}

// ---- gc and forget --------------------------------------------------------------------------------------------------

/// gc keeps the 3 newest staged versions, the bundle's and every live window's. Without --yes: from the records
/// only, nothing deleted, no API call. With it: the listing too (an object without a record goes as well), each
/// delete audited `deleted` (why gc), the records `absent`.
#[test]
fn gc_keeps_three_the_bundle_and_the_windows() {
    let w = W::new();
    let st = w.stager(Relaying::Answer(500), true);
    let versions = ["2.1.300", "2.1.301", "2.1.302", "2.1.303", "2.1.304", "2.1.305", "2.1.306"];
    for v in versions {
        let bytes = claude_bytes(v);
        w.admitted(v, &bytes, Some("staged"));
        st.s3.put(&format!("v1/_claude/mac/{v}/{}", sha(&bytes)), &bytes);
    }
    // An object no record names.
    let orphan = format!("v1/_claude/mac/2.1.299/{}", "a".repeat(64));
    st.s3.put(&orphan, b"x");
    w.bundle("2.1.300");
    w.window("2.1.302");
    let dry = w.staged(&st, &["claude", "gc", "--json"]);
    assert!(dry.status.success(), "{}", all(&dry));
    assert!(text(&dry.stdout).starts_with("{\n  \"outcome\""), "outcome first: {}", all(&dry));
    let doc: Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!((doc["outcome"].as_str(), doc["versions"].clone()), (Some("dry_run"), serde_json::json!(["2.1.301", "2.1.303"])), "{doc}");
    assert!(w.state().calls.is_empty() && st.s3.requests().is_empty(), "the records only");
    let out = w.staged(&st, &["claude", "gc", "--yes", "--json"]);
    assert!(out.status.success(), "{}", all(&out));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["versions"], serde_json::json!(["2.1.299", "2.1.301", "2.1.303"]), "{doc}");
    let current: Vec<String> = st.s3.objects().into_iter().filter(|o| o.current && !o.delete_marker).map(|o| o.key).collect();
    for v in ["2.1.300", "2.1.302", "2.1.304", "2.1.305", "2.1.306"] {
        assert!(current.iter().any(|k| k.contains(&format!("/{v}/"))), "{v} kept: {current:?}");
    }
    for v in ["2.1.299", "2.1.301", "2.1.303"] {
        assert!(!current.iter().any(|k| k.contains(&format!("/{v}/"))), "{v} deleted: {current:?}");
    }
    assert_eq!(w.record("2.1.301").unwrap().staging.unwrap().state, "absent");
    assert_eq!(w.record("2.1.304").unwrap().phase(), Phase::Staged);
    let rows = w.audit("claude_stage");
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(rows.iter().all(|r| r["detail"]["outcome"] == "deleted" && r["detail"]["why"] == "gc"), "{rows:?}");
}

/// forget refuses a version a live Cursor window runs (exit 9) unless --force; `--local` removes its binary and its
/// record with no API call; without it its S3 objects go too (audited, why forget); nothing left to forget is exit 1.
#[test]
fn forget_refuses_a_live_windows_version() {
    let w = W::new();
    let st = w.stager(Relaying::Answer(500), true);
    let bytes = claude_bytes(V);
    w.admitted(V, &bytes, Some("staged"));
    let p = w.paths();
    std::fs::create_dir_all(p.claude_bin_dir(V)).unwrap();
    std::fs::write(p.claude_bin(V), &bytes).unwrap();
    st.s3.put(&format!("v1/_claude/mac/{V}/{}", sha(&bytes)), &bytes);
    w.window(V);
    let out = w.staged(&st, &["claude", "forget", V]);
    assert_eq!(out.status.code(), Some(9), "{}", all(&out));
    assert!(text(&out.stderr).contains(&format!("claude {V} runs in a live Cursor window")) && text(&out.stderr).contains("--force"), "{}", all(&out));
    assert!(w.record(V).is_some() && p.claude_bin(V).exists() && st.s3.requests().is_empty(), "nothing forgotten");
    let out = w.staged(&st, &["claude", "forget", V, "--force", "--local"]);
    assert!(out.status.success(), "{}", all(&out));
    assert!(w.record(V).is_none() && !p.claude_bin_dir(V).exists(), "its record and binary gone");
    assert!(w.state().calls.is_empty() && st.s3.requests().is_empty(), "--local: no Touch ID, no S3");
    let out = w.staged(&st, &["claude", "forget", V, "--force"]);
    assert!(out.status.success(), "{}", all(&out));
    assert!(st.s3.objects().iter().any(|o| o.delete_marker && o.current), "its object deleted");
    assert_eq!((w.audit("claude_stage")[0]["detail"]["outcome"].as_str(), w.audit("claude_stage")[0]["detail"]["why"].as_str()), (Some("deleted"), Some("forget")));
    let out = w.staged(&st, &["claude", "forget", V, "--force"]);
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    assert!(text(&out.stderr).contains("nothing to forget"), "{}", all(&out));
}

// ---- I1 ----------------------------------------------------------------------------------------------------------

/// The stager through the real shim's `POST /claude/relay` (A1's): the remote rig's VM, its fake curl serving the
/// release's GET (`S3CURL_BODY`: never the network) and its real curl taking only the PUT to the tests' S3
/// (`S3CURL_REAL_ONLY`); the object then holds V's bytes.
#[test]
fn stage_relays_through_the_real_shim() {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let rig = common::remote::RemoteRig::new(&root);
    let bytes = claude_bytes(V);
    let body = root.join("release-claude");
    std::fs::write(&body, &bytes).unwrap();
    let body = body.display().to_string();
    rig.set_vm_curl_knobs(&[("S3CURL_REAL", common::remote::REAL_CURL), ("S3CURL_REAL_ONLY", "PUT"), ("S3CURL_BODY", body.as_str())]);
    // The rig's fake `/health` names `claude_stage_v1` while the shim serves it (`claudebin::SERVED`, A1).
    const { assert!(ai_env_cli::shim::claudebin::SERVED, "A1's relay is served") };
    Record::update(&rig.paths(), V, |r| {
        r.signature = Some(SignatureRow { outcome: "ok".into(), signer: Some(RELEASE_KEY_FPR.into()), linux_sha256: Some(sha(&bytes)), linux_size: Some(bytes.len() as u64), at: "t".into(), ..SignatureRow::default() });
        r.admission = Some(AdmissionRow { outcome: "admitted".into(), markers: Some("ok".into()), ai_env: "0.1.0".into(), at: "t".into(), ..AdmissionRow::default() });
    })
    .unwrap();
    let out = rig.run(&["claude", "stage", V], None);
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(rig.s3().get(&format!("v1/_claude/mac/{V}/{}", sha(&bytes))), Some(bytes));
    assert_eq!(Record::load(&rig.paths(), V).unwrap().unwrap().phase(), Phase::Staged);
}
