//! S11 part B (wave 1, B1): the loopback panel (`ai-env panel serve --port
//! 0`) through the real binary, spoken to in raw HTTP/1.1 over a
//! `std::net::TcpStream` (no client crate), stopped with SIGTERM
//! (plans/s11-contracts-B.md §B5, §B6.4). Each test runs in its own temporary
//! world: a bridge root whose bridge.toml says `[panel] enabled = true`, the
//! file-backed fake MicroVM API (`AI_ENV_BRIDGE_LAB_FAKE_API`, polls in
//! milliseconds), and the S11 clock (`AI_ENV_BRIDGE_LAB_NOW`). Nothing here
//! touches AWS or asks for a Touch ID: the fake API unseals nothing.
//!
//! The tests that need part B's B2 (the session and cost pages, the
//! follower behind `events`, the CLI's `audit tail`, `cost` and `session
//! show` documents) are written here and go green at I1, once B2 is merged:
//! `pages_render_escaped`'s last pages, `sse_streams_appended_rows`,
//! `models_equal_cli_json`'s last documents. The panel's migrate on the S10
//! rig is `panel/migrate.rs` (feature `shim`).
#![allow(dead_code)]

mod common;
#[cfg(feature = "shim")]
#[path = "panel/migrate.rs"]
mod migrate;

use ai_env_cli::bridge::api::{FakeState, FAKE_IMAGE_ARN};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// Every wait's bound.
pub const T: Duration = Duration::from_secs(60);
/// The S11 clock of every child: 2026-10-23T00:00:00Z.
pub const NOW: &str = "1792713600";
/// The six headers of every response (`panel::HEADERS`).
const SIX: [(&str, &str); 6] = [
    ("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    ("referrer-policy", "no-referrer"),
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("cache-control", "no-store"),
    ("cross-origin-resource-policy", "same-origin"),
];

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env")
}

// ---- raw HTTP/1.1 -----------------------------------------------------------------------

/// One response: its status, its headers (names lowercased, in order) and its body (de-chunked).
#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {} {}", self.status, self.text()))
    }

    /// The six headers, exactly once each; no cookie, no CORS header, no `WWW-Authenticate`.
    pub fn assert_hardened(&self, what: &str) {
        for (name, value) in SIX {
            assert_eq!(self.all(name), [value], "{what}: {name}: {:?}", self.headers);
        }
        for (k, _) in &self.headers {
            assert!(k != "set-cookie" && k != "www-authenticate" && !k.starts_with("access-control-"), "{what}: {k}: {:?}", self.headers);
        }
    }
}

/// The body of a chunked transfer.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(eol) = b.windows(2).position(|w| w == b"\r\n") else { return out };
        let size = usize::from_str_radix(String::from_utf8_lossy(&b[..eol]).split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        if size == 0 || b.len() < eol + 2 + size {
            return out;
        }
        out.extend_from_slice(&b[eol + 2..eol + 2 + size]);
        b = &b[(eol + 4 + size).min(b.len())..];
    }
}

/// A response head: its status, its headers, where its body starts.
type Head = (u16, Vec<(String, String)>, usize);

/// The head of a response (`None` while it is incomplete) and where its body starts.
fn parse_head(buf: &[u8]) -> Option<Head> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    Some((status, headers, end + 4))
}

/// A whole response read to the connection's end.
fn parse_response(buf: &[u8]) -> Resp {
    let (status, headers, at) = parse_head(buf).unwrap_or_else(|| panic!("no response head: {:?}", String::from_utf8_lossy(buf)));
    let resp = Resp { status, headers, body: Vec::new() };
    let body = if resp.header("transfer-encoding").is_some_and(|t| t.contains("chunked")) { dechunk(&buf[at..]) } else { buf[at..].to_vec() };
    Resp { body, ..resp }
}

/// `request` (its head and body as given) on a new connection, read to its end.
pub fn exchange(port: u16, request: &[u8]) -> Resp {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect to the panel");
    s.set_read_timeout(Some(T)).unwrap();
    s.write_all(request).expect("send the request");
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("read the response");
    parse_response(&buf)
}

/// A stream left open: its head read, the rest readable as it comes.
pub struct Stream {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    sock: TcpStream,
    pub seen: Vec<u8>,
}

impl Stream {
    pub fn resp(&self) -> Resp {
        Resp { status: self.status, headers: self.headers.clone(), body: Vec::new() }
    }

    /// Read until the text read so far takes `pred`, at most `within`; whether it did.
    pub fn read_until(&mut self, within: Duration, pred: impl Fn(&str) -> bool) -> bool {
        let until = Instant::now() + within;
        let mut buf = [0u8; 8192];
        while !pred(&String::from_utf8_lossy(&self.seen)) {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            self.sock.set_read_timeout(Some(left.min(Duration::from_millis(200)))).unwrap();
            match self.sock.read(&mut buf) {
                Ok(0) => return pred(&String::from_utf8_lossy(&self.seen)),
                Ok(n) => self.seen.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => return false,
            }
        }
        true
    }
}

/// `request` on a new connection kept open: its head, then the stream.
pub fn open_stream(port: u16, request: &[u8]) -> Stream {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect to the panel");
    sock.write_all(request).expect("send the request");
    sock.set_read_timeout(Some(T)).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((status, headers, at)) = parse_head(&buf) {
            return Stream { status, headers, sock, seen: buf[at..].to_vec() };
        }
        let n = sock.read(&mut chunk).expect("read the response head");
        assert!(n > 0, "the connection closed before its head: {:?}", String::from_utf8_lossy(&buf));
        buf.extend_from_slice(&chunk[..n]);
    }
}

// ---- the panel process ----------------------------------------------------------------------

/// A running `ai-env panel serve --port 0`: its port and bearer from its one stdout line.
pub struct Panel {
    child: Child,
    pub port: u16,
    pub bearer: String,
    stderr: Arc<Mutex<Vec<u8>>>,
    stdout_rest: mpsc::Receiver<String>,
}

impl Panel {
    /// Start `cmd` (an `ai-env panel serve …`) and read its URL line within [`T`].
    pub fn start(mut cmd: Command) -> Panel {
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn ai-env panel serve");
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let (mut err, sink) = (child.stderr.take().unwrap(), Arc::clone(&stderr));
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = err.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let out = child.stdout.take().unwrap();
        let (first_tx, first_rx) = mpsc::channel();
        let (rest_tx, stdout_rest) = mpsc::channel();
        std::thread::spawn(move || {
            let mut r = BufReader::new(out);
            let mut line = String::new();
            let _ = r.read_line(&mut line);
            let _ = first_tx.send(line);
            let mut rest = String::new();
            let _ = r.read_to_string(&mut rest);
            let _ = rest_tx.send(rest);
        });
        let line = first_rx.recv_timeout(T).unwrap_or_else(|_| panic!("no URL line within {T:?}: {}", String::from_utf8_lossy(&stderr.lock().unwrap())));
        let url = line.strip_prefix("panel: http://127.0.0.1:").and_then(|l| l.strip_suffix("/\n")).unwrap_or_else(|| panic!("the URL line: {line:?}; stderr: {}", String::from_utf8_lossy(&stderr.lock().unwrap())));
        let (port, bearer) = url.split_once('/').unwrap_or_else(|| panic!("the URL line: {line:?}"));
        let port: u16 = port.parse().unwrap_or_else(|_| panic!("the URL line's port: {line:?}"));
        assert_eq!(bearer.len(), 43, "a 43-character base64url bearer: {line:?}");
        assert!(bearer.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'), "{line:?}");
        Panel { child, port, bearer: bearer.to_string(), stderr, stdout_rest }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// `Host: 127.0.0.1:<port>`.
    pub fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// `http://127.0.0.1:<port>`.
    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// `/<bearer>/<rel>`.
    pub fn path(&self, rel: &str) -> String {
        format!("/{}/{rel}", self.bearer)
    }

    /// A request of `method` on `path` with `headers` (each `Name: value`; `Host` added unless one is given),
    /// `Connection: close` and `body`.
    pub fn request(&self, method: &str, path: &str, headers: &[String], body: &[u8]) -> Resp {
        let mut head = format!("{method} {path} HTTP/1.1\r\n");
        if !headers.iter().any(|h| h.to_ascii_lowercase().starts_with("host:")) {
            head.push_str(&format!("Host: {}\r\n", self.host()));
        }
        for h in headers {
            head.push_str(h);
            head.push_str("\r\n");
        }
        if !body.is_empty() || method == "POST" {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("Connection: close\r\n\r\n");
        let mut req = head.into_bytes();
        req.extend_from_slice(body);
        exchange(self.port, &req)
    }

    /// A browser's GET of `rel` under the bearer (`Sec-Fetch-Site: same-origin`).
    pub fn get(&self, rel: &str) -> Resp {
        self.request("GET", &self.path(rel), &["Sec-Fetch-Site: same-origin".to_string()], b"")
    }

    /// A browser's form POST of `body` to `actions`.
    pub fn post(&self, body: &str) -> Resp {
        self.request("POST", &self.path("actions"), &[format!("Origin: {}", self.origin()), "Sec-Fetch-Site: same-origin".into(), "Content-Type: application/x-www-form-urlencoded;charset=UTF-8".into()], body.as_bytes())
    }

    /// `GET events<query>` kept open.
    pub fn events(&self, query: &str) -> Stream {
        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nSec-Fetch-Site: same-origin\r\nAccept: text/event-stream\r\n\r\n", self.path(&format!("events{query}")), self.host());
        open_stream(self.port, req.as_bytes())
    }

    /// The confirm page's nonce for `action` on `target` (its `?json=1`).
    pub fn nonce(&self, action: &str, target: &str) -> String {
        let r = self.get(&format!("confirm?action={action}&target={target}&json=1"));
        assert_eq!(r.status, 200, "confirm {action} {target}: {}", r.text());
        r.json()["nonce"].as_str().unwrap_or_else(|| panic!("no nonce: {}", r.text())).to_string()
    }

    /// `POST actions` of `nonce` for `action` on `target`.
    pub fn post_action(&self, nonce: &str, action: &str, target: &str) -> Resp {
        self.post(&format!("nonce={nonce}&action={action}&target={target}"))
    }

    /// Action `nonce`'s document once it ended (`done` or `failed`), within [`T`].
    pub fn wait_action(&self, nonce: &str) -> Value {
        let t0 = Instant::now();
        loop {
            let r = self.get(&format!("actions/{nonce}?json=1"));
            assert_eq!(r.status, 200, "{}", r.text());
            let v = r.json();
            if v["state"] == "done" || v["state"] == "failed" {
                return v;
            }
            assert!(t0.elapsed() < T, "action {nonce} still {}: {}", v["state"], self.stderr());
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// `action` on `target` from its confirm page to its end: its nonce and its document.
    pub fn act(&self, action: &str, target: &str) -> (String, Value) {
        let nonce = self.nonce(action, target);
        let r = self.post_action(&nonce, action, target);
        assert_eq!((r.status, r.header("location")), (303, Some(format!("actions/{nonce}").as_str())), "{}", r.text());
        (nonce.clone(), self.wait_action(&nonce))
    }

    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }

    /// SIGTERM, then its exit within [`T`]: the code, what stdout said after the URL line, and stderr.
    pub fn stop(mut self) -> (Option<i32>, String, String) {
        // SAFETY: kill(2) of this test's own child.
        unsafe { libc::kill(libc::pid_t::try_from(self.child.id()).unwrap(), libc::SIGTERM) };
        let t0 = Instant::now();
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            assert!(t0.elapsed() < T, "the panel did not stop within {T:?}: {}", self.stderr());
            std::thread::sleep(Duration::from_millis(20));
        };
        let rest = self.stdout_rest.recv_timeout(T).unwrap_or_default();
        std::thread::sleep(Duration::from_millis(50));
        (status.code(), rest, self.stderr())
    }
}

impl Drop for Panel {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

// ---- the world ------------------------------------------------------------------------------

/// One isolated world: `bridge/` (bridge.toml, state, audit, logs), `keys/`, `ws/`, `fake.json`.
pub struct World {
    tmp: tempfile::TempDir,
}

impl Default for World {
    fn default() -> Self {
        World::new()
    }
}

/// `[aws]` of a world: the fake's image, a role in the fake image's account.
fn aws_table() -> String {
    let account = FAKE_IMAGE_ARN.split(':').nth(4).expect("the fake image ARN's account");
    format!("[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\nexecution_role_arn = \"arn:aws:iam::{account}:role/ai-env-exec\"\n")
}

impl World {
    /// The panel on, the fake API's VMs advancing on their own.
    pub fn new() -> World {
        World::with_toml("[panel]\nenabled = true\n")
    }

    /// `[aws]`, `[workspaces]` and then `tail` as bridge.toml.
    pub fn with_toml(tail: &str) -> World {
        let tmp = tempfile::tempdir().unwrap();
        for d in ["bridge", "keys", "ws"] {
            std::fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        let ws = std::fs::canonicalize(tmp.path().join("ws")).unwrap();
        std::fs::write(tmp.path().join("bridge").join("bridge.toml"), format!("{}\n[workspaces]\nroots = [{:?}]\n\n{tail}", aws_table(), ws.display().to_string())).unwrap();
        let w = World { tmp };
        w.update_fake(|s| s.auto_advance = true);
        w
    }

    pub fn root(&self) -> &Path {
        self.tmp.path()
    }

    pub fn bridge(&self) -> PathBuf {
        self.root().join("bridge")
    }

    pub fn paths(&self) -> ai_env_cli::bridge::config::Paths {
        ai_env_cli::bridge::config::Paths::from_root_and_env(self.bridge(), None)
    }

    pub fn fake(&self) -> PathBuf {
        self.root().join("fake.json")
    }

    pub fn update_fake(&self, f: impl FnOnce(&mut FakeState)) {
        let mut s = std::fs::read_to_string(self.fake()).ok().filter(|t| !t.trim().is_empty()).map_or_else(FakeState::new, |t| serde_json::from_str(&t).unwrap());
        f(&mut s);
        std::fs::write(self.fake(), serde_json::to_string_pretty(&s).unwrap()).unwrap();
    }

    /// `ai-env <args>` in this world: its own HOME, bridge and keystore, the fake API, the S11 clock; a
    /// developer's AWS, lab and fake variables removed.
    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args);
        for name in common::REMOVED_ENV {
            c.env_remove(name);
        }
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().to_string();
            if k.starts_with("AWS_") || k.starts_with("PULUMI_") || k.starts_with("AI_ENV_BRIDGE_LAB_") || k.starts_with("CLAUDE_CODE_") || k.starts_with("FAKE_") {
                c.env_remove(&k);
            }
        }
        c.env("HOME", self.root())
            .env("AI_ENV_BRIDGE_DIR", self.bridge())
            .env("AI_ENV_DIR", self.root().join("keys"))
            .env_remove("AI_ENV_BRIDGE_CONFIG")
            .env_remove("AI_ENV_BRIDGE_TRACE")
            .env_remove("AI_ENV_BRIDGE_AS")
            .env_remove("RUST_LOG")
            .env("AI_ENV_BRIDGE_LAB_FAKE_API", self.fake())
            .env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1")
            .env("AI_ENV_BRIDGE_LAB_NOW", NOW)
            .stdin(Stdio::null());
        c
    }

    /// `ai-env <args>` run to its end within [`T`].
    pub fn run(&self, args: &[&str]) -> Output {
        common::bounded::run_within(self.cmd(args), None, T, "ai-env")
    }

    /// `ai-env panel serve --port 0 <extra>`, started.
    pub fn serve(&self, extra: &[(&str, &str)]) -> Panel {
        let mut c = self.cmd(&["panel", "serve", "--port", "0"]);
        for (k, v) in extra {
            c.env(k, v);
        }
        Panel::start(c)
    }

    /// A new VM (`vm run --egress internet`, with `extra` flags): its id.
    pub fn vm(&self, extra: &[&str]) -> String {
        let mut args = vec!["vm", "run", "--egress", "internet", "--json"];
        args.extend_from_slice(extra);
        let o = self.run(&args);
        assert_eq!(o.status.code(), Some(0), "vm run: {}", String::from_utf8_lossy(&o.stderr));
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        v["id"].as_str().expect("the VM's id").to_string()
    }

    /// Every audit row, in order.
    pub fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.bridge().join("audit.jsonl")).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    /// The VM row of `id` as stored.
    pub fn vm_row(&self, id: &str) -> toml::Value {
        toml::from_str(&std::fs::read_to_string(self.bridge().join("state").join("vms").join(format!("{id}.toml"))).unwrap()).unwrap()
    }

    /// A row of `event` appended to the audit as stored (`detail` as given, `actor` among it).
    pub fn append_audit(&self, event: &str, detail: Value) {
        let line = serde_json::json!({"v": 2, "ts": "2026-10-22T23:00:00Z", "event": event, "session_id": null, "pid": 1, "detail": detail});
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.bridge().join("audit.jsonl")).unwrap();
        writeln!(f, "{line}").unwrap();
    }

    /// A session row: `mode` (`remote` with `vm`), closed, its wrapper long gone.
    pub fn session(&self, sid: &str, mode: &str, vm: Option<&str>, slug: &str, cwd: &str) {
        use ai_env_cli::bridge::registry::{self, SessionRow, REGISTRY_SCHEMA_V};
        let row = SessionRow {
            v: REGISTRY_SCHEMA_V,
            session_id: sid.to_string(),
            slug: Some(slug.to_string()),
            cwd: Some(cwd.to_string()),
            created: "2026-10-22T20:00:00Z".into(),
            last_seen: "2026-10-22T21:00:00Z".into(),
            status: "closed".into(),
            mode: mode.into(),
            route: if mode == "remote" { "remote".into() } else { "local:outside_roots".into() },
            pid: dead_pid(),
            microvm_id: vm.map(str::to_string),
            ..SessionRow::default()
        };
        registry::write(&self.paths(), &row).expect("the session row");
    }

    /// Every file under the world, concatenated (lossy).
    pub fn all_files(&self) -> String {
        let mut out = String::new();
        let mut stack = vec![self.root().to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let t = e.file_type().unwrap();
                if t.is_dir() {
                    stack.push(e.path());
                } else if t.is_file() {
                    out.push_str(&String::from_utf8_lossy(&std::fs::read(e.path()).unwrap()));
                }
            }
        }
        out
    }
}

/// The pid of a process that ran and exited.
pub fn dead_pid() -> u32 {
    let mut child = Command::new("/usr/bin/true").spawn().expect("run true");
    child.wait().expect("wait for true");
    child.id()
}

fn stderr_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A settings file of a capture (as the VM's helper reads it).
fn settings_file(scope: &str, text: Option<&str>) -> Value {
    use sha2::Digest;
    let path = match scope {
        "user" => "/Users/mike/.claude/settings.json".to_string(),
        "project" => "/Users/mike/w/.claude/settings.json".to_string(),
        _ => "/Users/mike/w/.claude/settings.local.json".to_string(),
    };
    match text {
        Some(t) => serde_json::json!({"scope": scope, "path": path, "present": true, "size": t.len(), "sha256": hex::encode(sha2::Sha256::digest(t.as_bytes())), "text": t}),
        None => serde_json::json!({"scope": scope, "path": path, "present": false, "size": 0}),
    }
}

/// Plant session `sid`'s settings captures: a start with no local settings, a latest whose local settings
/// allow `rule`.
fn plant_captures(w: &World, sid: &str, rule: &str) {
    let capture = |local: Option<&str>, at: &str| serde_json::json!({"path": "/Users/mike/w", "files": [settings_file("user", Some("{}")), settings_file("project", None), settings_file("local", local)], "project": {}, "at": at});
    let local = serde_json::json!({"permissions": {"allow": [rule]}}).to_string();
    let dir = w.bridge().join("quarantine").join(sid).join("settings");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("start.json"), serde_json::to_string_pretty(&capture(None, "2026-10-22T20:00:00Z")).unwrap()).unwrap();
    std::fs::write(dir.join("latest.json"), serde_json::to_string_pretty(&capture(Some(&local), "2026-10-22T20:30:00Z")).unwrap()).unwrap();
}

const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
const SID_LOCAL: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";

// ---- serve's lifecycle ------------------------------------------------------------------------

/// `--bind` other than 127.0.0.1 is exit 2 before anything is read: with the panel off, and with no
/// bridge.toml at all; nothing audited.
#[test]
fn non_loopback_bind_exits_2() {
    let w = World::with_toml("[panel]\nenabled = false\n");
    for bind in ["0.0.0.0", "::", "192.0.2.1", "localhost", "127.0.0.2"] {
        let o = w.run(&["panel", "serve", "--bind", bind, "--port", "0"]);
        assert_eq!(o.status.code(), Some(2), "{bind}: {}", stderr_of(&o));
        assert!(stderr_of(&o).contains(&format!("panel serve: --bind {bind}: the panel listens on 127.0.0.1 only")), "{}", stderr_of(&o));
        assert!(o.stdout.is_empty());
    }
    std::fs::remove_file(w.bridge().join("bridge.toml")).unwrap();
    assert_eq!(w.run(&["panel", "serve", "--bind", "0.0.0.0"]).status.code(), Some(2));
    assert!(!w.bridge().join("audit.jsonl").exists(), "nothing audited");
}

/// `[panel] enabled = false` (the default, with no `[panel]` and with no bridge.toml) is exit 9 naming the
/// key and the file; `--bind 127.0.0.1` passes the bind check.
#[test]
fn disabled_exits_9() {
    for tail in ["", "[panel]\nenabled = false\nport = 7391\n"] {
        let w = World::with_toml(tail);
        let o = w.run(&["panel", "serve", "--bind", "127.0.0.1"]);
        let err = stderr_of(&o);
        assert_eq!(o.status.code(), Some(9), "{err}");
        assert!(err.contains(&format!("panel serve is off: [panel] enabled = false in {}  <- set [panel] enabled = true in bridge.toml", w.bridge().join("bridge.toml").display())), "{err}");
        assert!(o.stdout.is_empty() && !w.bridge().join("audit.jsonl").exists());
    }
    let w = World::new();
    std::fs::remove_file(w.bridge().join("bridge.toml")).unwrap();
    assert_eq!(w.run(&["panel", "serve"]).status.code(), Some(9));
    // A hand-added key in [panel] is refused (deny_unknown_fields): no new key such as bind.
    let w = World::with_toml("[panel]\nenabled = true\nbind = \"0.0.0.0\"\n");
    let o = w.run(&["panel", "serve", "--port", "0"]);
    assert_ne!(o.status.code(), Some(0), "{}", stderr_of(&o));
    assert!(o.stdout.is_empty(), "no URL: {}", String::from_utf8_lossy(&o.stdout));
}

/// A busy port is exit 1 naming it and `--port 0`.
#[test]
fn busy_port_exits_1_naming_port_0() {
    let w = World::new();
    let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = held.local_addr().unwrap().port();
    let o = w.run(&["panel", "serve", "--port", &port.to_string()]);
    let err = stderr_of(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains(&format!("panel serve: 127.0.0.1:{port} is in use (")) && err.contains("  <- --port N, or --port 0 for any free port"), "{err}");
    assert!(o.stdout.is_empty());
    drop(held);
}

/// `panel_serve {port, outcome}` at start and at stop, by the panel; one stdout line; exit 0 on SIGTERM.
#[test]
fn serve_audits_started_and_stopped() {
    let w = World::new();
    let p = w.serve(&[]);
    let port = p.port.to_string();
    let t0 = Instant::now();
    while w.audit().is_empty() {
        assert!(t0.elapsed() < T, "no panel_serve started row");
        std::thread::sleep(Duration::from_millis(20));
    }
    let rows = w.audit();
    assert_eq!((rows.len(), rows[0]["detail"]["outcome"].as_str()), (1, Some("started")), "{rows:?}");
    let (code, rest, err) = p.stop();
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(rest, "", "stdout is the one URL line");
    let serving = format!("panel: serving on 127.0.0.1:{port} until Ctrl-C (the URL holds this run's bearer: do not share it)");
    assert!(err.lines().any(|l| l == serving), "a whole stderr line is the contract's: {err}");
    let rows: Vec<Value> = w.audit().into_iter().filter(|r| r["event"] == "panel_serve").collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    for (row, outcome) in rows.iter().zip(["started", "stopped"]) {
        assert_eq!(row["v"], 2);
        let d = row["detail"].as_object().unwrap();
        assert_eq!(d.len(), 3, "port, outcome and actor only: {row}");
        assert_eq!((d["port"].as_str(), d["outcome"].as_str(), d["actor"].as_str()), (Some(port.as_str()), Some(outcome), Some("panel")), "{row}");
    }
    let log = std::fs::read_to_string(w.bridge().join("logs").join("ai-env.log")).unwrap_or_default();
    assert!(log.contains(&format!("panel: serving on 127.0.0.1:{port}")) && log.contains("panel: stopped"), "{log}");
    // A stop right after the URL line (no request, no audit poll) is the panel's own: exit 0, one row each.
    let w = World::new();
    let p = w.serve(&[]);
    let port = p.port.to_string();
    let (code, _, err) = p.stop();
    assert_eq!(code, Some(0), "an immediate SIGTERM: {err}");
    let rows: Vec<(Option<String>, Option<String>)> = w
        .audit()
        .into_iter()
        .filter(|r| r["event"] == "panel_serve")
        .map(|r| (r["detail"]["port"].as_str().map(str::to_string), r["detail"]["outcome"].as_str().map(str::to_string)))
        .collect();
    let want = |o: &str| (Some(port.clone()), Some(o.to_string()));
    assert_eq!(rows, vec![want("started"), want("stopped")], "an immediate SIGTERM: {err}");
}

// ---- every request ----------------------------------------------------------------------------

/// A POST (or a GET) whose first segment is not the bearer is 401, with no `WWW-Authenticate`.
#[test]
fn post_without_bearer_401() {
    let w = World::new();
    let p = w.serve(&[]);
    let form = format!("Origin: {}", p.origin());
    let headers = [form, "Sec-Fetch-Site: same-origin".into(), "Content-Type: application/x-www-form-urlencoded".into()];
    for path in ["/actions", "/", "/actions/", &format!("/x{}/actions", p.bearer)] {
        let r = p.request("POST", path, &headers, b"nonce=x&action=vm-refresh&target=-");
        assert_eq!(r.status, 401, "{path}: {}", r.text());
        assert_eq!(r.text(), "unauthorized\n");
        assert!(r.header("www-authenticate").is_none());
        r.assert_hardened(path);
    }
    assert_eq!(p.request("GET", "/", &[], b"").status, 401);
    assert_eq!(p.stop().0, Some(0));
}

/// The bearer with one character changed (same length), one longer, one shorter: 401 for GET and POST; the
/// bearer itself passes.
#[test]
fn wrong_bearer_same_length_401() {
    let w = World::new();
    let p = w.serve(&[]);
    let b = &p.bearer;
    let flip = |i: usize| {
        let mut s: Vec<u8> = b.bytes().collect();
        s[i] = if s[i] == b'A' { b'B' } else { b'A' };
        String::from_utf8(s).unwrap()
    };
    for wrong in [flip(0), flip(21), flip(42), format!("{b}A"), b[1..].to_string(), b.to_ascii_lowercase(), b.to_ascii_uppercase()] {
        if wrong == *b {
            continue;
        }
        assert_eq!(wrong.len() == b.len(), wrong.len() == 43);
        let r = p.request("GET", &format!("/{wrong}/"), &[], b"");
        assert_eq!(r.status, 401, "{}", r.text());
        let r = p.request("POST", &format!("/{wrong}/actions"), &[format!("Origin: {}", p.origin()), "Content-Type: application/x-www-form-urlencoded".into()], b"a=b");
        assert_eq!(r.status, 401);
    }
    assert_eq!(p.get("").status, 200);
    assert_eq!(p.stop().0, Some(0));
}

/// A POST whose Origin is missing or not this panel's is 403 (`null` too: a form posted under no-referrer);
/// the nonce stays unused, so the right Origin then runs it.
#[test]
fn wrong_or_missing_origin_403() {
    let w = World::new();
    let p = w.serve(&[]);
    let nonce = p.nonce("vm-refresh", "-");
    let body = format!("nonce={nonce}&action=vm-refresh&target=-");
    let ct = "Content-Type: application/x-www-form-urlencoded".to_string();
    let other = p.port.wrapping_add(1);
    for origin in [None, Some("null".to_string()), Some(format!("http://localhost:{}", p.port)), Some(format!("http://127.0.0.1:{other}")), Some(format!("https://127.0.0.1:{}", p.port)), Some("http://evil.example".into())] {
        let mut headers = vec![ct.clone()];
        headers.extend(origin.iter().map(|o| format!("Origin: {o}")));
        let r = p.request("POST", &p.path("actions"), &headers, body.as_bytes());
        assert_eq!(r.status, 403, "{origin:?}: {}", r.text());
        assert_eq!(r.text(), "forbidden\n");
        r.assert_hardened("403");
    }
    let r = p.post(&body);
    assert_eq!(r.status, 303, "{}", r.text());
    let done = p.wait_action(&nonce);
    assert_eq!(done["state"], "done", "{done}");
    assert_eq!(p.stop().0, Some(0));
}

/// `Sec-Fetch-Site` other than `same-origin` or `none` on a GET, other than `same-origin` on a POST: 403.
#[test]
fn cross_site_403() {
    let w = World::new();
    let p = w.serve(&[]);
    for site in ["cross-site", "same-site"] {
        let r = p.request("GET", &p.path(""), &[format!("Sec-Fetch-Site: {site}")], b"");
        assert_eq!(r.status, 403, "{site}");
        let r = p.request("HEAD", &p.path("vms"), &[format!("Sec-Fetch-Site: {site}")], b"");
        assert_eq!(r.status, 403, "{site}");
        let r = p.request("POST", &p.path("actions"), &[format!("Origin: {}", p.origin()), format!("Sec-Fetch-Site: {site}"), "Content-Type: application/x-www-form-urlencoded".into()], b"a=b");
        assert_eq!(r.status, 403, "{site}");
    }
    for site in ["same-origin", "none"] {
        assert_eq!(p.request("GET", &p.path(""), &[format!("Sec-Fetch-Site: {site}")], b"").status, 200, "{site}");
    }
    assert_eq!(p.request("GET", &p.path(""), &[], b"").status, 200, "no Sec-Fetch-Site (curl)");
    let r = p.request("POST", &p.path("actions"), &[format!("Origin: {}", p.origin()), "Sec-Fetch-Site: none".into(), "Content-Type: application/x-www-form-urlencoded".into()], b"a=b");
    assert_eq!(r.status, 403, "a POST is same-origin only");
    assert_eq!(p.stop().0, Some(0));
}

/// A `Host` other than `127.0.0.1:<port>` (another name, another port, none) is 403, before the bearer.
#[test]
fn foreign_host_403() {
    let w = World::new();
    let p = w.serve(&[]);
    for host in [format!("localhost:{}", p.port), "evil.example".into(), "127.0.0.1".into(), format!("127.0.0.1:{}", p.port.wrapping_add(1)), format!("[::1]:{}", p.port)] {
        let r = p.request("GET", &p.path(""), &[format!("Host: {host}")], b"");
        assert_eq!(r.status, 403, "{host}: {}", r.text());
        r.assert_hardened(&host);
        let r = p.request("GET", "/not-the-bearer/", &[format!("Host: {host}")], b"");
        assert_eq!(r.status, 403, "the host first: {host}");
    }
    // HTTP/1.0 without a Host.
    let r = exchange(p.port, format!("GET {} HTTP/1.0\r\n\r\n", p.path("")).as_bytes());
    assert_eq!(r.status, 403, "{}", r.text());
    assert_eq!(p.stop().0, Some(0));
}

/// Every response carries the six headers and no cookie, no CORS header: pages, assets, documents, the
/// stream, HEAD, and every refusal.
#[test]
fn headers_and_no_cookie_everywhere() {
    let w = World::new();
    let p = w.serve(&[]);
    let ct = "Content-Type: application/x-www-form-urlencoded".to_string();
    let origin = format!("Origin: {}", p.origin());
    let cases: Vec<(&str, Resp, u16)> = vec![
        ("sessions", p.get(""), 200),
        ("sessions json", p.get("?json=1"), 200),
        ("vms", p.get("vms"), 200),
        ("audit", p.get("audit"), 200),
        ("audit json", p.get("audit?json=1"), 200),
        ("app.js", p.get("assets/app.js"), 200),
        ("app.css", p.get("assets/app.css"), 200),
        ("confirm", p.get("confirm?action=vm-refresh&target=-"), 200),
        ("head", p.request("HEAD", &p.path(""), &[], b""), 200),
        ("no slash", p.request("GET", &format!("/{}", p.bearer), &[], b""), 404),
        ("unknown", p.get("nope"), 404),
        ("bad query", p.get("vms?x=1"), 400),
        ("bad confirm", p.get("confirm?action=vm-reboot&target=-"), 400),
        ("no bearer", p.request("GET", "/", &[], b""), 401),
        ("host", p.request("GET", &p.path(""), &["Host: localhost".into()], b""), 403),
        ("method", p.request("PUT", &p.path(""), &[], b""), 405),
        ("type", p.request("POST", &p.path("actions"), &[origin.clone(), "Content-Type: text/plain".into()], b"a=b"), 415),
        ("size", p.request("POST", &p.path("actions"), &[origin.clone(), ct.clone()], &vec![b'a'; 5000]), 413),
        ("form", p.request("POST", &p.path("actions"), &[origin.clone(), ct.clone()], b"a=<b>"), 400),
        ("nonce", p.request("POST", &p.path("actions"), &[origin.clone(), ct.clone()], b"nonce=x&action=vm-refresh&target=-"), 403),
        ("post elsewhere", p.request("POST", &p.path("vms"), &[origin, ct], b"a=b"), 404),
        ("no action", p.get("actions/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"), 404),
    ];
    for (what, r, status) in &cases {
        assert_eq!(r.status, *status, "{what}: {}", r.text());
        r.assert_hardened(what);
        if *status != 200 {
            assert!(r.header("content-type").is_some_and(|c| c.starts_with("text/plain")), "{what}: {:?}", r.headers);
            assert!(!r.text().contains(&p.bearer), "{what}");
        }
    }
    assert!(cases.iter().find(|c| c.0 == "head").unwrap().1.body.is_empty(), "HEAD has no body");
    assert_eq!(cases[5].1.header("content-type"), Some("text/javascript; charset=utf-8"));
    let page = cases[0].1.text();
    assert!(page.contains("<body data-root=\"./\"") && !page.contains("style=") && !page.contains("<style") && page.matches("<script").count() == 1, "{page}");
    let stream = p.events("");
    assert_eq!(stream.status, 200);
    assert_eq!(stream.resp().header("content-type"), Some("text/event-stream"));
    stream.resp().assert_hardened("events");
    assert_eq!(p.stop().0, Some(0));
}

/// The bearer is in stdout's one line and nowhere else: not in the log (at debug), the audit, the state, or
/// stderr, whatever the requests carried (a wrong bearer, the bearer in a query, a header, a form value) and
/// after an action.
#[test]
fn bearer_never_in_logs_or_audit() {
    let w = World::new();
    let vm = w.vm(&[]);
    let p = w.serve(&[("RUST_LOG", "debug")]);
    let b = p.bearer.clone();
    let filtered = p.get(&format!("audit?event={b}"));
    assert!(matches!(filtered.status, 200 | 400 | 500), "a filter through B2's from_args: {}", filtered.status);
    assert_eq!(p.get(&format!("vms?x={b}")).status, 400);
    assert_eq!(p.request("GET", &p.path(""), &[format!("X-Echo: {b}"), format!("Referer: http://127.0.0.1:{}/{b}/", p.port)], b"").status, 200);
    assert_eq!(p.request("GET", &format!("/{b}/{b}"), &[], b"").status, 404);
    assert_eq!(p.request("GET", &p.path(""), &[format!("Host: {b}")], b"").status, 403);
    assert_eq!(p.post(&format!("nonce={b}&action=vm-suspend&target={vm}")).status, 403);
    let (_, done) = p.act("vm-suspend", &vm);
    assert_eq!(done["state"], "done", "{done}");
    let (code, rest, err) = p.stop();
    assert_eq!(code, Some(0));
    assert_eq!(rest, "");
    assert!(!err.contains(&b), "stderr: {err}");
    let files = w.all_files();
    assert!(!files.contains(&b), "a file holds the bearer");
    let log = std::fs::read_to_string(w.bridge().join("logs").join("ai-env.log")).unwrap();
    assert!(log.contains("panel: action vm-suspend") && log.contains("(exit 0)"), "each action's word, target, outcome and code: {log}");
}

// ---- the pages --------------------------------------------------------------------------------

/// Every value a page shows is escaped: a session's slug and cwd, a VM's label, an audit row's value, a
/// settings rule; nothing a row holds becomes markup. (The session and cost pages need B2: green at I1.)
#[test]
fn pages_render_escaped() {
    let w = World::new();
    let vm = w.vm(&["--label", "<i>vm</i>"]);
    w.session(SID, "remote", Some(&vm), "<script>alert(1)</script>", "/w/\"quoted\" & 'single' <b>");
    w.session(SID_LOCAL, "local-child", None, "local", "/w/local");
    w.append_audit("vm_suspend", serde_json::json!({"actor": "cli", "id": vm, "purpose": "<script>alert(2)</script>"}));
    plant_captures(&w, SID, "Bash(echo <script>alert(3)</script>)");
    let p = w.serve(&[]);
    let never = ["<script>alert", "<i>vm", "<b>"];
    let check = |what: &str, r: &Resp, want: &[&str]| {
        assert_eq!(r.status, 200, "{what}: {}", r.text());
        assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"), "{what}");
        let t = r.text();
        for n in never {
            assert!(!t.contains(n), "{what}: {n} unescaped:\n{t}");
        }
        for wanted in want {
            assert!(t.contains(wanted), "{what}: no {wanted}:\n{t}");
        }
        assert!(!t.contains(&p.bearer), "{what}: no page holds the bearer");
    };
    check("sessions", &p.get(""), &["&lt;script&gt;alert(1)&lt;/script&gt;", &format!("href=\"./session/{SID}\""), &format!("href=\"./confirm?action=session-migrate&amp;target={SID}\"")]);
    check("vms", &p.get("vms"), &["&lt;i&gt;vm&lt;/i&gt;", &format!("href=\"./confirm?action=vm-suspend&amp;target={vm}\""), "href=\"./confirm?action=vm-refresh&amp;target=-\""]);
    check("audit", &p.get("audit"), &["purpose=&lt;script&gt;alert(2)&lt;/script&gt;", "<tbody id=\"rows\">"]);
    check("settings", &p.get(&format!("settings/{SID}")), &["Bash(echo &lt;script&gt;alert(3)&lt;/script&gt;)", &format!("ai-env wrapper settings-sync {SID} --all-safe"), "<body data-root=\"../\""]);
    assert!(!w.bridge().join("quarantine").join(SID).join("settings").join("diff.json").exists(), "the panel never writes diff.json");
    check("confirm", &p.get(&format!("confirm?action=session-migrate&target={SID}")), &[&format!("ai-env session migrate {SID}"), "name=\"nonce\""]);
    assert_eq!(p.get(&format!("confirm?action=session-migrate&target={SID_LOCAL}")).status, 400, "a chat on this Mac is no migrate target");
    assert_eq!(p.get("confirm?action=session-migrate&target=0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d").status, 404);
    assert_eq!(p.get("confirm?action=vm-suspend&target=-microvm").status, 400, "no VM id");
    assert_eq!(p.get("confirm?action=vm-suspend&target=pending-x").status, 400, "a pending row's stem is no VM id");
    assert_eq!(p.get("confirm?action=vm-suspend&target=microvm-00000000-0000-4000-8000-000000000000").status, 404);
    assert_eq!(p.get("settings/not-a-uuid").status, 400);
    assert_eq!(p.get(&format!("settings/{SID_LOCAL}")).status, 404, "no start capture");
    assert_eq!(p.get("session/not-a-uuid").status, 400);
    // B2's pages (green at I1).
    check("session", &p.get(&format!("session/{SID}")), &["&lt;b&gt;", "&quot;quoted&quot; &amp; &#39;single&#39;", "<body data-root=\"../\""]);
    assert_eq!(p.get("session/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d").status, 404);
    check("cost", &p.get("cost"), &["window "]);
    check("cost since", &p.get("cost?since=2026-10-22"), &["window "]);
    assert_eq!(p.get("cost?since=yesterday").status, 400);
    assert_eq!(p.stop().0, Some(0));
}

// ---- the stream ------------------------------------------------------------------------------

/// `events` streams the rows written after it opened that its filter takes (scrubbed again, a DEL or a C1 as its
/// escape, as `audit tail --json` prints it), and each action's state. (`audit::read::Follower::poll` and the filters
/// are B2's: green at I1.)
#[test]
fn sse_streams_appended_rows() {
    let w = World::new();
    let vm = w.vm(&[]);
    let p = w.serve(&[]);
    let mut filtered = p.events(&format!("?event=vm_suspend&vm={vm}"));
    let mut all = p.events("");
    assert_eq!((filtered.status, all.status), (200, 200));
    std::thread::sleep(Duration::from_millis(400));
    w.append_audit("vm_resume", serde_json::json!({"actor": "cli", "id": vm, "purpose": "marker-not-taken"}));
    w.append_audit("vm_suspend", serde_json::json!({"actor": "cli", "id": vm, "purpose": "marker-taken\u{9b}\u{7f}"}));
    assert!(filtered.read_until(T, |t| t.contains("marker-taken\\u009b\\u007f")), "the row, inert: {}", String::from_utf8_lossy(&filtered.seen));
    let seen = String::from_utf8_lossy(&filtered.seen).into_owned();
    assert!(seen.contains("event: audit\ndata: {") && !seen.contains("marker-not-taken"), "{seen}");
    assert!(seen.contains("marker-taken\\u009b\\u007f") && !seen.contains(['\u{9b}', '\u{7f}']), "inert: {seen}");
    assert!(all.read_until(T, |t| t.contains("marker-not-taken") && t.contains("marker-taken")), "{}", String::from_utf8_lossy(&all.seen));
    let (nonce, done) = p.act("vm-refresh", "-");
    assert_eq!(done["state"], "done", "{done}");
    assert!(all.read_until(T, |t| t.contains("event: action") && t.contains(&format!("\"id\":\"{nonce}\"")) && t.contains("\"state\":\"done\"")), "{}", String::from_utf8_lossy(&all.seen));
    assert_eq!(p.stop().0, Some(0), "the stop ends the streams");
}

/// At most eight streams: a ninth is 503 with `Retry-After: 15`; the stop ends the eight.
#[test]
fn the_ninth_stream_is_503() {
    let w = World::new();
    let p = w.serve(&[]);
    let streams: Vec<Stream> = (0..8).map(|_| p.events("")).collect();
    assert!(streams.iter().all(|s| s.status == 200), "{:?}", streams.iter().map(|s| s.status).collect::<Vec<_>>());
    let r = p.request("GET", &p.path("events"), &[], b"");
    assert_eq!(r.status, 503, "{}", r.text());
    assert_eq!(r.header("retry-after"), Some("15"));
    r.assert_hardened("503");
    assert_eq!(p.get("").status, 200, "the pages still answer");
    let t0 = Instant::now();
    assert_eq!(p.stop().0, Some(0));
    assert!(t0.elapsed() < Duration::from_secs(10), "the stop ended the open streams: {:?}", t0.elapsed());
    drop(streams);
}

// ---- the actions -----------------------------------------------------------------------------

/// The audit rows of `vm` (its `id`): each event and its detail but `actor` and `id`, and the actors.
fn vm_rows(w: &World, vm: &str) -> (Vec<(String, Value)>, Vec<String>) {
    let rows: Vec<Value> = w.audit().into_iter().filter(|r| r["detail"]["id"] == vm && r["event"] != "vm_run").collect();
    let shapes = rows
        .iter()
        .map(|r| {
            let mut d = r["detail"].as_object().cloned().unwrap_or_default();
            d.remove("actor");
            d.remove("id");
            (r["event"].as_str().unwrap_or_default().to_string(), Value::Object(d))
        })
        .collect();
    (shapes, rows.iter().map(|r| r["detail"]["actor"].as_str().unwrap_or("-").to_string()).collect())
}

/// Suspend and resume through the panel and through the CLI, each on its own VM: the same lines, the same
/// row changes, and the same audit rows but `actor` (`panel`, `cli`).
#[test]
fn actions_equal_cli_on_fake_api() {
    let w = World::new();
    let (a, b) = (w.vm(&[]), w.vm(&[]));
    assert_ne!(a, b);
    let p = w.serve(&[]);
    let (_, suspended) = p.act("vm-suspend", &a);
    let (_, resumed) = p.act("vm-resume", &a);
    let (code, _, err) = p.stop();
    assert_eq!(code, Some(0), "{err}");
    let cli_suspend = w.run(&["vm", "suspend", &b]);
    let cli_resume = w.run(&["vm", "resume", &b]);
    assert_eq!((cli_suspend.status.code(), cli_resume.status.code()), (Some(0), Some(0)), "{}{}", stderr_of(&cli_suspend), stderr_of(&cli_resume));
    let line = |o: &Output| String::from_utf8_lossy(&o.stdout).trim_end().to_string();
    let shape = |l: &str, id: &str| l.replace(id, "<vm>").split(" in ").next().unwrap_or_default().to_string();
    for (doc, o, want) in [(&suspended, &cli_suspend, "<vm> SUSPENDED"), (&resumed, &cli_resume, "<vm> RUNNING")] {
        assert_eq!((doc["state"].as_str(), doc["code"].as_i64()), (Some("done"), Some(0)), "{doc}");
        assert_eq!(shape(doc["line"].as_str().unwrap(), &a), shape(&line(o), &b), "the CLI's line: {doc}");
        assert_eq!(shape(&line(o), &b), want);
    }
    let (ra, rb) = (w.vm_row(&a), w.vm_row(&b));
    for key in ["status", "state_seen"] {
        assert_eq!(ra.get(key), rb.get(key), "{key}: {ra:?} / {rb:?}");
    }
    assert_eq!(ra.get("state_seen").and_then(toml::Value::as_str), Some("RUNNING"));
    let ((shape_a, actors_a), (shape_b, actors_b)) = (vm_rows(&w, &a), vm_rows(&w, &b));
    assert_eq!(shape_a, shape_b, "the same rows but actor");
    let moves: Vec<&str> = shape_a.iter().map(|(e, _)| e.as_str()).filter(|e| e.starts_with("vm_suspend") || e.starts_with("vm_resume")).collect();
    assert_eq!(moves, ["vm_suspend", "vm_resume"], "{shape_a:?}");
    assert!(actors_a.iter().all(|x| x == "panel") && actors_b.iter().all(|x| x == "cli"), "{actors_a:?} {actors_b:?}");
}

/// One action at a time: a second POST while one runs is 409 naming it, and leaves its nonce unused.
#[test]
fn one_action_at_a_time_409() {
    let w = World::new();
    let (a, b) = (w.vm(&[]), w.vm(&[]));
    w.update_fake(|s| s.park_get_ms = 3000);
    let p = w.serve(&[]);
    let first = p.nonce("vm-suspend", &a);
    let second = p.nonce("vm-suspend", &b);
    assert_eq!(p.post_action(&first, "vm-suspend", &a).status, 303);
    let r = p.post_action(&second, "vm-suspend", &b);
    assert_eq!(r.status, 409, "{}", r.text());
    assert!(r.text().starts_with(&format!("an action is running: vm-suspend {a} since ")) && r.text().contains("(it has its own page)"), "{}", r.text());
    r.assert_hardened("409");
    let running = p.get(&format!("actions/{first}?json=1")).json();
    assert!(running["state"] == "running" || running["state"] == "queued", "{running}");
    assert_eq!(p.wait_action(&first)["state"], "done");
    let r = p.post_action(&second, "vm-suspend", &b);
    assert_eq!(r.status, 303, "the 409 left the nonce unused: {}", r.text());
    assert_eq!(p.wait_action(&second)["state"], "done");
    assert_eq!(p.stop().0, Some(0));
}

/// A nonce runs once, only for its action and target; an unknown one is 403.
#[test]
fn nonce_single_use() {
    let w = World::new();
    let (a, b) = (w.vm(&[]), w.vm(&[]));
    let p = w.serve(&[]);
    let n = p.nonce("vm-suspend", &a);
    assert_eq!(p.post_action(&n, "vm-suspend", &b).status, 403, "another target");
    assert_eq!(p.post_action(&n, "vm-resume", &a).status, 403, "another action");
    assert_eq!(p.post_action("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", "vm-suspend", &a).status, 403, "never issued");
    assert_eq!(p.post_action(&n, "vm-suspend", &a).status, 303);
    assert_eq!(p.wait_action(&n)["state"], "done");
    let again = p.post_action(&n, "vm-suspend", &a);
    assert_eq!(again.status, 403, "used: {}", again.text());
    // HEAD on confirm issues none: its page has no form.
    let head = p.request("HEAD", &p.path(&format!("confirm?action=vm-resume&target={a}")), &[], b"");
    assert_eq!((head.status, head.body.len()), (200, 0));
    for bad in ["nonce=x&action=vm-suspend", "nonce=x&action=vm-suspend&target=y&more=z", "nonce=x&action=vm-reboot&target=y", "nonce=&action=vm-suspend&target=y"] {
        assert_eq!(p.post(bad).status, 400, "{bad}");
    }
    assert_eq!(p.stop().0, Some(0));
}

/// Each action's confirm page and status page name its CLI twin.
#[test]
fn every_action_names_its_cli_twin() {
    let w = World::new();
    let vm = w.vm(&[]);
    w.session(SID, "remote", Some(&vm), "remote", "/w/remote");
    let p = w.serve(&[]);
    for (action, target, twin) in [
        ("vm-suspend", vm.as_str(), format!("ai-env vm suspend {vm}")),
        ("vm-resume", vm.as_str(), format!("ai-env vm resume {vm}")),
        ("vm-terminate", vm.as_str(), format!("ai-env vm terminate {vm}")),
        ("vm-refresh", "-", "ai-env vm list".to_string()),
        ("session-migrate", SID, format!("ai-env session migrate {SID}")),
    ] {
        let doc = p.get(&format!("confirm?action={action}&target={target}&json=1")).json();
        assert_eq!((doc["action"].as_str(), doc["target"].as_str(), doc["twin"].as_str()), (Some(action), Some(target), Some(twin.as_str())), "{doc}");
        assert!(doc["touch_ids"].as_str().is_some_and(|t| t.contains("Touch ID")), "{doc}");
        let page = p.get(&format!("confirm?action={action}&target={target}")).text();
        assert!(page.contains(&format!("<code>{twin}</code>")), "{page}");
        if action == "vm-terminate" {
            assert_eq!(doc["chats"], serde_json::json!([]), "a closed chat is no chat on it: {doc}");
        }
    }
    let (nonce, done) = p.act("vm-refresh", "-");
    assert_eq!((done["twin"].as_str(), done["state"].as_str(), done["id"].as_str()), (Some("ai-env vm list"), Some("done"), Some(nonce.as_str())), "{done}");
    let page = p.get(&format!("actions/{nonce}")).text();
    assert!(page.contains("<code>ai-env vm list</code>") && page.contains(&format!("data-action=\"{nonce}\"")) && page.contains("<body data-root=\"../\""), "{page}");
    assert_eq!(p.stop().0, Some(0));
}

/// Each page's `?json=1` is its CLI twin's document. (`session show`, `audit tail` and `cost` are B2's:
/// green at I1.)
#[test]
fn models_equal_cli_json() {
    let w = World::new();
    let vm = w.vm(&[]);
    w.session(SID, "remote", Some(&vm), "remote", "/w/remote");
    w.session(SID_LOCAL, "local-child", None, "local", "/w/local");
    plant_captures(&w, SID, "Bash(git status)");
    // P-1: a detail value holding a raw C1 (U+009B, a terminal's CSI) and a DEL, which a JSON line may hold raw.
    w.append_audit("vm_run", serde_json::json!({"actor": "cli", "id": vm, "purpose": "csi\u{9b}31m del\u{7f} end"}));
    let p = w.serve(&[]);
    let cli = |args: &[&str]| {
        let o = w.run(args);
        assert_eq!(o.status.code(), Some(0), "{args:?}: {}", stderr_of(&o));
        o.stdout
    };
    let doc = |rel: &str| {
        let r = p.get(rel);
        assert_eq!(r.status, 200, "{rel}: {}", r.text());
        r
    };
    let json = |b: &[u8]| -> Value { serde_json::from_slice(b).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(b))) };
    assert_eq!(doc("?json=1").header("content-type"), Some("application/json"));
    assert_eq!(doc("?json=1").json(), json(&cli(&["session", "list", "--json"])), "session list --json");
    let panel_diff = doc(&format!("settings/{SID}?json=1")).json();
    assert!(!w.bridge().join("quarantine").join(SID).join("settings").join("diff.json").exists());
    assert_eq!(panel_diff, json(&cli(&["session", "show", SID, "--settings-diff", "--json"])), "session show --settings-diff --json");
    let vms = doc("vms?json=1").json();
    assert_eq!(vms["backend"], "registry");
    assert_eq!(vms["vms"].as_array().map(|v| v.iter().map(|i| i["id"].clone()).collect::<Vec<_>>()), Some(vec![Value::String(vm.clone())]), "{vms}");
    let token = w.vm_row(&vm).get("session_token").and_then(toml::Value::as_str).expect("the row's session token").to_string();
    assert!(!vms.to_string().contains("session_token") && !vms.to_string().contains(&token), "{vms}");
    // B2's documents (green at I1).
    assert_eq!(doc(&format!("session/{SID}?json=1")).json(), json(&cli(&["session", "show", SID, "--json"])), "session show --json");
    let audit = doc("audit?json=1&event=vm_run");
    assert_eq!(audit.header("content-type"), Some("application/x-ndjson"));
    assert_eq!(audit.text(), String::from_utf8_lossy(&cli(&["audit", "tail", "-n", "200", "--event", "vm_run", "--json"])), "audit tail --json");
    // Both documents carry the C1 and the DEL as their escapes, never raw.
    let text = audit.text();
    assert!(text.contains("csi\\u009b31m del\\u007f end") && !text.contains(['\u{9b}', '\u{7f}']), "{text}");
    assert_eq!(doc("audit?json=1").text(), String::from_utf8_lossy(&cli(&["audit", "tail", "-n", "200", "--json"])));
    assert_eq!(doc("cost?since=24h&json=1").json(), json(&cli(&["cost", "--since", "24h", "--json"])), "cost --json");
    assert_eq!(p.stop().0, Some(0));
}
