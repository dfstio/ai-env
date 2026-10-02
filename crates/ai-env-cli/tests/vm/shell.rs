//! The `vm shell` pump over loopback (plan S4 D11): a plain-TCP WebSocket
//! server built here (the TLS dial lives in `bridge::transport`; `src/`
//! has no plaintext client), the pump generic over the stream. Bytes typed go
//! out as binary frames, binary and text frames come back to the output, a
//! remote close ends the session, the escape byte quits, and after input EOF
//! replies are still printed until the remote closes or stays quiet.
//!
//! S5, the scripted shell (`run_script_over`): the script goes out as one
//! frame; the output comes back until the remote closes or the budget
//! passes; the marker parser ignores the shell's echo of the script. The
//! rendered `egress check` and dns-path scripts also run for real in
//! /bin/bash behind the loopback server, with fake `curl` and `dig` on a
//! pinned PATH (no network), modelling a closed VPC, a leaky one, a dead
//! proxy, and platform DNS.
use ai_env_cli::bridge::egress::check::{dns_path_outcome, judge, parse_markers, render_dns_script, render_script, Verdict, CASES};
use ai_env_cli::bridge::egress::PROXY_IP;
use ai_env_cli::bridge::vm::shell::{pump, run_script_over, session_init_id, PumpEnd, ESCAPE, SCRIPT_OUTPUT_MAX};
use futures_util::{SinkExt, StreamExt};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::Message;

/// A server that first sends `greeting` (a text frame, as the platform's
/// `session_init`), then answers every binary frame with `echo:<bytes>` as a
/// text frame and closes after `close_after` frames; the client side is the pump.
async fn session(input: &'static [u8], escape: Option<u8>, close_after: usize, linger: Duration, greeting: Option<&'static str>) -> (PumpEnd, Vec<u8>, Vec<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        if let Some(g) = greeting {
            ws.send(Message::Text(g.into())).await.unwrap();
        }
        let mut got = Vec::new();
        while let Some(Ok(msg)) = ws.next().await {
            match msg {
                Message::Binary(b) => {
                    got.push(b.to_vec());
                    ws.send(Message::Text(format!("echo:{}", String::from_utf8_lossy(&b)).into())).await.unwrap();
                    if got.len() == close_after {
                        let _ = ws.close(None).await;
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        got
    });
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}/shell"), tcp).await.unwrap();
    let (out_w, mut out_r) = tokio::io::duplex(64 * 1024);
    let end = pump(ws, input, out_w, escape, linger).await.unwrap();
    let mut out = Vec::new();
    out_r.read_to_end(&mut out).await.unwrap();
    (end, out, server.await.unwrap())
}

#[tokio::test]
async fn pump_sends_binary_and_prints_replies_until_the_remote_closes() {
    // The remote closes: the linger never elapses (a long one makes the test independent of timing).
    let (end, out, got) = session(b"uname -a\n", None, 1, Duration::from_secs(10), None).await;
    assert_eq!(end, PumpEnd::RemoteClosed);
    assert_eq!(got, vec![b"uname -a\n".to_vec()]);
    assert_eq!(String::from_utf8(out).unwrap(), "echo:uname -a\n");
}

#[tokio::test]
async fn pump_quits_on_the_escape_byte_after_sending_what_came_before_it() {
    let input: &'static [u8] = &[b'l', b's', ESCAPE, b'x'];
    let (end, _out, got) = session(input, Some(ESCAPE), 99, Duration::from_secs(10), None).await;
    assert_eq!(end, PumpEnd::Escaped);
    assert_eq!(got, vec![b"ls".to_vec()], "the escape byte and what follows are never sent");
}

#[tokio::test]
async fn pump_closes_after_input_eof_once_the_remote_is_quiet() {
    // The remote never closes: the session ends by the linger (1 s is ample for a loopback echo).
    let (end, out, got) = session(b"ls\n", None, 99, Duration::from_secs(1), None).await;
    assert_eq!(end, PumpEnd::InputEof);
    assert_eq!(got, vec![b"ls\n".to_vec()]);
    assert_eq!(String::from_utf8(out).unwrap(), "echo:ls\n", "the reply after EOF is still printed");
}

#[tokio::test]
async fn pump_reports_the_platform_session_init_instead_of_printing_it() {
    // Live (30 Sep 2026): the platform's first frame is this text frame; the shell output follows.
    let init = r#"{"type":"session_init","session_id":"31de9f8c-8de9-4fa4-ad4e-e21b03779af9"}"#;
    let (end, out, _) = session(b"ls\n", None, 1, Duration::from_secs(10), Some(init)).await;
    assert_eq!(end, PumpEnd::RemoteClosed);
    assert_eq!(String::from_utf8(out).unwrap(), "echo:ls\n", "the session_init frame never reaches the terminal");
}

// ---- the scripted shell (S5) ------------------------------------------------------------------

const NONCE: &str = "00c0ffee12345678";

/// What a loopback shell answers to the script it received.
type Responder = Box<dyn FnOnce(Vec<u8>) -> Vec<Message> + Send>;

/// One scripted session over loopback: the server takes the script (one
/// binary frame), sends what `respond` makes of it (computed on the blocking
/// pool: it may run bash), then closes — or, with `close` false, stays
/// silent until the client closes. Returns the client's output, how long
/// `run_script_over` took, and the script the server received.
async fn scripted(script: &str, budget: Duration, close: bool, respond: Responder) -> (String, Duration, Vec<u8>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let got = loop {
            match ws.next().await {
                Some(Ok(Message::Binary(b))) => break b.to_vec(),
                Some(Ok(_)) => continue,
                _ => return Vec::new(),
            }
        };
        let input = got.clone();
        let frames = tokio::task::spawn_blocking(move || respond(input)).await.unwrap();
        for f in frames {
            if ws.send(f).await.is_err() {
                return got;
            }
        }
        if close {
            let _ = ws.close(None).await;
        } else {
            while let Some(Ok(m)) = ws.next().await {
                if m.is_close() {
                    break;
                }
            }
        }
        got
    });
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr)).await.unwrap().unwrap();
    let (ws, _) = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::client_async(format!("ws://{addr}/shell"), tcp)).await.unwrap().unwrap();
    let t = Instant::now();
    let out = tokio::time::timeout(Duration::from_secs(120), run_script_over(ws, script, budget)).await.expect("run_script_over is bounded").unwrap();
    let took = t.elapsed();
    let got = tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap();
    (out, took, got)
}

/// The shell's echo of `script` as a terminal returns it (prompt, CRLF).
fn echo(script: &[u8]) -> Message {
    let text: String = String::from_utf8_lossy(script).lines().map(|l| format!("bash-5.2# {l}\r\n")).collect();
    Message::Text(text.into())
}

/// Every case's marker in a closed, working VPC.
fn passing_markers() -> String {
    let mut out = String::new();
    for c in &CASES {
        let line = match c.name {
            "allowed" | "allowed-last" => "rc=0 code=401 size=86 conn=1 hc=200 t403=no sq=no".to_string(),
            "direct-name" => "rc=6 code=000 size=0 conn=0 hc=000 t403=no sq=no".to_string(),
            "direct-ipv4" | "direct-http" | "proxy-other-port" => "rc=28 code=000 size=0 conn=0 hc=000 t403=no sq=no".to_string(),
            "direct-ipv6" => "rc=7 code=000 size=0 conn=0 hc=000 t403=no sq=no".to_string(),
            "imds" | "imds-v6" => "rc=0 code=401 size=0 conn=1 hc=000 t403=no sq=no".to_string(),
            "proxy-http-8080" => "rc=0 code=403 size=3900 conn=1 hc=000 t403=no sq=yes".to_string(),
            n if n.starts_with("proxy-") || n == "denied" => "rc=56 code=000 size=0 conn=1 hc=403 t403=yes sq=no".to_string(),
            n if n.starts_with("dns-public") => format!("rc=9 ns={} res=no st=none ra=none", if n == "dns-public-port" { "208.67.222.222" } else { "1.1.1.1" }),
            n if n.starts_with("dns-platform6") => "rc=9 ns=fd00:ec2::253 res=no st=none ra=none".to_string(),
            n if n.starts_with("dns-") => "rc=9 ns=10.42.0.2 res=no st=none ra=none".to_string(),
            other => panic!("no marker for {other}"),
        };
        out.push_str(&format!("@@AIENV{NONCE} {} {line}\r\n", c.name));
    }
    out.push_str(&format!("@@AIENV{NONCE} end\r\n"));
    out
}

#[tokio::test]
async fn run_script_returns_the_markers_and_the_echo_never_parses() {
    let script = render_script(NONCE, PROXY_IP);
    let init = r#"{"type":"session_init","session_id":"31de9f8c-8de9-4fa4-ad4e-e21b03779af9"}"#;
    let respond: Responder = Box::new(move |got| {
        // The markers arrive split across frames, mid-line, as a terminal delivers them.
        let markers = passing_markers().into_bytes();
        let (a, b) = markers.split_at(markers.len() / 2 + 7);
        vec![Message::Text(init.into()), echo(&got), Message::Binary(a.to_vec().into()), Message::Binary(b.to_vec().into()), Message::Text("bash-5.2# exit\r\n".into())]
    });
    let (out, took, got) = scripted(&script, Duration::from_secs(30), true, respond).await;
    assert_eq!(got, script.as_bytes(), "the script goes out as one frame, as rendered");
    assert!(took < Duration::from_secs(10), "the close ends the session early: {took:?}");
    assert!(!out.contains("session_init"), "the platform's session_init frame is not output");
    assert!(out.contains("bash-5.2# aienv_c allowed https://api.anthropic.com/v1/models"), "the echo is in the output");
    let m = parse_markers(&out, NONCE).unwrap();
    assert_eq!(m.cases.len(), CASES.len());
    assert!(m.finished);
    let j = judge(&m);
    assert!(j.passed(), "{:?}", j.failures());
    // The echo alone (a session cut before any case ran) parses as nothing.
    let echo_only: Responder = Box::new(|got| vec![echo(&got)]);
    let (out, _, _) = scripted(&script, Duration::from_secs(30), true, echo_only).await;
    let m = parse_markers(&out, NONCE).unwrap();
    assert!(m.cases.is_empty() && !m.finished, "{m:?}");
    assert!(!judge(&m).passed());
}

#[tokio::test]
async fn a_silent_session_ends_at_the_budget() {
    let script = render_script(NONCE, PROXY_IP);
    let silent: Responder = Box::new(|_| vec![Message::Text("bash-5.2# ".into())]);
    let budget = Duration::from_millis(400);
    let (out, took, _) = scripted(&script, budget, false, silent).await;
    assert!(took >= budget && took < Duration::from_secs(10), "{took:?}");
    assert_eq!(out, "bash-5.2# ");
    assert!(!parse_markers(&out, NONCE).unwrap().finished);
}

#[tokio::test]
async fn a_close_ends_the_session_and_the_output_is_capped() {
    let script = "exit\n";
    let flood: Responder = Box::new(|_| (0..40).map(|_| Message::Binary(vec![b'x'; 64 * 1024].into())).collect());
    let (out, took, _) = scripted(script, Duration::from_secs(60), true, flood).await;
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert_eq!(out.len(), SCRIPT_OUTPUT_MAX, "2.5 MiB sent, 1 MiB kept");
    let nothing: Responder = Box::new(|_| Vec::new());
    let (out, took, _) = scripted(script, Duration::from_secs(60), true, nothing).await;
    assert!(out.is_empty() && took < Duration::from_secs(10), "{took:?}");
}

/// A fake `curl` for the rendered script: no network, the `-w` variables
/// filled. Without the proxy, names do not resolve, IPv6 is unreachable,
/// IMDS answers 401, the proxy's own port answers squid's 400 (the script's
/// wait for the proxy), everything else times out without a connection
/// (`FAKE_WORLD=leaky`: 1.1.1.1:443 answers; `hang`: it connects, then
/// times out); through the proxy, the allowlisted API answers 401 in a
/// tunnel (CONNECT 200), a plain-http request gets squid's 403 page with
/// `X-Squid-Error`, any other CONNECT the proxy's 403 and curl's text
/// (`dead`: the proxy refuses connections; `dies`: after the first request;
/// `late`: the VM reaches nothing for its first 3 connection attempts, as
/// measured live 1 Oct 2026).
const FAKE_CURL: &str = r#"#!/bin/sh
fmt=; url=; noproxy=0; prev=
for a in "$@"; do
  case "$prev" in -w) fmt=$a ;; --noproxy) noproxy=1 ;; esac
  case "$a" in http://*|https://*) url=$a ;; esac
  prev=$a
done
case "$url" in https://*) proxy=${https_proxy:-} ;; *) proxy=${http_proxy:-} ;; esac
[ "$noproxy" = 1 ] && proxy=
code=000; size=0; conn=0; hc=000; xse=; rc=0; err=
world=${FAKE_WORLD:-closed}
if [ "$world" = late ]; then
  tries=$(( $(cat "$HOME/net-tries" 2>/dev/null || echo 0) + 1 ))
  echo "$tries" > "$HOME/net-tries"
  if [ "$tries" -le 3 ]; then
    printf '%s' "$fmt" | sed -e "s/%{http_code}/000/" -e "s/%{size_download}/0/" -e "s/%{num_connects}/0/" -e "s/%{http_connect}/000/" -e "s/%header{x-squid-error}//"
    printf 'curl: (7) Failed to connect: Network is unreachable\n' >&2
    exit 7
  fi
fi
if [ -z "$proxy" ]; then
  case "$url" in
    http://10.42.0.10:3128/)
      if [ "$world" = dead ]; then rc=7; err="Failed to connect to 10.42.0.10 port 3128: Connection refused"; else code=400; size=3500; conn=1; fi ;;
    https://api.anthropic.com/*) rc=6; err="Could not resolve host: api.anthropic.com" ;;
    https://1.1.1.1/)
      case "$world" in
        leaky) code=200; size=1234; conn=1 ;;
        hang) rc=28; conn=1; err="SSL connection timeout" ;;
        *) rc=28; err="Connection timed out after 5002 milliseconds" ;;
      esac ;;
    https://\[*) rc=7; err="Failed to connect: Network is unreachable" ;;
    http://169.254.169.254/*|http://\[fd00:ec2::254\]/*) code=401; conn=1 ;;
    *) rc=28; err="Connection timed out after 5001 milliseconds" ;;
  esac
else
  calls=$(( $(cat "$HOME/proxy-calls" 2>/dev/null || echo 0) + 1 ))
  echo "$calls" > "$HOME/proxy-calls"
  if [ "$world" = dead ] || { [ "$world" = dies ] && [ "$calls" -gt 1 ]; }; then
    rc=7; err="Failed to connect to the proxy: Connection refused"
  else
    conn=1
    case "$url" in
      https://api.anthropic.com/v1/models) code=401; size=86; hc=200 ;;
      http://*) code=403; size=3900; xse="ERR_ACCESS_DENIED 0" ;;
      *) rc=56; hc=403; err="CONNECT tunnel failed, response 403" ;;
    esac
  fi
fi
printf '%s' "$fmt" | sed -e "s/%{http_code}/$code/" -e "s/%{size_download}/$size/" -e "s/%{num_connects}/$conn/" -e "s/%{http_connect}/$hc/" -e "s/%header{x-squid-error}/$xse/"
[ -n "$err" ] && printf 'curl: (%s) %s\n' "$rc" "$err" >&2
exit "$rc"
"#;

/// A fake `dig` printing what `+noall +comments +answer` prints: no server
/// replies (dig's own error lines, which name the server, then exit 9)
/// unless `FAKE_DNS_REPLY` names it (exit 0: a header with its status, the
/// flags line, `ra` among them with `FAKE_DNS_RA=1`; with
/// `FAKE_DNS_RESOLVES=1` status NOERROR and an answer, else
/// `FAKE_DNS_STATUS`, REFUSED by default); `FAKE_DNS_TRUNCATE` names a
/// server whose UDP reply comes truncated and whose TCP retry fails (exit 9).
const FAKE_DIG: &str = r#"#!/bin/sh
server=
for a in "$@"; do case "$a" in @*) server=${a#@} ;; esac; done
if [ -n "${FAKE_DNS_TRUNCATE:-}" ] && [ "$server" = "$FAKE_DNS_TRUNCATE" ]; then
  echo ";; Truncated, retrying in TCP mode."
  echo ";; Connection to $server#53($server) for example.com failed: connection refused."
  echo ";; no servers could be reached"
  exit 9
fi
if [ -n "${FAKE_DNS_REPLY:-}" ] && [ "$server" = "$FAKE_DNS_REPLY" ]; then
  st=${FAKE_DNS_STATUS:-REFUSED}; [ "${FAKE_DNS_RESOLVES:-0}" = 1 ] && st=NOERROR
  ra=; [ "${FAKE_DNS_RA:-0}" = 1 ] && ra=' ra'
  echo ";; Got answer:"
  echo ";; ->>HEADER<<- opcode: QUERY, status: $st, id: 4242"
  echo ";; flags: qr rd$ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1"
  echo
  [ "${FAKE_DNS_RESOLVES:-0}" = 1 ] && printf 'example.com.\t\t300\tIN\tA\t93.184.215.14\n'
  exit 0
fi
echo ";; communications error to $server#53: timed out"
echo ";; no servers could be reached"
exit 9
"#;

/// Run `script` in /bin/bash (no rc files, a clean environment, the fakes
/// first on PATH, `/etc/resolv.conf` replaced by `resolv`), killed after 60 s.
fn run_bash(dir: &Path, script: &[u8], resolv: &str, env: &[(&str, &str)]) -> String {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for (name, body) in [("curl", FAKE_CURL), ("dig", FAKE_DIG), ("sleep", "#!/bin/sh\nexit 0\n")] {
        std::fs::write(bin.join(name), body).unwrap();
        std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let conf = dir.join("resolv.conf");
    std::fs::write(&conf, resolv).unwrap();
    let script = String::from_utf8_lossy(script).replace("/etc/resolv.conf", &conf.display().to_string());
    let mut c = std::process::Command::new("/bin/bash");
    c.args(["--norc", "--noprofile"]).env_clear().env("PATH", format!("{}:/usr/bin:/bin", bin.display())).env("HOME", dir).env("LC_ALL", "C");
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let _ = child.stdin.take().unwrap().write_all(script.as_bytes());
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let out = match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(out) => out.unwrap(),
        Err(_) => {
            let _ = std::process::Command::new("/bin/kill").args(["-9", &pid.to_string()]).status();
            panic!("bash did not finish within 60 s");
        }
    };
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// The rendered script through the loopback shell, run by bash in `world`'s
/// environment: the echo, then whatever bash printed.
async fn through_bash(script: String, resolv: &'static str, env: &'static [(&'static str, &'static str)]) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let respond: Responder = Box::new(move |got| {
        let printed = run_bash(&path, &got, resolv, env);
        vec![echo(&got), Message::Binary(printed.into_bytes().into())]
    });
    let (out, _, _) = scripted(&script, Duration::from_secs(90), true, respond).await;
    drop(dir);
    out
}

fn failing(j: &ai_env_cli::bridge::egress::check::Judgement) -> Vec<&'static str> {
    j.cases.iter().filter(|c| c.verdict == Verdict::Fail).map(|c| c.name).collect()
}

#[tokio::test]
async fn the_egress_check_script_runs_in_bash_and_is_judged() {
    let resolv = "# platform\nnameserver 10.42.0.2\nnameserver 10.42.0.3\n";
    let run = |resolv: &'static str, env: &'static [(&'static str, &'static str)]| through_bash(render_script(NONCE, PROXY_IP), resolv, env);
    // A closed VPC with a working proxy: every case passes, no DNS server replies.
    let out = run(resolv, &[]).await;
    let m = parse_markers(&out, NONCE).unwrap_or_else(|e| panic!("{e}"));
    assert!(m.finished && m.cases.len() == CASES.len(), "{m:?}");
    assert_eq!(m.get("dns-resolv-udp").unwrap().ns.as_deref(), Some("10.42.0.2"), "the first resolv.conf nameserver");
    assert_eq!(m.get("dns-subnet-tcp").unwrap().ns.as_deref(), Some("10.42.1.2"));
    assert_eq!(m.get("dns-public-port").unwrap().ns.as_deref(), Some("208.67.222.222"));
    let denied = m.get("denied").unwrap();
    assert_eq!((denied.t403, denied.hc, denied.conn), (Some(true), Some(403), Some(1)), "the proxy's CONNECT 403 and curl's text, not its exit code");
    let get = m.get("proxy-http-8080").unwrap();
    assert_eq!((get.code, get.sq), (Some(403), Some(true)), "squid's error header, reduced to yes in the VM");
    assert_eq!((m.get("allowed").unwrap().hc, m.get("allowed-last").unwrap().code), (Some(200), Some(401)));
    assert_eq!(m.get("direct-ipv4").unwrap().conn, Some(0));
    let j = judge(&m);
    assert!(j.passed(), "{:?}", j.failures());
    assert_eq!(j.dns, "no-dns");
    assert!(!out.contains("93.184.215.14") && !out.contains("communications error") && !out.contains("ERR_ACCESS_DENIED 0") && !out.contains("CONNECT tunnel failed, response 403\n"), "what dig and curl saw never leaves the VM's shell variables");
    // Direct egress to 1.1.1.1 answers, or connects and hangs (curl exit 28 after a connection): OPEN.
    const LEAKY: &[(&str, &str)] = &[("FAKE_WORLD", "leaky")];
    const HANG: &[(&str, &str)] = &[("FAKE_WORLD", "hang")];
    for world in [LEAKY, HANG] {
        let j = judge(&parse_markers(&run(resolv, world).await, NONCE).unwrap());
        assert_eq!(failing(&j), ["direct-ipv4"], "{world:?}: {:?}", j.failures());
        assert!(j.cases.iter().find(|c| c.name == "direct-ipv4").unwrap().reason.starts_with("OPEN"), "{world:?}");
    }
    // The proxy does not answer: allowed fails, and nothing the dead network "closed" counts.
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_WORLD", "dead")]).await, NONCE).unwrap());
    assert!(!j.passed());
    let f = |j: &ai_env_cli::bridge::egress::check::Judgement, n: &str| j.cases.iter().find(|c| c.name == n).unwrap().clone();
    assert!(f(&j, "allowed").reason.contains("did not answer") && f(&j, "allowed").reason.contains("never opened a connection to the proxy's port"), "{}", f(&j, "allowed").reason);
    assert_eq!(j.ready.map(|w| (w.tries, w.ok)), Some((30, false)), "the wait gave up after its attempts");
    assert!(f(&j, "direct-name").reason.contains("not counted") && f(&j, "dns-platform-udp").reason.contains("not counted"));
    assert!(f(&j, "denied").reason.contains("no 403"), "{}", f(&j, "denied").reason);
    assert_eq!(f(&j, "imds").verdict, Verdict::Recorded);
    // The proxy dies after the first request: allowed passed, allowed-last did not — the run is void all the same.
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_WORLD", "dies")]).await, NONCE).unwrap());
    assert_eq!(f(&j, "allowed").verdict, Verdict::Pass);
    assert_eq!(f(&j, "allowed-last").verdict, Verdict::Fail);
    assert!(f(&j, "direct-ipv6").reason.contains("not counted"), "{}", f(&j, "direct-ipv6").reason);
    // The VM's network comes up late (measured live 1 Oct 2026: the first allowed could not connect at all): the
    // script waits for the proxy's port, then every case passes and the run says how long it waited.
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_WORLD", "late")]).await, NONCE).unwrap());
    assert!(j.passed(), "{:?}", j.failures());
    assert_eq!(j.ready.map(|w| (w.tries, w.ok)), Some((4, true)), "three attempts reached nothing, the fourth the proxy");
    // Without the wait the same world fails the way the live run did.
    let unwaited = render_script(NONCE, PROXY_IP).replace("aienv_r 10.42.0.10:3128\n", "");
    let j = judge(&parse_markers(&through_bash(unwaited, resolv, &[("FAKE_WORLD", "late")]).await, NONCE).unwrap());
    assert!(f(&j, "allowed").reason.contains("did not answer") && f(&j, "direct-name").reason.contains("not counted") && f(&j, "allowed-last").verdict == Verdict::Pass, "{:?}", j.failures());
    // The platform resolver resolves: those cases fail; DNS Firewall (a reply, no address) passes.
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_DNS_REPLY", "169.254.169.253"), ("FAKE_DNS_RESOLVES", "1")]).await, NONCE).unwrap());
    assert_eq!(failing(&j), ["dns-platform-udp", "dns-platform-tcp"], "{:?}", j.failures());
    assert_eq!(j.dns, "platform-dns-resolves:169.254.169.253", "a resolving platform resolver is never plain platform-dns");
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_DNS_REPLY", "169.254.169.253")]).await, NONCE).unwrap());
    assert!(j.passed(), "{:?}", j.failures());
    assert_eq!(j.dns, "platform-dns:169.254.169.253");
    assert!(f(&j, "dns-platform-udp").reason.starts_with("169.254.169.253 replied (status REFUSED, no recursion) and resolved nothing"), "{}", f(&j, "dns-platform-udp").reason);
    // A truncated UDP reply whose TCP retry fails comes through as TRUNCATED: a public resolver that did so is open.
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_DNS_TRUNCATE", "1.1.1.1")]).await, NONCE).unwrap());
    assert_eq!(failing(&j), ["dns-public-udp", "dns-public-tcp"], "{:?}", j.failures());
    assert_eq!(j.dns, "open-dns:1.1.1.1");
    // The dead world's wait printed a dot per failed attempt before its marker (the shell is never silent for a minute).
    assert!(run(resolv, &[("FAKE_WORLD", "dead")]).await.contains(&format!("{}@@AIENV{NONCE} ready try=30", ".".repeat(30))));
    // dig's status and the recursion flag come through the VM's shell variables.
    let m = parse_markers(&run(resolv, &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_STATUS", "SERVFAIL"), ("FAKE_DNS_RA", "1")]).await, NONCE).unwrap();
    let r = m.get("dns-platform6-tcp").unwrap();
    assert_eq!((r.rc, r.resolves, r.status.as_deref(), r.ra), (Some(0), Some(false), Some("SERVFAIL"), Some(true)));
    assert_eq!(m.get("dns-platform-udp").unwrap().status, None, "no reply, no status");
    let m = parse_markers(&run(resolv, &[("FAKE_DNS_REPLY", "169.254.169.253"), ("FAKE_DNS_RESOLVES", "1"), ("FAKE_DNS_RA", "1")]).await, NONCE).unwrap();
    let r = m.get("dns-platform-udp").unwrap();
    assert_eq!((r.resolves, r.status.as_deref(), r.ra), (Some(true), Some("NOERROR"), Some(true)), "an answer line is an address");
    // OpenDNS answering on UDP 443: open.
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_DNS_REPLY", "208.67.222.222")]).await, NONCE).unwrap());
    assert_eq!(failing(&j), ["dns-public-port"], "{:?}", j.failures());
    assert_eq!(j.dns, "open-dns:208.67.222.222");
    // A public resolv.conf nameserver must not reply; none at all is not asked.
    let j = judge(&parse_markers(&run("nameserver 9.9.9.9\n", &[("FAKE_DNS_REPLY", "9.9.9.9")]).await, NONCE).unwrap());
    assert_eq!(failing(&j), ["dns-resolv-udp", "dns-resolv-tcp"], "{:?}", j.failures());
    let m = parse_markers(&run("# empty\n", &[]).await, NONCE).unwrap();
    assert_eq!((m.get("dns-resolv-udp").unwrap().rc, m.get("dns-resolv-udp").unwrap().ns.clone()), (None, None));
    assert!(judge(&m).passed());
}

/// The script drops aliases and functions named like its tools (`curl`,
/// `dig`, `command`, `printf`) before it runs them — and without either
/// half of its first line (`\unalias -a`, `unset -f …`) the same tampered
/// shell fools it, so the test is not vacuous.
#[tokio::test]
async fn the_script_runs_the_tools_not_aliases_or_functions() {
    let tamper = "shopt -s expand_aliases\ncurl() { echo fake; }; dig() { echo 1.2.3.4; }; command() { echo fake; }; printf() { echo fake; }\nalias curl='echo fake' dig='echo 1.2.3.4' command='echo fake' printf='echo fake'\n";
    let script = render_script(NONCE, PROXY_IP);
    let run = |script: String| async move {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let respond: Responder = Box::new(move |got| vec![Message::Binary(run_bash(&path, &got, "nameserver 10.42.0.2\n", &[]).into_bytes().into())]);
        let (out, _, _) = scripted(&format!("{tamper}{script}"), Duration::from_secs(90), true, respond).await;
        judge(&parse_markers(&out, NONCE).unwrap())
    };
    let j = run(script.clone()).await;
    assert!(j.passed() && j.dns == "no-dns", "{:?}", j.failures());
    for (half, mutant) in [("\\unalias -a; ", script.replacen("\\unalias -a; ", "", 1)), ("unset -f …", script.replacen("unset -f command curl dig printf 2>/dev/null; ", "", 1))] {
        assert_ne!(mutant, script, "{half} is in the script");
        let j = run(mutant).await;
        assert!(!j.passed() && j.cases.iter().all(|c| c.result.is_none()), "without {half} the tampered shell must fool the script: {:?}", j.failures());
    }
}

#[tokio::test]
async fn the_dns_path_script_runs_in_bash() {
    let resolv = "nameserver 10.42.0.2\n";
    let m = parse_markers(&through_bash(render_dns_script(NONCE, PROXY_IP), resolv, &[]).await, NONCE).unwrap();
    assert!(m.finished && m.cases.len() == 15, "{m:?}");
    let (v, note) = dns_path_outcome(&m).unwrap();
    assert_eq!(v, "no-dns");
    assert!(note.starts_with("resolves=no resolv.conf nameserver 10.42.0.2;"), "{note}");
    let m = parse_markers(&through_bash(render_dns_script(NONCE, PROXY_IP), resolv, &[("FAKE_DNS_REPLY", "10.42.1.2")]).await, NONCE).unwrap();
    let (v, note) = dns_path_outcome(&m).unwrap();
    assert_eq!(v, "platform-dns:10.42.1.2");
    assert!(note.starts_with("resolves=no") && note.contains("10.42.1.2 udp replied (REFUSED, no recursion), tcp replied (REFUSED, no recursion)"), "{note}");
    let m = parse_markers(&through_bash(render_dns_script(NONCE, PROXY_IP), resolv, &[("FAKE_DNS_REPLY", "10.42.1.2"), ("FAKE_DNS_RESOLVES", "1")]).await, NONCE).unwrap();
    assert_eq!(dns_path_outcome(&m).unwrap().0, "platform-dns-resolves:10.42.1.2", "names resolve through the platform: never plain platform-dns");
    let m = parse_markers(&through_bash(render_dns_script(NONCE, PROXY_IP), resolv, &[("FAKE_DNS_REPLY", "1.1.1.1")]).await, NONCE).unwrap();
    assert_eq!(dns_path_outcome(&m).unwrap().0, "open-dns:1.1.1.1", "a public resolver that replies is open DNS");
    const DEAD: &[(&str, &str)] = &[("FAKE_WORLD", "dead")];
    const DIES: &[(&str, &str)] = &[("FAKE_WORLD", "dies")];
    for world in [DEAD, DIES] {
        let m = parse_markers(&through_bash(render_dns_script(NONCE, PROXY_IP), resolv, world).await, NONCE).unwrap();
        assert!(dns_path_outcome(&m).unwrap_err().contains("proves nothing"), "{world:?}: no verdict from a VM whose networking is dead");
    }
}

#[test]
fn session_init_is_recognised_and_nothing_else() {
    assert_eq!(session_init_id(r#"{"type":"session_init","session_id":"abc"}"#).as_deref(), Some("abc"));
    assert_eq!(session_init_id(r#"{"type":"session_init"}"#).as_deref(), Some("?"));
    assert_eq!(session_init_id(r#"{"type":"other","session_id":"abc"}"#), None);
    assert_eq!(session_init_id("λ $ ls"), None, "shell output passes through");
    assert_eq!(session_init_id(r#"{"session_id":"abc"}"#), None);
}
