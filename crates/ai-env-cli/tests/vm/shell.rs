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
//! /bin/bash behind a loopback shell ([`bash_shell`]), with fake `curl` and
//! `dig` on a pinned PATH (no network), modelling a closed VPC, a leaky one,
//! a dead proxy, and platform DNS: the stub's empty NOERROR and every other
//! reply a platform resolver can give (an SOA, NXDOMAIN, SERVFAIL, REFUSED, a
//! record, a forwarder that strips the SOA, an address).
//!
//! S9, the stdin path (`run_script_frames_over`): the egress check's
//! presigned URLs are typed only once the script asks (its `urls` marker,
//! printed with the terminal's echo off). The loopback shell echoes what it
//! receives as a terminal in cooked mode does until then, so a URL typed
//! early would show in the output; the fake IMDS hands `s3-imds-role` the
//! role's credentials, which must sign its PUT and never show.
use ai_env_cli::bridge::egress::check::{dns_path_outcome, judge, judge_with, parse_markers, render_dns_script, render_script, script_frames, url_reads, urls_marker, FrontObject, S3Facts, Verdict, CASES};
use ai_env_cli::bridge::egress::PROXY_IP;
use ai_env_cli::bridge::vm::shell::{pump, run_script_frames_over, run_script_over, session_init_id, Gated, PumpEnd, ESCAPE, SCRIPT_OUTPUT_MAX};
use futures_util::{SinkExt, StreamExt};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

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
            "direct-name" | "s3-direct" => "rc=6 code=000 size=0 conn=0 hc=000 t403=no sq=no".to_string(),
            "direct-ipv4" | "direct-http" | "proxy-other-port" => "rc=28 code=000 size=0 conn=0 hc=000 t403=no sq=no".to_string(),
            "direct-ipv6" => "rc=7 code=000 size=0 conn=0 hc=000 t403=no sq=no".to_string(),
            "imds" | "imds-v6" => "rc=0 code=401 size=0 conn=1 hc=000 t403=no sq=no".to_string(),
            "proxy-http-8080" => "rc=0 code=403 size=3900 conn=1 hc=000 t403=no sq=yes".to_string(),
            // The S9 S3 cases (§7.7): s3-own 200/200, the S3Denied cases 403 AccessDenied, proxy-s3-other-host a
            // CONNECT 403 (the proxy- arm below), s3-direct no connection (the direct-name arm above).
            "s3-own" => "rc=0 put=200 get=200 hc=200 s3=-".to_string(),
            "s3-front-bucket" | "s3-front-path" => "rc=0 put=000 get=403 hc=200 s3=AccessDenied".to_string(),
            "s3-own-outside-prefix" | "s3-imds-role" => "rc=0 put=403 get=000 hc=200 s3=AccessDenied".to_string(),
            n if n.starts_with("proxy-") || n == "denied" => "rc=56 code=000 size=0 conn=1 hc=403 t403=yes sq=no".to_string(),
            n if n.starts_with("dns-public") => format!("rc=9 ns={} res=no st=none ra=none an=none au=none", if n == "dns-public-port" { "208.67.222.222" } else { "1.1.1.1" }),
            n if n.starts_with("dns-platform6") => "rc=9 ns=fd00:ec2::253 res=no st=none ra=none an=none au=none".to_string(),
            n if n.starts_with("dns-") => "rc=9 ns=10.42.0.2 res=no st=none ra=none an=none au=none".to_string(),
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
///
/// S9 (§7.7): it reads `-K`'s config (`user`, `header`) as curl does, and
/// honours `-f` (an HTTP error is exit 22 and no body; without it, IMDS's
/// HTML error page is the body). IMDSv2 hands out a session token to a PUT,
/// and, to a request carrying it, the role `ai-env-vm-exec` and its
/// credentials ([`IMDS_SECRETS`]; `FAKE_NO_ROLE`: the listing is IMDS's 404,
/// `FAKE_IMDS_PARTIAL`: no Token). Through the opened tunnel (CONNECT 200),
/// S3 serves a presigned PUT or GET of `v1/_egress-check/`, refuses one of
/// `x/_egress-check/` and the fronting GETs of the public object with 403
/// `AccessDenied`, and so a PUT signed (`--aws-sigv4`) with exactly the
/// role's credentials; a `--aws-sigv4` request without them (an anonymous
/// PUT) is no request at all (exit 2), and a PUT without `Content-Length: 0`
/// gets S3's 411 `MissingContentLength`.
const FAKE_CURL: &str = r#"#!/bin/sh
fmt=; url=; noproxy=0; prev=; sigv4=0; method=GET; fail=0; hdrs=; kconf=; user=
for a in "$@"; do
  case "$prev" in -w) fmt=$a ;; --noproxy) noproxy=1 ;; -X) method=$a ;; -H) hdrs="$hdrs
$a" ;; -K) kconf=$(cat "$a") ;; esac
  case "$a" in http://*|https://*) url=$a ;; --aws-sigv4) sigv4=1 ;; -[!-]*f*) fail=1 ;; esac
  prev=$a
done
if [ -n "$kconf" ]; then
  hdrs="$hdrs
$(printf '%s\n' "$kconf" | sed -n 's/^header = "\(.*\)"$/\1/p')"
  user=$(printf '%s\n' "$kconf" | sed -n 's/^user = "\(.*\)"$/\1/p')
fi
has() { printf '%s\n' "$hdrs" | grep -qxF "$1"; }
filled() { printf '%s' "$fmt" | sed -e "s/%{http_code}/$1/" -e "s/%{http_connect}/$2/" -e "s/%{size_download}/0/" -e "s/%{num_connects}/1/" -e "s/%header{x-squid-error}//"; }
case "$url" in https://*) proxy=${https_proxy:-} ;; *) proxy=${http_proxy:-} ;; esac
[ "$noproxy" = 1 ] && proxy=
# IMDSv2, as the check VM's execution role sees it.
imds_err() {
  if [ "$fail" = 1 ]; then printf 'curl: (22) The requested URL returned error: %s\n' "$1" >&2; exit 22; fi
  printf '<?xml version="1.0" encoding="iso-8859-1"?>\n<html><head><title>%s - Not Found</title></head><body><h1>%s</h1></body></html>\n' "$1" "$1"
  exit 0
}
case "$url" in
  http://169.254.169.254/latest/api/token)
    [ "$method" = PUT ] || imds_err 405
    printf fake-imds-token; exit 0 ;;
  http://169.254.169.254/latest/meta-data/iam/security-credentials/*)
    has 'X-aws-ec2-metadata-token: fake-imds-token' || imds_err 401
    [ -z "${FAKE_NO_ROLE:-}" ] || imds_err 404
    role=${url#http://169.254.169.254/latest/meta-data/iam/security-credentials/}
    if [ -z "$role" ]; then printf ai-env-vm-exec; exit 0; fi
    [ "$role" = ai-env-vm-exec ] || imds_err 404
    printf '{\n  "Code" : "Success",\n  "LastUpdated" : "2026-10-18T09:00:00Z",\n  "Type" : "AWS-HMAC",\n  "AccessKeyId" : "fake-imds-key-id",\n  "SecretAccessKey" : "fake-imds-secret",\n'
    [ -n "${FAKE_IMDS_PARTIAL:-}" ] || printf '  "Token" : "fake-imds-session-token",\n'
    printf '  "Expiration" : "2026-10-18T15:00:00Z"\n}'
    exit 0 ;;
esac
# S3 through the opened tunnel (the S9 egress-check requests, §7.7).
s3code=; s3err=
if [ "$sigv4" = 1 ]; then
  if [ "$user" != "fake-imds-key-id:fake-imds-secret" ] || ! has 'x-amz-security-token: fake-imds-session-token'; then
    printf 'curl: (2) fake curl: --aws-sigv4 without the role credentials\n' >&2
    filled 000 000; exit 2
  fi
  s3code=403; s3err=AccessDenied
else case "$url" in
  *"/v1/_egress-check/"*) s3code=200 ;;
  *"/x/_egress-check/"*) s3code=403; s3err=AccessDenied ;;
  *copernicus-dem-30m*) s3code=403; s3err=AccessDenied ;;
esac; fi
if [ -n "$s3code" ] && [ "$method" = PUT ] && ! has 'Content-Length: 0'; then s3code=411; s3err=MissingContentLength; fi
if [ -n "$s3code" ]; then
  [ -n "$s3err" ] && printf '<Error><Code>%s</Code></Error>' "$s3err"
  filled "$s3code" 200
  exit 0
fi
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

/// A fake `dig` printing what `+noall +comments +answer` (the run's fresh
/// name, with the header) and `+noall +answer` (example.com, records only)
/// print. The name after `@server` must be `FAKE_DNS_NAME` with `+comments`
/// and `example.com` without, or it exits 10 (a script that asks another
/// name never passes). No server replies (dig's own error lines, which name
/// the server, then exit 9) unless `FAKE_DNS_REPLY` names it (exit 0): the
/// header with `FAKE_DNS_STATUS` (NOERROR by default), the flags line (`ra`
/// with `FAKE_DNS_RA=1`) and its counts, `FAKE_DNS_ANSWERS` (a CNAME line
/// when above 0) and `FAKE_DNS_AUTHORITY` (0 by default: the platform stub's
/// empty NOERROR); `FAKE_DNS_RESOLVES=1` answers an address for whatever
/// name is asked, `FAKE_DNS_EXAMPLE=1` one for example.com only (a forwarder
/// that strips the SOA but resolves), `FAKE_DNS_EXAMPLE_SILENT=1` no reply to
/// example.com at all (dig's timeout, exit 9: a forwarder whose upstream is
/// slow). `FAKE_DNS_TRUNCATE` names a server whose UDP reply comes truncated
/// and whose TCP retry fails (exit 9).
const FAKE_DIG: &str = r#"#!/bin/sh
server=; name=; comments=0; next=0
for a in "$@"; do
  [ "$next" = 1 ] && name=$a
  next=0
  case "$a" in @*) server=${a#@}; next=1 ;; +comments) comments=1 ;; esac
done
if [ "$comments" = 1 ]; then want=${FAKE_DNS_NAME:-}; else want=example.com; fi
if [ -z "$want" ] || [ "$name" != "$want" ]; then
  echo ";; fake dig: asked $name, expected $want"
  exit 10
fi
if [ "$comments" = 0 ] && [ "${FAKE_DNS_EXAMPLE_SILENT:-0}" = 1 ]; then
  echo ";; communications error to $server#53: timed out"
  echo ";; no servers could be reached"
  exit 9
fi
if [ -n "${FAKE_DNS_TRUNCATE:-}" ] && [ "$server" = "$FAKE_DNS_TRUNCATE" ]; then
  echo ";; Truncated, retrying in TCP mode."
  echo ";; Connection to $server#53($server) for $name failed: connection refused."
  echo ";; no servers could be reached"
  exit 9
fi
if [ -n "${FAKE_DNS_REPLY:-}" ] && [ "$server" = "$FAKE_DNS_REPLY" ]; then
  resolves=${FAKE_DNS_RESOLVES:-0}
  if [ "$comments" = 1 ]; then
    st=${FAKE_DNS_STATUS:-NOERROR}; an=${FAKE_DNS_ANSWERS:-0}; au=${FAKE_DNS_AUTHORITY:-0}
    [ "$resolves" = 1 ] && st=NOERROR && an=1
    ra=; [ "${FAKE_DNS_RA:-0}" = 1 ] && ra=' ra'
    echo ";; Got answer:"
    echo ";; ->>HEADER<<- opcode: QUERY, status: $st, id: 4242"
    echo ";; flags: qr rd$ra; QUERY: 1, ANSWER: $an, AUTHORITY: $au, ADDITIONAL: 1"
    echo
    [ "$an" -gt 0 ] && [ "$resolves" != 1 ] && printf '%s.\t\t300\tIN\tCNAME\tother.example.net.\n' "$name"
  fi
  [ "$resolves" = 1 ] && printf '%s.\t\t300\tIN\tA\t93.184.215.14\n' "$name"
  [ "$comments" = 0 ] && [ "$resolves" != 1 ] && [ "${FAKE_DNS_EXAMPLE:-0}" = 1 ] && printf 'example.com.\t\t300\tIN\tA\t93.184.215.14\n'
  exit 0
fi
echo ";; communications error to $server#53: timed out"
echo ";; no servers could be reached"
exit 9
"#;

/// The run's fresh name the fake `dig` insists on (`d<NONCE>.example.com`), spelled out so a change of the
/// script's name fails here.
const FAKE_DNS_NAME: &str = "d00c0ffee12345678.example.com";

/// The three fake presigned URLs the S3 cases (§7.7) read from stdin, in the
/// order the script reads them into `AIENV_U`: s3-own's PUT and GET of
/// `v1/_egress-check/<nonce>`, and s3-own-outside-prefix's PUT of
/// `x/_egress-check/<nonce>`. The fake `curl` keys off the path (`/v1/` served,
/// `/x/` refused). They are typed, as the Mac types them, only once the
/// script asks; it reads them silently (`read -rs`), so they never reach the
/// output.
const S3_FAKE_URLS: [&str; 3] = [
    "https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/v1/_egress-check/00c0ffee12345678?X-Amz-Fake=put",
    "https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/v1/_egress-check/00c0ffee12345678?X-Amz-Fake=get",
    "https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/x/_egress-check/00c0ffee12345678?X-Amz-Fake=outside",
];

/// What the fake IMDS hands the check VM (not credential-shaped): the role's access key id, secret and session token,
/// and IMDS's own session token. None may ever reach the output.
const IMDS_SECRETS: [&str; 4] = ["fake-imds-key-id", "fake-imds-secret", "fake-imds-session-token", "fake-imds-token"];

/// The fakes on a pinned PATH under `dir` (`bin/`: curl, dig, and a `sleep` that returns at once) and `resolv` as the
/// shell's `/etc/resolv.conf`; returns that file's path.
fn install_fakes(dir: &Path, resolv: &str) -> String {
    use std::os::unix::fs::PermissionsExt as _;
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for (name, body) in [("curl", FAKE_CURL), ("dig", FAKE_DIG), ("sleep", "#!/bin/sh\nexit 0\n")] {
        std::fs::write(bin.join(name), body).unwrap();
        std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let conf = dir.join("resolv.conf");
    std::fs::write(&conf, resolv).unwrap();
    conf.display().to_string()
}

/// A loopback platform shell: /bin/bash (no rc files, a clean environment,
/// the fakes first on PATH, `/etc/resolv.conf` replaced by `resolv`) reads
/// the binary frames the client sends, in order, as its stdin; what it prints
/// (stdout and stderr) goes back as binary frames, and the session closes
/// when bash exits (killed after 60 s; the client's close ends its stdin).
/// Like a terminal in cooked mode it echoes each frame as it receives it
/// (prompt, CRLF) — until bash has printed the run's `urls` marker, which the
/// script prints once it has turned the echo off. Returns the frames it got.
async fn bash_shell(listener: tokio::net::TcpListener, dir: PathBuf, resolv: &'static str, env: &'static [(&'static str, &'static str)]) -> Vec<Vec<u8>> {
    use tokio::io::AsyncWriteExt as _;
    let (tcp, _) = listener.accept().await.unwrap();
    let (mut tx, mut rx) = tokio_tungstenite::accept_async(tcp).await.unwrap().split();
    let conf = install_fakes(&dir, resolv);
    let mut c = tokio::process::Command::new("/bin/bash");
    c.args(["--norc", "--noprofile"]).env_clear().env("PATH", format!("{}:/usr/bin:/bin", dir.join("bin").display())).env("HOME", &dir).env("LC_ALL", "C").env("FAKE_DNS_NAME", FAKE_DNS_NAME);
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true).spawn().unwrap();
    let mut stdin = child.stdin.take();
    let (mut stdout, mut stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let marker = urls_marker(NONCE).into_bytes();
    let (mut got, mut printed, mut echoing) = (Vec::new(), Vec::<u8>::new(), true);
    let (mut client_open, mut out_open, mut err_open) = (true, true, true);
    let (mut ob, mut eb) = (vec![0u8; 8192], vec![0u8; 8192]);
    let deadline = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(deadline);
    while out_open || err_open {
        let mut printing: Option<Vec<u8>> = None;
        tokio::select! {
            () = &mut deadline => {
                let _ = child.start_kill();
                break;
            }
            msg = rx.next(), if client_open => match msg {
                Some(Ok(Message::Binary(b))) => {
                    if echoing {
                        let _ = tx.send(echo(&b)).await;
                    }
                    let text = String::from_utf8_lossy(&b).replace("/etc/resolv.conf", &conf);
                    if let Some(input) = stdin.as_mut() {
                        let _ = input.write_all(text.as_bytes()).await;
                    }
                    got.push(b.to_vec());
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => {
                    client_open = false;
                    stdin = None;
                }
                Some(Ok(_)) => {}
            },
            n = stdout.read(&mut ob), if out_open => match n {
                Ok(n) if n > 0 => printing = Some(ob[..n].to_vec()),
                _ => out_open = false,
            },
            n = stderr.read(&mut eb), if err_open => match n {
                Ok(n) if n > 0 => printing = Some(eb[..n].to_vec()),
                _ => err_open = false,
            },
        }
        if let Some(bytes) = printing {
            printed.extend_from_slice(&bytes);
            // The script turned the echo off before it printed the marker; set before the marker leaves, so before
            // the client can answer it.
            if printed.windows(marker.len()).any(|w| w == marker.as_slice()) {
                echoing = false;
            }
            if client_open {
                let _ = tx.send(Message::Binary(bytes.into())).await;
            }
        }
    }
    let _ = child.wait().await;
    let _ = tx.send(Message::Close(None)).await;
    got
}

/// `script` typed into a loopback bash shell ([`bash_shell`]) as the Mac
/// types it (`check::script_frames`): the fake presigned URLs, exactly as
/// many as the script reads, and the rest of the script only once the shell
/// printed the `urls` marker — or, `gate` false, right behind the script, as
/// no Mac types them. Returns what came back and the frames the shell got.
async fn bash_session(script: &str, gate: bool, resolv: &'static str, env: &'static [(&'static str, &'static str)]) -> (String, Vec<Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(bash_shell(listener, dir.path().to_path_buf(), resolv, env));
    let ws = dial(addr).await;
    let (first, then) = script_frames(script, &S3_FAKE_URLS[..url_reads(script)]).unwrap();
    let marker = urls_marker(NONCE);
    let after = if gate { marker.as_str() } else { "" };
    let gated: Vec<Gated<'_>> = then.iter().map(|t| Gated { after, text: t.expose() }).collect();
    let out = tokio::time::timeout(Duration::from_secs(120), run_script_frames_over(ws, first, &gated, Duration::from_secs(90))).await.expect("run_script_frames_over is bounded").unwrap();
    let got = tokio::time::timeout(Duration::from_secs(70), server).await.unwrap().unwrap();
    drop(dir);
    (out, got)
}

/// The rendered script through the loopback bash shell, typed as the Mac
/// types it, in `env`'s world: the echo, then whatever bash printed.
async fn through_bash(script: String, resolv: &'static str, env: &'static [(&'static str, &'static str)]) -> String {
    bash_session(&script, true, resolv, env).await.0
}

/// A WebSocket client to the loopback server at `addr`.
async fn dial(addr: std::net::SocketAddr) -> WebSocketStream<tokio::net::TcpStream> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr)).await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::client_async(format!("ws://{addr}/shell"), tcp)).await.unwrap().unwrap().0
}

fn failing(j: &ai_env_cli::bridge::egress::check::Judgement) -> Vec<&'static str> {
    j.cases.iter().filter(|c| c.verdict == Verdict::Fail).map(|c| c.name).collect()
}

#[tokio::test]
async fn the_egress_check_script_runs_in_bash_and_is_judged() {
    let resolv = "# platform\nnameserver 10.42.0.2\nnameserver 10.42.0.3\n";
    let run = |resolv: &'static str, env: &'static [(&'static str, &'static str)]| through_bash(render_script(NONCE, PROXY_IP), resolv, env);
    // A closed VPC with a working proxy: every case passes, no DNS server replies.
    let (out, got) = bash_session(&render_script(NONCE, PROXY_IP), true, resolv, &[]).await;
    let m = parse_markers(&out, NONCE).unwrap_or_else(|e| panic!("{e}"));
    assert!(m.finished && m.urls && m.cases.len() == CASES.len(), "{m:?}");
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
    // The S9 S3 cases (§7.7): s3-own stored and read back through the endpoint (CONNECT 200, both 200); the S3Denied
    // cases 403 AccessDenied through the tunnel; proxy-s3-other-host a CONNECT 403; s3-direct made no connection.
    let own = m.get("s3-own").unwrap();
    assert_eq!((own.put, own.get, own.hc, own.s3.as_deref()), (Some(200), Some(200), Some(200), None), "s3-own: {own:?}");
    for n in ["s3-front-bucket", "s3-front-path", "s3-own-outside-prefix", "s3-imds-role"] {
        let r = m.get(n).unwrap();
        assert_eq!((r.hc, r.s3.as_deref()), (Some(200), Some("AccessDenied")), "{n}: {r:?}");
        assert!(r.put == Some(403) || r.get == Some(403), "{n}: 403 somewhere: {r:?}");
    }
    assert_eq!(m.get("proxy-s3-other-host").unwrap().hc, Some(403), "a CONNECT squid refuses");
    assert_eq!(m.get("s3-direct").unwrap().conn, Some(0), "no direct connection to the bucket host");
    for n in ["s3-own", "s3-front-bucket", "s3-front-path", "s3-own-outside-prefix", "s3-imds-role", "proxy-s3-other-host", "s3-direct"] {
        assert_eq!(j.cases.iter().find(|c| c.name == n).unwrap().verdict, Verdict::Pass, "{n}");
    }
    // Custody (§2.2): the shell got the script up to its read loop, then — once it asked, its echo off — the URLs and
    // the rest; no URL, and nothing IMDS handed over, reached the output.
    assert_eq!(got.len(), 2, "the script, then the URLs and the rest");
    let urls: String = S3_FAKE_URLS.iter().map(|u| format!("{u}\n")).collect();
    assert!(got[1].starts_with(urls.as_bytes()) && !String::from_utf8_lossy(&got[0]).contains("X-Amz-Fake"), "the URLs went in the second frame only");
    for u in &S3_FAKE_URLS {
        assert!(!out.contains(u), "a presigned URL leaked into the shell output: {u}");
    }
    assert!(!out.contains("X-Amz-Fake"), "no query of a presigned URL in the output");
    for secret in IMDS_SECRETS {
        assert!(!out.contains(secret), "{secret} reached the shell output");
    }
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
    // The platform resolver resolves: those cases fail; the stub's empty NOERROR (no answer, no authority) passes.
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_DNS_REPLY", "169.254.169.253"), ("FAKE_DNS_RESOLVES", "1")]).await, NONCE).unwrap());
    assert_eq!(failing(&j), ["dns-platform-udp", "dns-platform-tcp"], "{:?}", j.failures());
    assert_eq!(j.dns, "platform-dns-resolves:169.254.169.253", "a resolving platform resolver is never plain platform-dns");
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_DNS_REPLY", "169.254.169.253")]).await, NONCE).unwrap());
    assert!(j.passed(), "{:?}", j.failures());
    assert_eq!(j.dns, "platform-dns:169.254.169.253");
    assert!(f(&j, "dns-platform-udp").reason.starts_with("169.254.169.253 replied with an empty NOERROR (status NOERROR, answer 0, authority 0, no recursion) and no address for example.com"), "{}", f(&j, "dns-platform-udp").reason);
    // A truncated UDP reply whose TCP retry fails comes through as TRUNCATED: a public resolver that did so is open.
    let j = judge(&parse_markers(&run(resolv, &[("FAKE_DNS_TRUNCATE", "1.1.1.1")]).await, NONCE).unwrap());
    assert_eq!(failing(&j), ["dns-public-udp", "dns-public-tcp"], "{:?}", j.failures());
    assert_eq!(j.dns, "open-dns:1.1.1.1");
    // The dead world's wait printed a dot per failed attempt before its marker (the shell is never silent for a minute).
    assert!(run(resolv, &[("FAKE_WORLD", "dead")]).await.contains(&format!("{}@@AIENV{NONCE} ready try=30", ".".repeat(30))));
    // dig's status, counts and the recursion flag come through the VM's shell variables.
    let m = parse_markers(&run(resolv, &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_STATUS", "SERVFAIL"), ("FAKE_DNS_RA", "1"), ("FAKE_DNS_AUTHORITY", "1")]).await, NONCE).unwrap();
    let r = m.get("dns-platform6-tcp").unwrap();
    assert_eq!((r.rc, r.resolves, r.status.as_deref(), r.ra, r.answers, r.authority), (Some(0), Some(false), Some("SERVFAIL"), Some(true), Some(0), Some(1)));
    let r = m.get("dns-platform-udp").unwrap();
    assert_eq!((r.status.as_deref(), r.answers, r.authority), (None, None, None), "no reply, no status, no counts");
    let m = parse_markers(&run(resolv, &[("FAKE_DNS_REPLY", "169.254.169.253"), ("FAKE_DNS_RESOLVES", "1"), ("FAKE_DNS_RA", "1")]).await, NONCE).unwrap();
    let r = m.get("dns-platform-udp").unwrap();
    assert_eq!((r.resolves, r.status.as_deref(), r.ra, r.answers), (Some(true), Some("NOERROR"), Some(true), Some(1)), "an answer line is an address");
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
    // The URLs right behind the script (a tampered printf never prints the marker a Mac would wait for).
    let run = |script: String| async move {
        let (out, _) = bash_session(&format!("{tamper}{script}"), false, "nameserver 10.42.0.2\n", &[]).await;
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
    assert!(note.starts_with("resolves=no") && note.contains("10.42.1.2 udp replied (NOERROR, answer 0, authority 0, no recursion), tcp replied (NOERROR, answer 0, authority 0, no recursion)"), "{note}");
    // A recursor's negative answer (NXDOMAIN with the zone's SOA): answered, never accepted.
    let m = parse_markers(&through_bash(render_dns_script(NONCE, PROXY_IP), resolv, &[("FAKE_DNS_REPLY", "10.42.1.2"), ("FAKE_DNS_STATUS", "NXDOMAIN"), ("FAKE_DNS_AUTHORITY", "1"), ("FAKE_DNS_RA", "1")]).await, NONCE).unwrap();
    let (v, note) = dns_path_outcome(&m).unwrap();
    assert_eq!(v, "platform-dns-answered:10.42.1.2");
    assert!(note.contains("10.42.1.2 udp replied (NXDOMAIN, answer 0, authority 1, recursion available)"), "{note}");
    // The stub's reply to the fresh name, but no reply to example.com at all: answered, and the note says so.
    let m = parse_markers(&through_bash(render_dns_script(NONCE, PROXY_IP), resolv, &[("FAKE_DNS_REPLY", "10.42.1.2"), ("FAKE_DNS_EXAMPLE_SILENT", "1")]).await, NONCE).unwrap();
    let (v, note) = dns_path_outcome(&m).unwrap();
    assert_eq!(v, "platform-dns-answered:10.42.1.2");
    assert!(note.contains("10.42.1.2 udp replied (example.com A unanswered, answer 0, authority 0, no recursion), tcp replied (example.com A unanswered, answer 0, authority 0, no recursion)"), "{note}");
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

/// Every platform reply the matrix of the design names, at `fd00:ec2::253`, through the real script in bash: only
/// the stub's empty NOERROR (no answer, no authority) and no address for example.com passes; every other reply fails
/// both platform6 cases, and the run's verdict is its class.
#[tokio::test]
async fn every_platform_reply_through_bash_is_judged_by_its_class() {
    const STUB: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_RA", "1")];
    const SOA: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_RA", "1"), ("FAKE_DNS_AUTHORITY", "1")];
    const NXDOMAIN: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_STATUS", "NXDOMAIN"), ("FAKE_DNS_AUTHORITY", "1")];
    const SERVFAIL: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_STATUS", "SERVFAIL"), ("FAKE_DNS_RA", "1")];
    const REFUSED: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_STATUS", "REFUSED")];
    const CNAME: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_ANSWERS", "1")];
    const FORWARDER: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_EXAMPLE", "1")];
    const SOA_AND_EXAMPLE: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_AUTHORITY", "1"), ("FAKE_DNS_EXAMPLE", "1")];
    const RESOLVES: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_RESOLVES", "1")];
    const EXAMPLE_SILENT: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_RA", "1"), ("FAKE_DNS_EXAMPLE_SILENT", "1")];
    let answered = "platform-dns-answered:fd00:ec2::253";
    let resolves = "platform-dns-resolves:fd00:ec2::253";
    for (world, what, verdict) in [
        (STUB, "the stub's empty NOERROR", "platform-dns:fd00:ec2::253"),
        (SOA, "an SOA in AUTHORITY (a validating recursor's black lie)", answered),
        (NXDOMAIN, "NXDOMAIN with the SOA", answered),
        (SERVFAIL, "SERVFAIL", answered),
        (REFUSED, "REFUSED", answered),
        (CNAME, "a record without an address", answered),
        (EXAMPLE_SILENT, "the stub's reply to the fresh name, but none to example.com (a forwarder whose upstream is slow)", answered),
        (FORWARDER, "an empty fresh name, but example.com resolves (a forwarder that strips the SOA)", resolves),
        (SOA_AND_EXAMPLE, "an SOA and example.com resolving", resolves),
        (RESOLVES, "an address for the fresh name", resolves),
    ] {
        let out = through_bash(render_script(NONCE, PROXY_IP), "nameserver 10.42.0.2\n", world).await;
        let j = judge(&parse_markers(&out, NONCE).unwrap_or_else(|e| panic!("{what}: {e}")));
        let empty = verdict.starts_with("platform-dns:");
        assert_eq!(failing(&j), if empty { vec![] } else { vec!["dns-platform6-udp", "dns-platform6-tcp"] }, "{what}: {:?}", j.failures());
        assert_eq!(j.dns, verdict, "{what}");
        assert_eq!(j.passed(), empty, "{what}");
        if world == EXAMPLE_SILENT {
            // The fresh name's counts still come through; the status says what went missing.
            let r = j.cases.iter().find(|c| c.name == "dns-platform6-tcp").unwrap();
            assert!(r.reason.starts_with("fd00:ec2::253 replied (example.com A unanswered, answer 0, authority 0, recursion available): "), "{}", r.reason);
        }
    }
}

/// The script's two DNS queries are each what the judgement rests on: asking example.com instead of the fresh name
/// fails every DNS case (the fake dig refuses any other name), and without the example.com query the forwarder that
/// strips the SOA would pass — so its row of the matrix is not vacuous. Likewise without the check of that query's
/// exit code a server that never answers example.com would pass.
#[tokio::test]
async fn each_dns_query_of_the_script_is_load_bearing() {
    const FORWARDER: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_EXAMPLE", "1")];
    const EXAMPLE_SILENT: &[(&str, &str)] = &[("FAKE_DNS_REPLY", "fd00:ec2::253"), ("FAKE_DNS_EXAMPLE_SILENT", "1")];
    let script = render_script(NONCE, PROXY_IP);
    let old_name = script.replace("\"@$s\" \"$N\" A", "\"@$s\" example.com A");
    assert_ne!(old_name, script, "the fresh-name query is in the script");
    let j = judge(&parse_markers(&through_bash(old_name, "nameserver 10.42.0.2\n", &[]).await, NONCE).unwrap());
    let dns: Vec<&str> = CASES.iter().filter(|c| c.group == "dns").map(|c| c.name).collect();
    assert_eq!(dns.len(), 13);
    assert_eq!(failing(&j), dns, "{:?}", j.failures());
    assert!(j.cases.iter().filter(|c| c.group == "dns").all(|c| c.reason.contains("dig exited 10")), "{:?}", j.failures());
    let no_example = script.replace("[ $rc = 0 ] && { e=$(command dig -r +noall +answer +time=2 +tries=1 \"$@\" \"@$s\" example.com A 2>&1 </dev/null); q=$?; }; ", "");
    assert_ne!(no_example, script, "the example.com query is in the script");
    let j = judge(&parse_markers(&through_bash(no_example, "nameserver 10.42.0.2\n", FORWARDER).await, NONCE).unwrap());
    assert!(j.passed() && j.dns == "platform-dns:fd00:ec2::253", "without the example.com query the forwarder passes: {:?}", j.failures());
    let unchecked = script.replace("[ $q = 0 ] || t=NOEXAMPLE; ", "");
    assert_ne!(unchecked, script, "the example.com query's exit code is checked");
    let j = judge(&parse_markers(&through_bash(unchecked, "nameserver 10.42.0.2\n", EXAMPLE_SILENT).await, NONCE).unwrap());
    assert!(j.passed() && j.dns == "platform-dns:fd00:ec2::253", "without that check a server that never answers example.com passes: {:?}", j.failures());
}

/// s3-imds-role in bash against the fake IMDS (§7.7): IMDSv2's session token
/// goes with every request, and the role's credentials sign the PUT (a
/// config on a file descriptor, never an argv) — 403 `AccessDenied` passes,
/// and none of it reaches the output. Without a role (IMDS's 404) the case
/// says `norole`, recorded `no_role` only for a VM without an execution role;
/// a role without its session token says `nocreds`, and fails. Unsigned, or
/// without a length, the PUT fails the case: each part of it is load-bearing.
#[tokio::test]
async fn the_imds_role_case_signs_with_the_roles_credentials() {
    let resolv = "nameserver 10.42.0.2\n";
    let imds = |m: &ai_env_cli::bridge::egress::check::Markers| m.get("s3-imds-role").cloned().unwrap();
    let verdict = |j: &ai_env_cli::bridge::egress::check::Judgement| j.cases.iter().find(|c| c.name == "s3-imds-role").unwrap().clone();
    let out = through_bash(render_script(NONCE, PROXY_IP), resolv, &[]).await;
    for secret in IMDS_SECRETS {
        assert!(!out.contains(secret), "{secret} reached the shell output");
    }
    let m = parse_markers(&out, NONCE).unwrap();
    let r = imds(&m);
    assert_eq!((r.put, r.get, r.hc, r.s3.as_deref()), (Some(403), Some(0), Some(200), Some("AccessDenied")), "{r:?}");
    assert!(judge(&m).passed(), "{:?}", judge(&m).failures());
    // No role (IMDS's 404, which -f keeps out of the role's name): recorded no_role only for a VM without one.
    let m = parse_markers(&through_bash(render_script(NONCE, PROXY_IP), resolv, &[("FAKE_NO_ROLE", "1")]).await, NONCE).unwrap();
    let r = imds(&m);
    assert_eq!((r.put, r.get, r.hc, r.s3.as_deref()), (Some(0), Some(0), Some(0), Some("norole")), "{r:?}");
    let without = S3Facts { has_role: false, front: FrontObject::Status(200) };
    let j = judge_with(&m, &BTreeSet::new(), &without);
    assert!(j.passed() && verdict(&j).verdict == Verdict::Recorded && j.summary().contains(" s3-imds-role=recorded:no_role "), "{:?} {}", j.failures(), j.summary());
    let j = judge(&m);
    assert_eq!(failing(&j), ["s3-imds-role"], "a VM with an execution role whose IMDS lists none fails");
    assert!(verdict(&j).reason.contains("IMDS gave it no role (norole)"), "{}", verdict(&j).reason);
    // A role without its session token: nothing complete to sign with.
    let m = parse_markers(&through_bash(render_script(NONCE, PROXY_IP), resolv, &[("FAKE_IMDS_PARTIAL", "1")]).await, NONCE).unwrap();
    assert_eq!(imds(&m).s3.as_deref(), Some("nocreds"));
    assert_eq!(failing(&judge(&m)), ["s3-imds-role"]);
    // The PUT unsigned (no credentials in the config: an anonymous PUT, which the endpoint would refuse all the same),
    // or without a length: the case fails.
    let script = render_script(NONCE, PROXY_IP);
    let creds = r#"-K <(printf 'user = "%s:%s"\nheader = "x-amz-security-token: %s"\n' "$aienv_ak" "$aienv_sk" "$aienv_tk") "#;
    let length = "-H 'x-amz-content-sha256: UNSIGNED-PAYLOAD' -H 'Content-Length: 0' ";
    for (what, mutant) in [("unsigned", script.replacen(creds, "", 1)), ("without a length", script.replacen(length, "-H 'x-amz-content-sha256: UNSIGNED-PAYLOAD' ", 1))] {
        assert_ne!(mutant, script, "{what}: the part is in the script");
        let j = judge(&parse_markers(&through_bash(mutant, resolv, &[]).await, NONCE).unwrap());
        assert_eq!(failing(&j), ["s3-imds-role"], "{what}: {:?}", j.failures());
    }
}

/// A terminal that echoes what it receives, as the platform shell's does in
/// cooked mode: it echoes the script frame and every frame that arrives
/// within `running` (the shell still running the script's earlier lines);
/// then — the script having turned the echo off — it prints `marker` and
/// reads what comes next silently (up to 2 s), prints the end and closes.
/// `None`: the script never asks; it stays silent until the client closes.
/// Returns each frame it received and whether it came after the marker.
async fn cooked_terminal(listener: tokio::net::TcpListener, marker: Option<String>, running: Duration) -> Vec<(Vec<u8>, bool)> {
    let (tcp, _) = listener.accept().await.unwrap();
    let (mut tx, mut rx) = tokio_tungstenite::accept_async(tcp).await.unwrap().split();
    let mut got = Vec::new();
    let until = tokio::time::Instant::now() + running;
    while let Ok(Some(Ok(msg))) = tokio::time::timeout_at(until, rx.next()).await {
        if let Message::Binary(b) = msg {
            let _ = tx.send(echo(&b)).await;
            got.push((b.to_vec(), false));
        }
    }
    let Some(marker) = marker else {
        while let Some(Ok(msg)) = rx.next().await {
            if let Message::Binary(b) = msg {
                got.push((b.to_vec(), false));
            }
        }
        return got;
    };
    tx.send(Message::Binary(format!("{marker}\r\n").into_bytes().into())).await.unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    while got.len() < 2 {
        match tokio::time::timeout_at(until, rx.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => got.push((b.to_vec(), true)),
            Ok(Some(Ok(_))) => {}
            _ => break,
        }
    }
    let _ = tx.send(Message::Binary(format!("@@AIENV{NONCE} end\r\n").into_bytes().into())).await;
    let _ = tx.send(Message::Close(None)).await;
    got
}

/// The stdin path against a terminal that echoes what it receives
/// (`cooked_terminal`): `run_script_frames_over` types the URLs only once the
/// script's `urls` marker shows, so they arrive after the script turned the
/// echo off and never reach the output. Typed right behind the script, as a
/// client that does not wait for the marker types them, they are echoed. When
/// the marker never shows, nothing more is typed.
#[tokio::test]
async fn the_urls_are_typed_only_once_the_script_asks_and_never_echoed() {
    let marker = urls_marker(NONCE);
    let then = format!("{}\nthe-rest-of-the-script\n", S3_FAKE_URLS[0]);
    let bind = || async { tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap() };
    // As the Mac types them.
    let listener = bind().await;
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(cooked_terminal(listener, Some(marker.clone()), Duration::from_millis(300)));
    let out = run_script_frames_over(dial(addr).await, "the-script-up-to-its-read-loop\n", &[Gated { after: &marker, text: &then }], Duration::from_secs(10)).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap();
    assert_eq!(got.iter().map(|(_, after)| *after).collect::<Vec<_>>(), [false, true], "the script at once, the URLs only after the marker");
    assert_eq!(got[1].0, then.as_bytes());
    assert!(out.contains("bash-5.2# the-script-up-to-its-read-loop\r\n") && out.contains(&marker) && out.contains(&format!("@@AIENV{NONCE} end")), "{out}");
    assert!(!out.contains("X-Amz-Fake") && !out.contains("the-rest-of-the-script"), "nothing typed after the marker is echoed: {out}");
    // Typed right behind the script, before it asked: echoed into the output.
    let listener = bind().await;
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(cooked_terminal(listener, Some(marker.clone()), Duration::from_millis(300)));
    let (mut tx, mut rx) = dial(addr).await.split();
    tx.send(Message::Binary(b"the-script-up-to-its-read-loop\n".to_vec().into())).await.unwrap();
    tx.send(Message::Binary(then.clone().into_bytes().into())).await.unwrap();
    let mut naive = String::new();
    while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_secs(10), rx.next()).await {
        match m {
            Message::Text(t) => naive.push_str(&t),
            Message::Binary(b) => naive.push_str(&String::from_utf8_lossy(&b)),
            _ => {}
        }
    }
    let got = tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap();
    assert!(got.len() == 2 && !got[1].1 && naive.contains(S3_FAKE_URLS[0]), "typed before the script asked, the URL is echoed: {naive}");
    // The script never asks: no URL is typed, and the session ends at its budget.
    let listener = bind().await;
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(cooked_terminal(listener, None, Duration::from_millis(100)));
    let t = Instant::now();
    let out = run_script_frames_over(dial(addr).await, "the-script\n", &[Gated { after: &marker, text: &then }], Duration::from_millis(600)).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap();
    assert!(t.elapsed() >= Duration::from_millis(600) && got.len() == 1 && !out.contains("X-Amz-Fake"), "{got:?}");
}

/// Each gated part waits for its own `after`, in the output that came after
/// the previous part's: a second part gated on the same text is typed only
/// when the text shows again, never on its first showing.
#[tokio::test]
async fn each_gated_part_waits_for_its_own_marker() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let (mut tx, mut rx) = tokio_tungstenite::accept_async(tcp).await.unwrap().split();
        let mut order = Vec::new();
        // One frame each step (or none within 400 ms); before steps 1 and 3 the shell prints GO — the second time
        // split across two frames. The second part must not come on the first GO (step 2).
        for step in 0..4 {
            match step {
                1 => tx.send(Message::Binary(b"GO\r\n".to_vec().into())).await.unwrap(),
                3 => {
                    tx.send(Message::Binary(b"G".to_vec().into())).await.unwrap();
                    tx.send(Message::Binary(b"O\r\n".to_vec().into())).await.unwrap();
                }
                _ => {}
            }
            let frame = tokio::time::timeout(Duration::from_millis(400), rx.next()).await.ok().flatten().and_then(Result::ok);
            order.push(format!("{frame:?}"));
        }
        let _ = tx.send(Message::Close(None)).await;
        order
    });
    let out = run_script_frames_over(dial(addr).await, "one", &[Gated { after: "GO", text: "two" }, Gated { after: "GO", text: "three" }], Duration::from_secs(10)).await.unwrap();
    let order = tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap();
    let frame = |t: &str| format!("{:?}", Some(Message::Binary(t.as_bytes().to_vec().into())));
    assert_eq!(order, [frame("one"), frame("two"), "None".to_string(), frame("three")], "a marker split across frames still counts");
    assert_eq!(out, "GO\r\nGO\r\n");
}

#[test]
fn session_init_is_recognised_and_nothing_else() {
    assert_eq!(session_init_id(r#"{"type":"session_init","session_id":"abc"}"#).as_deref(), Some("abc"));
    assert_eq!(session_init_id(r#"{"type":"session_init"}"#).as_deref(), Some("?"));
    assert_eq!(session_init_id(r#"{"type":"other","session_id":"abc"}"#), None);
    assert_eq!(session_init_id("λ $ ls"), None, "shell output passes through");
    assert_eq!(session_init_id(r#"{"session_id":"abc"}"#), None);
}
