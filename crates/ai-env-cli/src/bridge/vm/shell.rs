//! `ai-env vm shell`: the platform's WebSocket shell (experimental; plan S4
//! D11). The shell token comes from `CreateMicrovmShellAuthToken` (the VM must
//! run with the `SHELL_INGRESS` connector: `ai-env vm run --shell`); the
//! dial is `transport::dial_shell`. The frame format is undocumented, so the
//! pump is deliberately dumb: stdin bytes go out as binary frames, binary and
//! text frames come back to stdout, a close ends the session, Ctrl-] quits.
//! Measured live (S4 part B, 30 Sep 2026): header and subprotocol auth both
//! work; the first frame is a text `{"type":"session_init","session_id":…}`,
//! reported on stderr instead of printed ([`session_init_id`]); the shell is
//! bash in the image's root filesystem (PID 1 `ai-env`), not a VM host with
//! `ctr` as the AWS docs describe. On a terminal, stdin is switched to raw
//! mode for the session and restored on every exit path ([`RawMode`]).
//!
//! The scripted shell (S5: `ai-env egress check`, the dns-path probe):
//! [`run_script`] sends one script through the same shell and returns what
//! the remote printed, never printing or logging it ([`run_script_over`] is
//! its dial-free half). Its callers refuse under the file-backed fake before
//! any token or dial ([`fake_backend_refusal`]). S9: [`run_script_frames`]
//! types more input only once the remote's output asks for it ([`Gated`]):
//! the egress check's presigned URLs, which its script reads with the
//! terminal's echo off.
use crate::bridge::api::{MicrovmApi, VmState};
use crate::bridge::errors::BridgeError;
use crate::bridge::transport::{dial_shell, ShellAuth};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use std::time::Duration;
use tokio_tungstenite::WebSocketStream;

/// Ctrl-] — the byte that ends a session typed on a terminal.
pub const ESCAPE: u8 = 0x1d;

/// After input EOF (piped commands), output is still printed until the
/// remote closes, or until it has been quiet this long; then the close is sent.
pub const EOF_LINGER: Duration = Duration::from_secs(5);

/// Why a pumped session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpEnd {
    /// The remote side sent a close frame or ended the stream.
    RemoteClosed,
    /// The escape byte was read from the input.
    Escaped,
    /// The input reached EOF and the remote stayed quiet for the linger (the close was sent).
    InputEof,
}

/// The session id of the platform's `{"type":"session_init","session_id":…}`
/// text frame; `None` for anything else (shell output passes through as is).
#[must_use]
pub fn session_init_id(text: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    if v.get("type").and_then(|t| t.as_str()) != Some("session_init") {
        return None;
    }
    Some(v.get("session_id").and_then(|s| s.as_str()).unwrap_or("?").to_string())
}

/// Move bytes between `input`/`output` and the WebSocket until one side ends.
/// At input EOF the input side stops, but replies keep coming until the
/// remote closes or stays quiet for `linger`. Generic over the stream so
/// tests drive it over plain loopback TCP (the only TLS dial lives in
/// `transport`).
pub async fn pump<S, I, O>(ws: WebSocketStream<S>, mut input: I, mut output: O, escape: Option<u8>, linger: Duration) -> Result<PumpEnd, BridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let lost = |e: &dyn std::fmt::Display| BridgeError::Transport(format!("shell: {e}"));
    let (mut sink, mut stream) = ws.split();
    let mut buf = vec![0u8; 8192];
    let mut input_open = true;
    loop {
        let quiet = tokio::time::sleep(linger);
        tokio::pin!(quiet);
        tokio::select! {
            () = &mut quiet, if !input_open => {
                let _ = sink.send(Message::Close(None)).await;
                return Ok(PumpEnd::InputEof);
            }
            n = input.read(&mut buf), if input_open => {
                let n = n.map_err(|e| lost(&e))?;
                if n == 0 {
                    input_open = false;
                    continue;
                }
                let chunk = &buf[..n];
                if let Some(at) = escape.and_then(|e| chunk.iter().position(|b| *b == e)) {
                    if at > 0 {
                        sink.send(Message::Binary(chunk[..at].to_vec().into())).await.map_err(|e| lost(&e))?;
                    }
                    let _ = sink.send(Message::Close(None)).await;
                    return Ok(PumpEnd::Escaped);
                }
                sink.send(Message::Binary(chunk.to_vec().into())).await.map_err(|e| lost(&e))?;
            }
            msg = stream.next() => {
                match msg {
                    None | Some(Ok(Message::Close(_))) => return Ok(PumpEnd::RemoteClosed),
                    Some(Ok(Message::Binary(b))) => output.write_all(&b).await.map_err(|e| lost(&e))?,
                    Some(Ok(Message::Text(t))) => match session_init_id(&t) {
                        // `\r\n`: the terminal may be in raw mode.
                        Some(sid) => eprint!("ai-env: shell session {sid}\r\n"),
                        None => output.write_all(t.as_bytes()).await.map_err(|e| lost(&e))?,
                    },
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(lost(&e)),
                }
                output.flush().await.map_err(|e| lost(&e))?;
            }
        }
    }
}

/// Raw mode on stdin while alive (only when stdin is a terminal); the saved
/// settings are restored on drop, so every return and `?` path restores them.
pub struct RawMode {
    saved: Option<libc::termios>,
}

impl RawMode {
    /// Switch stdin to raw mode if it is a terminal; a no-op otherwise.
    #[must_use]
    pub fn enter_if_tty() -> RawMode {
        // SAFETY: isatty on a descriptor number; no memory is touched.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            return RawMode { saved: None };
        }
        // SAFETY: zeroed is a valid termios bit pattern; tcgetattr fills it before use.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr writes into `t`, which lives across the call.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut t) } != 0 {
            return RawMode { saved: None };
        }
        let saved = t;
        // SAFETY: cfmakeraw only edits the struct it is given.
        unsafe { libc::cfmakeraw(&mut t) };
        // SAFETY: tcsetattr reads `t`; on failure nothing changed and nothing needs restoring.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) } != 0 {
            return RawMode { saved: None };
        }
        RawMode { saved: Some(saved) }
    }

    /// Is stdin in raw mode because of this guard?
    #[must_use]
    pub fn active(&self) -> bool {
        self.saved.is_some()
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(saved) = self.saved.take() {
            // SAFETY: restores the settings read in enter_if_tty on the same descriptor.
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &saved) };
        }
    }
}

/// `ai-env vm shell ID`: shell token (the VM must have `SHELL_INGRESS`), dial,
/// raw mode, pump. A `ValidationException` from the token call gets the
/// `vm run --shell` hint.
pub async fn shell<A: MicrovmApi>(api: &A, id: &str, minutes: u16, auth: ShellAuth) -> Result<PumpEnd, BridgeError> {
    let vm = api.get(id).await?;
    if vm.state.is_terminal() {
        return Err(BridgeError::Terminated(format!("{id} is {}", vm.state.as_str())));
    }
    let token = match api.create_shell_token(id, minutes).await {
        Ok(t) => t,
        Err(BridgeError::Validation(m)) => {
            return Err(BridgeError::Validation(format!("{m} — start the VM with `ai-env vm run --shell` (the SHELL_INGRESS connector)")));
        }
        Err(e) => return Err(e),
    };
    let ws = dial_shell(&vm.endpoint, token.value()?, auth).await?;
    let raw = RawMode::enter_if_tty();
    eprint!("ai-env: shell on {id} (experimental; {} quits){}", if raw.active() { "Ctrl-]" } else { "EOF" }, if raw.active() { "\r\n" } else { "\n" });
    let end = pump(ws, tokio::io::stdin(), tokio::io::stdout(), raw.active().then_some(ESCAPE), EOF_LINGER).await;
    drop(raw);
    end
}

// ---- the scripted shell (S5) ---------------------------------------------------------------

/// The most of a scripted session's output that is kept (1 MiB); the rest is dropped.
pub const SCRIPT_OUTPUT_MAX: usize = 1024 * 1024;

/// The shell token of a scripted session: it only has to outlive the handshake.
pub const SCRIPT_TOKEN_MINUTES: u16 = 5;

/// What `ai-env egress check` and the dns-path probe answer under the
/// file-backed fake (`Backend::Fake`), before any shell token or dial: the
/// fake has no shell to carry a script (exit 9).
#[must_use]
pub fn fake_backend_refusal(what: &str) -> BridgeError {
    BridgeError::Policy(format!("{what}: the file-backed fake cannot carry a shell (AI_ENV_BRIDGE_LAB_FAKE_API is set): the scripted shell needs the real service"))
}

/// The remote ended the stream without a clean close (a reset after `exit`
/// is common): the end of the session, not an error.
fn ended(e: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::error::{Error as WsError, ProtocolError};
    match e {
        WsError::ConnectionClosed | WsError::AlreadyClosed | WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => true,
        WsError::Io(io) => matches!(io.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof),
        _ => false,
    }
}

/// Send `script` (one binary frame; it ends with `exit`, so the shell ends
/// the session) and collect what the remote prints — binary and text frames,
/// the platform's `session_init` frame left out — until it closes (or resets
/// the stream) or `budget` has passed since the script was sent (then the
/// close is sent; a silent session ends there). The budget is the whole
/// script's: its cases bound themselves (curl and dig timeouts). The output
/// is returned, never printed or logged, at most [`SCRIPT_OUTPUT_MAX`]
/// bytes (lossy UTF-8). Generic over the stream like [`pump`], so tests
/// drive it over plain loopback TCP.
pub async fn run_script_over<S>(ws: WebSocketStream<S>, script: &str, budget: Duration) -> Result<String, BridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_script_frames_over(ws, script, &[], budget).await
}

/// Input a scripted session types only once the remote asks for it: `text`
/// goes out as one binary frame once the output collected so far (the
/// [`SCRIPT_OUTPUT_MAX`] kept) contains `after` — an empty `after` at once —
/// and never when it does not show before the budget passes or the remote
/// closes. The egress check's script prints `after` (its `urls` marker, built
/// at run time, so its echo never matches) once it has turned its terminal's
/// echo off and is about to read the presigned URLs `text` holds: a terminal
/// echoes input as it receives it, so typed before then they would be echoed
/// into the output — or, read by a line still running, run as commands that
/// print them. No `Debug`: `text` may hold secrets.
#[derive(Clone, Copy)]
pub struct Gated<'a> {
    pub after: &'a str,
    pub text: &'a str,
}

/// Like [`run_script_over`], with more input typed as the remote asks for it:
/// `script` goes out as one binary frame at once, then each of `gated`, in
/// order, once its `after` shows in the output that came after the previous
/// part's ([`Gated`]); what was not sent when the session ends never is. The
/// egress check sends its script, then the presigned URLs its script reads on
/// stdin (`check::run_check_script`): never in the script text, the shell's
/// argv or its environment (the script hands them to curl's argv in that VM,
/// which runs no agent), typed only while the remote terminal's echo is off, and read
/// with `read -rs`, so they never appear in the returned output (nor in a log
/// or an audit row: §2.2's third `expose()`). The caller registers any secret
/// in them with the scrubber beforehand.
pub async fn run_script_frames_over<S>(ws: WebSocketStream<S>, script: &str, gated: &[Gated<'_>], budget: Duration) -> Result<String, BridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let lost = |e: &dyn std::fmt::Display| BridgeError::Transport(format!("shell script: {e}"));
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::Binary(script.as_bytes().to_vec().into())).await.map_err(|e| lost(&e))?;
    let deadline = tokio::time::Instant::now() + budget;
    let mut out: Vec<u8> = Vec::new();
    // The next gated part, and where in `out` its `after` may start: past the previous part's, and past what an
    // earlier search already ruled out.
    let (mut next, mut from) = (0usize, 0usize);
    loop {
        while let Some(g) = gated.get(next) {
            let needle = g.after.as_bytes();
            let Some(at) = find(&out[from..], needle) else {
                from = from.max(out.len().saturating_sub(needle.len().saturating_sub(1)));
                break;
            };
            sink.send(Message::Binary(g.text.as_bytes().to_vec().into())).await.map_err(|e| lost(&e))?;
            from += at + needle.len();
            next += 1;
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                let _ = sink.send(Message::Close(None)).await;
                break;
            }
            msg = stream.next() => match msg {
                None | Some(Ok(Message::Close(_))) => break,
                Some(Ok(Message::Binary(b))) => keep(&mut out, &b),
                Some(Ok(Message::Text(t))) => {
                    if session_init_id(&t).is_none() {
                        keep(&mut out, t.as_bytes());
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) if ended(&e) => break,
                Some(Err(e)) => return Err(lost(&e)),
            }
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// `bytes` appended to a scripted session's output, up to [`SCRIPT_OUTPUT_MAX`] in all (the rest dropped).
fn keep(out: &mut Vec<u8>, bytes: &[u8]) {
    let room = SCRIPT_OUTPUT_MAX.saturating_sub(out.len());
    out.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

/// Where `needle` first occurs in `hay` (an empty needle at 0).
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The scripted shell on VM `id`: `GetMicrovm` (it must be RUNNING), a
/// shell token (the VM must have `SHELL_INGRESS`: a `ValidationException`
/// gets the `vm run --shell` hint), the dial (`transport::dial_shell`), then
/// [`run_script_over`]. Callers refuse the file-backed fake before this
/// ([`fake_backend_refusal`]): it would dial the fake's endpoint name.
pub async fn run_script<A: MicrovmApi>(api: &A, id: &str, script: &str, budget: Duration, auth: ShellAuth) -> Result<String, BridgeError> {
    run_script_frames(api, id, script, &[], budget, auth).await
}

/// [`run_script`] with more input typed as the remote asks for it
/// ([`run_script_frames_over`], [`Gated`]): the egress check's presigned URLs,
/// typed only once its script has turned the terminal's echo off and is about
/// to read them. Every other step is `run_script`'s (RUNNING, the shell token,
/// the dial).
pub async fn run_script_frames<A: MicrovmApi>(api: &A, id: &str, script: &str, gated: &[Gated<'_>], budget: Duration, auth: ShellAuth) -> Result<String, BridgeError> {
    let vm = api.get(id).await?;
    if vm.state.is_terminal() {
        return Err(BridgeError::Terminated(format!("{id} is {}", vm.state.as_str())));
    }
    if vm.state != VmState::Running {
        return Err(BridgeError::Conflict(format!("{id} is {}, not RUNNING: the scripted shell needs a running VM", vm.state.as_str())));
    }
    let token = match api.create_shell_token(id, SCRIPT_TOKEN_MINUTES).await {
        Ok(t) => t,
        Err(BridgeError::Validation(m)) => {
            return Err(BridgeError::Validation(format!("{m} — start the VM with `ai-env vm run --egress vpc --shell` (the SHELL_INGRESS connector)")));
        }
        Err(e) => return Err(e),
    };
    crate::wire::redact::register_secret(token.value()?.expose());
    let ws = dial_shell(&vm.endpoint, token.value()?, auth).await?;
    run_script_frames_over(ws, script, gated, budget).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::{managed_connector_arn, Call, FakeMicrovmApi, IdleSpec, RunSpec, FAKE_IMAGE_ARN};
    use tokio_tungstenite::tungstenite::error::{Error as WsError, ProtocolError};

    fn spec(token: &str, shell: bool) -> RunSpec {
        RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: if shell { vec![managed_connector_arn("HTTP_INGRESS"), managed_connector_arn("SHELL_INGRESS")] } else { vec![] },
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: token.into(),
        }
    }

    #[test]
    fn the_fake_refusal_is_a_policy_refusal() {
        let e = fake_backend_refusal("egress check");
        assert!(matches!(&e, BridgeError::Policy(m) if m.starts_with("egress check: the file-backed fake cannot carry a shell")), "{e}");
        assert_eq!(crate::errors::CliError::from(e).exit_code(), 9);
    }

    /// A gated part's `after` is found anywhere in the output, also across what came in two frames; an empty one at
    /// once.
    #[test]
    fn find_locates_a_gate_and_an_empty_one_at_once() {
        assert_eq!(find(b"bash-5.2# x\r\n@@AIENV0123 urls\r\n", b"@@AIENV0123 urls"), Some(13));
        assert_eq!(find(b"@@AIENV0123 url", b"@@AIENV0123 urls"), None);
        assert_eq!((find(b"", b""), find(b"abc", b"")), (Some(0), Some(0)));
        assert_eq!(find(b"", b"x"), None);
        let mut out = Vec::new();
        keep(&mut out, &vec![b'x'; SCRIPT_OUTPUT_MAX - 2]);
        keep(&mut out, b"GO");
        keep(&mut out, b"GO");
        assert_eq!((out.len(), find(&out, b"GOGO")), (SCRIPT_OUTPUT_MAX, None), "past the cap nothing is kept, nor found");
    }

    #[test]
    fn a_reset_after_exit_ends_the_session() {
        for e in [WsError::ConnectionClosed, WsError::AlreadyClosed, WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake), WsError::Io(std::io::ErrorKind::ConnectionReset.into())] {
            assert!(ended(&e), "{e}");
        }
        for e in [WsError::Protocol(ProtocolError::HandshakeIncomplete), WsError::Io(std::io::ErrorKind::PermissionDenied.into()), WsError::Utf8] {
            assert!(!ended(&e), "{e}");
        }
    }

    /// Everything `run_script` refuses before it asks for a token or dials (the fake's endpoint is never dialled).
    #[tokio::test]
    async fn run_script_needs_a_running_vm_with_the_shell() {
        let api = FakeMicrovmApi::new();
        let pending = api.run(&spec("t-pending", true)).await.unwrap();
        let e = run_script(&api, &pending.id, "exit\n", Duration::from_secs(1), ShellAuth::Header).await.unwrap_err();
        assert!(matches!(&e, BridgeError::Conflict(m) if m.contains("not RUNNING")), "{e}");
        let plain = api.run(&spec("t-plain", false)).await.unwrap();
        api.advance_all();
        let e = run_script(&api, &plain.id, "exit\n", Duration::from_secs(1), ShellAuth::Header).await.unwrap_err();
        assert!(matches!(&e, BridgeError::Validation(m) if m.contains("vm run --egress vpc --shell")), "{e}");
        api.terminate(&pending.id).await.unwrap();
        let e = run_script(&api, &pending.id, "exit\n", Duration::from_secs(1), ShellAuth::Header).await.unwrap_err();
        assert!(matches!(e, BridgeError::Terminated(_)), "{e}");
        let tokens: Vec<Call> = api.calls().into_iter().filter(|c| matches!(c, Call::ShellToken { .. })).collect();
        assert_eq!(tokens, [Call::ShellToken { id: plain.id.clone(), minutes: SCRIPT_TOKEN_MINUTES }], "a token only for the RUNNING VM");
    }
}
