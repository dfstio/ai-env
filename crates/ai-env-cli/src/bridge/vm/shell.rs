//! `ai-env vm shell`: the platform's WebSocket shell (experimental; plan S4
//! D11). The shell token comes from `CreateMicrovmShellAuthToken` (the VM must
//! run with the `SHELL_INGRESS` connector: `ai-env vm run --shell`); the
//! dial is `transport::dial_shell`. The frame format is undocumented, so the
//! pump is deliberately dumb: stdin bytes go out as binary frames, binary and
//! text frames come back to stdout, a close ends the session, Ctrl-] quits.
//! On a terminal, stdin is switched to raw mode for the session and restored
//! on every exit path ([`RawMode`]).
use crate::bridge::api::MicrovmApi;
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
                    Some(Ok(Message::Text(t))) => output.write_all(t.as_bytes()).await.map_err(|e| lost(&e))?,
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
