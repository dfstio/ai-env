//! The `vm shell` pump over loopback (plan S4 D11): a plain-TCP WebSocket
//! server built here (the TLS dial lives in `bridge::transport`; `src/`
//! has no plaintext client), the pump generic over the stream. Bytes typed go
//! out as binary frames, binary and text frames come back to the output, a
//! remote close ends the session, the escape byte quits, and after input EOF
//! replies are still printed until the remote closes or stays quiet.
use ai_env_cli::bridge::vm::shell::{pump, PumpEnd, ESCAPE};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::Message;

/// A server that answers every binary frame with `echo:<bytes>` as a text
/// frame and closes after `close_after` frames; the client side is the pump.
async fn session(input: &'static [u8], escape: Option<u8>, close_after: usize, linger: Duration) -> (PumpEnd, Vec<u8>, Vec<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
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
    let (end, out, got) = session(b"uname -a\n", None, 1, Duration::from_secs(10)).await;
    assert_eq!(end, PumpEnd::RemoteClosed);
    assert_eq!(got, vec![b"uname -a\n".to_vec()]);
    assert_eq!(String::from_utf8(out).unwrap(), "echo:uname -a\n");
}

#[tokio::test]
async fn pump_quits_on_the_escape_byte_after_sending_what_came_before_it() {
    let input: &'static [u8] = &[b'l', b's', ESCAPE, b'x'];
    let (end, _out, got) = session(input, Some(ESCAPE), 99, Duration::from_secs(10)).await;
    assert_eq!(end, PumpEnd::Escaped);
    assert_eq!(got, vec![b"ls".to_vec()], "the escape byte and what follows are never sent");
}

#[tokio::test]
async fn pump_closes_after_input_eof_once_the_remote_is_quiet() {
    // The remote never closes: the session ends by the linger (1 s is ample for a loopback echo).
    let (end, out, got) = session(b"ls\n", None, 99, Duration::from_secs(1)).await;
    assert_eq!(end, PumpEnd::InputEof);
    assert_eq!(got, vec![b"ls\n".to_vec()]);
    assert_eq!(String::from_utf8(out).unwrap(), "echo:ls\n", "the reply after EOF is still printed");
}
