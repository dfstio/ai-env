//! Signers (WM-R8): a signer never signs bytes it is handed; it builds the transcript
//! (`ai_env_source::wire::transcript`) from the challenge's fields itself.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::agent::{self, AgentError, Request, Response, SignRequest};
use crate::globs::valid_relay_id;
use crate::keys::{Alg, KeyFileError, PublicKey, SigningKey};

/// One signature through the agent: one connection, within this budget (WM-R8).
const SIGN_BUDGET: Duration = Duration::from_secs(3);
/// The agent's refusals that a retry cannot cure (WM-R15's refused class); its other answers are transient.
const REFUSALS: [&str; 3] = ["wrong_key", "wrong_worker", "unsupported"];

/// The challenge's fields a signer needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    /// `Challenge.relay_id`.
    pub relay_id: String,
    /// `Challenge.nonce`: 32 bytes.
    pub nonce: Vec<u8>,
    /// The worker's id, as its `Hello` carries it.
    pub worker_id: String,
    /// The worker's `Hello.protocol`.
    pub protocol: u32,
}

/// Signs a worker's handshake.
pub trait Signer: Send + Sync + 'static {
    /// Its algorithm.
    fn alg(&self) -> Alg;
    /// Its public key.
    fn public_key(&self) -> PublicKey;
    /// The worker id this signer signs for, if it is bound to one (an agent's): `build()` refuses another.
    fn bound_worker_id(&self) -> Option<&str> {
        None
    }
    /// The signature of the transcript of `c`, its own `alg` and public key.
    /// The form `#[async_trait]` expands to (LD-P2, Q-WM19), so an impl may be written either way.
    fn sign_worker_auth<'s, 'c, 'f>(&'s self, c: &'c AuthChallenge) -> crate::BoxFuture<'f, Result<[u8; 64], SignError>>
    where
        's: 'f,
        'c: 'f,
        Self: 'f;
}

/// §P's transcript (P-R25) of `c` under `alg` and `public_key`, after WM-R8's checks of the challenge: a
/// 32-byte nonce and a relay id that is a name. Every signer signs these bytes and no others.
pub(crate) fn transcript(c: &AuthChallenge, alg: Alg, public_key: &PublicKey) -> Result<Vec<u8>, SignError> {
    if c.nonce.len() != ai_env_source::wire::NONCE_LEN {
        return Err(SignError::new(format!("the challenge's nonce is {} bytes, not {}", c.nonce.len(), ai_env_source::wire::NONCE_LEN)));
    }
    if !valid_relay_id(&c.relay_id) {
        return Err(SignError::new(format!("the challenge's relay id is not a name ({})", ai_env_source::names::NAME_RULE)));
    }
    Ok(ai_env_source::wire::transcript(&c.relay_id, &c.nonce, &c.worker_id, alg.wire() as i32 as u32, public_key.bytes(), c.protocol))
}

/// A signer over a 0600 key file (servers).
pub struct FileSigner {
    key: SigningKey,
}

impl FileSigner {
    /// The key of that file (`keys::read_key_file`).
    pub fn open(path: impl AsRef<Path>) -> Result<FileSigner, KeyFileError> {
        crate::keys::read_key_file(path.as_ref()).map(FileSigner::from_key)
    }

    /// A signer of this key.
    pub fn from_key(key: SigningKey) -> FileSigner {
        FileSigner { key }
    }
}

impl Signer for FileSigner {
    fn alg(&self) -> Alg {
        Alg::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    fn sign_worker_auth<'s, 'c, 'f>(&'s self, c: &'c AuthChallenge) -> crate::BoxFuture<'f, Result<[u8; 64], SignError>>
    where
        's: 'f,
        'c: 'f,
        Self: 'f,
    {
        let signed = transcript(c, Alg::Ed25519, &self.key.public_key()).map(|t| self.key.sign(&t));
        Box::pin(std::future::ready(signed))
    }
}

/// A signer through the Mac's signing agent (`ai-env relay agent`).
pub struct AgentSigner {
    socket: PathBuf,
    worker_id: String,
    worker_key: PublicKey,
}

impl AgentSigner {
    /// Asks the agent's status once (its worker id and key); `None` is `agent::default_socket_path()`.
    pub async fn connect(socket: Option<PathBuf>) -> Result<AgentSigner, AgentError> {
        let socket = socket
            .or_else(agent::default_socket_path)
            .ok_or_else(|| AgentError::new(format!("no relay agent socket: set {} or HOME", agent::AGENT_SOCKET_ENV)))?;
        match agent::request(&socket, &Request::Status, agent::IO_TIMEOUT).await? {
            Response::Status(s) => Ok(AgentSigner { socket, worker_id: s.worker_id, worker_key: s.worker_key }),
            Response::Refused { error, .. } => Err(AgentError::new(format!("relay agent at {}: refused status: {error}", socket.display()))),
            _ => Err(AgentError::new(format!("relay agent at {}: an answer that is not its status", socket.display()))),
        }
    }
}

impl Signer for AgentSigner {
    fn alg(&self) -> Alg {
        Alg::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.worker_key
    }

    fn bound_worker_id(&self) -> Option<&str> {
        Some(&self.worker_id)
    }

    fn sign_worker_auth<'s, 'c, 'f>(&'s self, c: &'c AuthChallenge) -> crate::BoxFuture<'f, Result<[u8; 64], SignError>>
    where
        's: 'f,
        'c: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            let shown = self.socket.display();
            // Checked here too, so a bad challenge never reaches the agent; the agent builds its own copy.
            let expected = transcript(c, Alg::Ed25519, &self.worker_key).map_err(|e| SignError::new(format!("relay agent at {shown}: {e}")))?;
            let req = Request::SignWorkerAuth(SignRequest {
                worker_id: c.worker_id.clone(),
                relay_id: c.relay_id.clone(),
                nonce: c.nonce.clone(),
                alg: Alg::Ed25519,
                public_key: self.worker_key,
                protocol: c.protocol,
            });
            match agent::request(&self.socket, &req, SIGN_BUDGET).await {
                Ok(Response::Signed { signature }) if self.worker_key.verify(&expected, &signature) => Ok(signature),
                Ok(Response::Signed { .. }) => Err(SignError::new(format!("relay agent at {shown}: its signature does not verify with its worker key"))),
                Ok(Response::Refused { error, message }) => {
                    let text = format!("relay agent at {shown}: refused: {error}: {message}");
                    Err(if REFUSALS.contains(&error.as_str()) { SignError::refusal(text) } else { SignError::new(text) })
                }
                Ok(_) => Err(SignError::new(format!("relay agent at {shown}: an answer that is not a signature"))),
                Err(e) => Err(SignError::new(e.to_string())),
            }
        })
    }
}

/// A signature refused or not made; it names the socket or the check, never a key. Phase 0 freezes the name;
/// W chooses its insides: the text, and whether a retry cannot cure it (WM-R15's refused class).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SignError {
    message: String,
    refusal: bool,
}

impl SignError {
    /// A signature not made (the agent not answering, a bad challenge): the tunnel ends as transient.
    pub fn new(message: impl Into<String>) -> SignError {
        SignError { message: message.into(), refusal: false }
    }

    /// A refusal (a wrong key, a wrong worker, an unsupported protocol): the tunnel ends as refused and the
    /// next dial waits the refused floor (WM-R15, WM-R16).
    pub fn refusal(message: impl Into<String>) -> SignError {
        SignError { message: message.into(), refusal: true }
    }

    /// Whether it is a refusal.
    pub fn is_refusal(&self) -> bool {
        self.refusal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn sha256(bytes: &[u8]) -> String {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn challenge() -> AuthChallenge {
        AuthChallenge { relay_id: "relay-test".into(), nonce: (0u8..32).collect(), worker_id: "worker-a".into(), protocol: 1 }
    }

    /// A signer written with `#[async_trait]` (Q-WM19): the trait's form takes it, behind `Arc<dyn Signer>`.
    struct MacroSigner {
        key: SigningKey,
        bound: Option<String>,
    }

    #[async_trait::async_trait]
    impl Signer for MacroSigner {
        fn alg(&self) -> Alg {
            Alg::Ed25519
        }

        fn public_key(&self) -> PublicKey {
            self.key.public_key()
        }

        fn bound_worker_id(&self) -> Option<&str> {
            self.bound.as_deref()
        }

        async fn sign_worker_auth(&self, c: &AuthChallenge) -> Result<[u8; 64], SignError> {
            tokio::task::yield_now().await;
            transcript(c, Alg::Ed25519, &self.key.public_key()).map(|t| self.key.sign(&t))
        }
    }

    /// WM-T10.
    #[tokio::test]
    async fn file_signer_signs_the_transcript_vector() {
        let signer = FileSigner::from_key(SigningKey::from_seed(&[1u8; 32]).expect("seed"));
        let c = challenge();
        let t = transcript(&c, Alg::Ed25519, &signer.public_key()).expect("a transcript");
        assert_eq!(t.len(), 145);
        assert_eq!(sha256(&t), "57e9fb1870d1bf5b87b5eb9be3a79e5b627f479a590faad275b02ebf01544700");
        let sig = signer.sign_worker_auth(&c).await.expect("signed");
        assert_eq!(sha256(&sig), "b94fb69e27d782f3ba07b9bc73d443590a46f8b9126a092fe2cb854b175200a6");
        assert!(signer.public_key().verify(&t, &sig));
        assert_eq!(signer.alg(), Alg::Ed25519);
        assert_eq!(signer.bound_worker_id(), None);

        let short = AuthChallenge { nonce: vec![0; 31], ..challenge() };
        let e = signer.sign_worker_auth(&short).await.expect_err("31 bytes");
        assert!(e.to_string().contains("31 bytes") && !e.is_refusal(), "{e}");
        let spaced = AuthChallenge { relay_id: "relay test".into(), ..challenge() };
        assert!(signer.sign_worker_auth(&spaced).await.is_err());

        let dyn_signer: Arc<dyn Signer> = Arc::new(MacroSigner { key: SigningKey::from_seed(&[1u8; 32]).expect("seed"), bound: Some("other".into()) });
        let macro_sig = dyn_signer.sign_worker_auth(&c).await.expect("signed");
        assert_eq!(macro_sig, sig, "Ed25519 is deterministic: the same bytes");
        assert_eq!(dyn_signer.bound_worker_id(), Some("other"));
        let spawned = tokio::spawn(async move { dyn_signer.sign_worker_auth(&challenge()).await });
        assert_eq!(spawned.await.expect("joined").expect("signed"), sig);
    }

    /// The agent's half of `AgentSigner`: a socket that answers `status`, then signs or refuses as scripted.
    async fn fake_agent(path: &Path, key: SigningKey, answers: Vec<&'static str>) -> tokio::task::JoinHandle<Vec<Request>> {
        let listener = tokio::net::UnixListener::bind(path).expect("bind");
        tokio::spawn(async move {
            let mut seen = Vec::new();
            for answer in std::iter::once("status").chain(answers) {
                let (stream, _) = listener.accept().await.expect("accept");
                let mut reader = BufReader::new(stream);
                let mut line = Vec::new();
                reader.read_until(b'\n', &mut line).await.expect("a line");
                let req = agent::decode_request(&line).expect("a request");
                let response = match (answer, &req) {
                    ("status", _) => Response::Status(agent::AgentStatus {
                        pid: 1,
                        until: u64::MAX,
                        worker_id: "worker-a".into(),
                        worker_key: key.public_key(),
                        session_key: key.public_key(),
                        signed: 0,
                        minted: 0,
                    }),
                    ("sign", Request::SignWorkerAuth(s)) => {
                        let c = AuthChallenge { relay_id: s.relay_id.clone(), nonce: s.nonce.clone(), worker_id: s.worker_id.clone(), protocol: s.protocol };
                        Response::Signed { signature: key.sign(&transcript(&c, s.alg, &s.public_key).expect("a transcript")) }
                    }
                    ("garbage", _) => Response::Signed { signature: [0u8; 64] },
                    (code, _) => Response::Refused { error: code.into(), message: "scripted".into() },
                };
                reader.get_mut().write_all(&agent::encode_response(&response)).await.expect("answer");
                seen.push(req);
            }
            seen
        })
    }

    #[tokio::test]
    async fn agent_signer_asks_the_status_once_and_checks_each_signature() {
        let dir = tempfile::Builder::new().prefix("aew").tempdir_in("/tmp").expect("a temp dir");
        let path = dir.path().join("agent.sock");
        let key = SigningKey::from_seed(&[1u8; 32]).expect("seed");
        let public = key.public_key();
        let agent = fake_agent(&path, key, vec!["sign", "wrong_worker", "busy", "garbage"]).await;
        let signer = AgentSigner::connect(Some(path.clone())).await.expect("connected");
        assert_eq!((signer.bound_worker_id(), signer.public_key()), (Some("worker-a"), public));

        let c = challenge();
        let sig = signer.sign_worker_auth(&c).await.expect("signed");
        assert!(public.verify(&transcript(&c, Alg::Ed25519, &public).expect("a transcript"), &sig));
        let refused = signer.sign_worker_auth(&c).await.expect_err("refused");
        assert!(refused.is_refusal(), "{refused}");
        let busy = signer.sign_worker_auth(&c).await.expect_err("refused");
        assert!(!busy.is_refusal() && busy.to_string().contains(&path.display().to_string()), "{busy}");
        let garbage = signer.sign_worker_auth(&c).await.expect_err("a bad signature");
        assert!(garbage.to_string().contains("does not verify"), "{garbage}");
        let short = AuthChallenge { nonce: vec![0; 31], ..challenge() };
        let e = signer.sign_worker_auth(&short).await.expect_err("checked before the agent is asked");
        assert!(!e.is_refusal() && e.to_string().contains(&path.display().to_string()) && e.to_string().contains("31 bytes"), "names the socket (WM-R8): {e}");

        let seen = agent.await.expect("the agent ran");
        assert_eq!(seen.len(), 5, "one status, then one connection per signature");
        assert_eq!(seen[0], Request::Status);
        match &seen[1] {
            Request::SignWorkerAuth(s) => assert_eq!((s.worker_id.as_str(), s.relay_id.as_str(), s.nonce.len(), s.public_key), ("worker-a", "relay-test", 32, public)),
            other => panic!("{other:?}"),
        }
        let gone = signer.sign_worker_auth(&c).await.expect_err("no agent");
        assert!(!gone.is_refusal() && gone.to_string().contains(&path.display().to_string()), "{gone}");
        assert!(AgentSigner::connect(Some(dir.path().join("none.sock"))).await.is_err());
    }
}
