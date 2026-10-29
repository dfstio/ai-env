//! The VM session token of a remote spawn (S13, WM-R50 to WM-R53, WM-R62; LD-WM2 to LD-WM5). Each new spawn (a
//! new chat, a retry, a move; never a reattach) asks this Mac's `ai-env relay agent` for a token naming its VM,
//! its spawn id, the chat it resumes or moves, and the workspace's grant, within 2 s; a minted token becomes the
//! spawn's relay session (`wire::relay::RelaySpawn`: the token, the relay's private face from the constants
//! `RELAY_IP` and `RELAY_PORT`, `RELAY_IP` as the name its certificate carries, and `state/relay-ca.der`), which
//! rides the spawn's credential delivery to its own VM only (`agent::Delivery::with_relay`).
//!
//! Nothing here fails or delays a spawn past its 2 s: every other outcome is a word for `session_remote_start`
//! (`relay=<word>`, none for `off`) and the chat runs without relay tools. The wrapper's own Touch ID stays its
//! only one: the agent, not the wrapper, holds the session key.
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::egress::{RELAY_IP, RELAY_PORT};
use crate::bridge::vm::registry::VmRow;
use crate::bridge::voice;
use crate::bridge::workspace::{workspace_cfg, WorkspaceRef};
use crate::wire::frame::{SpawnId, CAP_RELAY_V1};
use crate::wire::redact::Secret;
use crate::wire::relay::RelaySpawn;
use ai_env_worker::agent::{request, MintRequest, Request, Response};
use ai_env_worker::globs::valid_id;
use ai_env_worker::session::SESSION_MAX_S;
use std::time::Duration;

/// The whole ask's budget (WM-R51, WM-R53): connect, request and answer.
pub const MINT_BUDGET: Duration = Duration::from_secs(2);
/// The least a token must live to be worth asking for (WM-R51: `wall` below it).
const MINT_MIN_S: u64 = 60;

/// What [`for_spawn`] made: a relay session, or the word saying why there is none.
pub enum MintOutcome {
    Minted(RelaySpawn),
    /// `off` (no grant), `bad_config`, `no_cap`, `wall`, `no_ca`, `no_agent` or `agent_error`.
    Skipped(&'static str),
}

impl MintOutcome {
    /// `minted`, or the skip's word: `session_remote_start`'s `relay` value.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            MintOutcome::Minted(_) => "minted",
            MintOutcome::Skipped(word) => word,
        }
    }

    /// The relay session, when one was minted.
    #[must_use]
    pub fn into_spawn(self) -> Option<RelaySpawn> {
        match self {
            MintOutcome::Minted(spawn) => Some(spawn),
            MintOutcome::Skipped(_) => None,
        }
    }
}

impl std::fmt::Debug for MintOutcome {
    /// `Minted(RelaySpawn(…))` (never the token) or `Skipped(<word>)`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintOutcome::Minted(spawn) => write!(f, "Minted({spawn:?})"),
            MintOutcome::Skipped(word) => write!(f, "Skipped({word})"),
        }
    }
}

/// The token of the spawn `spawn_id` on the VM of `row` (WM-R50 to WM-R52), asked of this Mac's agent in this
/// order, the first that applies its word: the grant (`[[workspace]].relay_grant`, else `[relay].grant`) empty
/// `off`; the grant or `[relay].worker_id` not an id `bad_config`; the VM's shim without `relay_v1` `no_cap`;
/// less than a minute before `min(now + 8 h, the VM's wall)` `wall`; no `state/relay-ca.der` `no_ca`; no agent
/// socket `no_agent`; then one `mint_session` within 2 s: a token is `minted`, no answer `no_agent`, a refusal
/// `agent_error`. With a grant set, `no_agent` and `agent_error` say one note (WM-R53): its refusal's code is
/// known only here.
pub async fn for_spawn(cfg: &BridgeConfig, paths: &Paths, ws: &WorkspaceRef, row: &VmRow, spawn_id: &SpawnId, chat: Option<&str>, now: u64) -> MintOutcome {
    let (outcome, code) = ask(cfg, paths, ws, row, spawn_id, chat, now).await;
    if let Some(note) = note_of(&outcome, code.as_deref()) {
        voice::note(&note);
    }
    outcome
}

/// WM-R53's note for `outcome` (`code`: the agent's refusal beside an `agent_error`), when it says one: only
/// `no_agent` and `agent_error`, which arise with a grant set.
fn note_of(outcome: &MintOutcome, code: Option<&str>) -> Option<String> {
    match outcome {
        MintOutcome::Skipped("no_agent") => Some("relay: no relay agent answers on this Mac (ai-env relay agent): this chat runs without relay tools".to_string()),
        MintOutcome::Skipped("agent_error") => Some(format!("relay: the relay agent refused this chat's token ({}): this chat runs without relay tools", code.unwrap_or("no token"))),
        _ => None,
    }
}

/// [`for_spawn`]'s steps; beside an `agent_error`, the agent's code when it named one (a word only).
async fn ask(cfg: &BridgeConfig, paths: &Paths, ws: &WorkspaceRef, row: &VmRow, spawn_id: &SpawnId, chat: Option<&str>, now: u64) -> (MintOutcome, Option<String>) {
    let skip = |word: &'static str| (MintOutcome::Skipped(word), None);
    let grant = workspace_cfg(cfg, ws).and_then(|w| w.relay_grant.clone()).unwrap_or_else(|| cfg.relay.grant.clone());
    if grant.is_empty() {
        return skip("off");
    }
    if !valid_id(&grant) || !valid_id(&cfg.relay.worker_id) {
        return skip("bad_config");
    }
    if !row.caps.as_ref().is_some_and(|caps| caps.iter().any(|c| c == CAP_RELAY_V1)) {
        return skip("no_cap");
    }
    let exp = row.wall_deadline.map_or(now + SESSION_MAX_S, |wall| wall.min(now + SESSION_MAX_S));
    if exp < now + MINT_MIN_S {
        return skip("wall");
    }
    let Some(ca_der_b64) = super::tls::ca_der_b64(paths) else {
        return skip("no_ca");
    };
    let socket = paths.relay_agent_socket();
    if std::fs::symlink_metadata(&socket).is_err() {
        return skip("no_agent");
    }
    let req = Request::MintSession(MintRequest { vm_id: row.id.clone(), session_id: spawn_id.to_string(), chat_id: chat.map(str::to_string), grant_id: grant, exp });
    match request(&socket, &req, MINT_BUDGET).await {
        Ok(Response::Minted { token, .. }) => {
            let spawn = RelaySpawn { token: Secret::new(token), addr: format!("{RELAY_IP}:{RELAY_PORT}"), server_name: RELAY_IP.to_string(), ca_der_b64 };
            match spawn.check() {
                Ok(()) => (MintOutcome::Minted(spawn), None),
                Err(why) => {
                    tracing::warn!("relay: the minted session is refused ({why})");
                    (MintOutcome::Skipped("agent_error"), Some("bad_token".into()))
                }
            }
        }
        Ok(Response::Refused { error, .. }) => {
            let code = Some(error).filter(|e| !e.is_empty() && e.len() <= 32 && e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
            (MintOutcome::Skipped("agent_error"), code)
        }
        Ok(_) => skip("agent_error"),
        Err(e) => {
            tracing::info!("relay: no token from the agent: {e}");
            skip("no_agent")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::workspace::{Head, WsKind};
    use crate::wire::workspace::ObjectFormat;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    const VM: &str = "microvm-0199a1b2-0000-7000-8000-000000000001";
    const CHAT: &str = "0199a1b2-0000-4000-8000-000000000003";

    /// What the fake agent does with each request.
    #[derive(Clone, Copy)]
    enum Script {
        Mint,
        Refuse,
        Mute,
    }

    /// An in-process fake agent on `<root>/state/relay-agent.sock`: every request line it took, in order.
    fn fake_agent(paths: &Paths, script: Script) -> Arc<Mutex<Vec<ai_env_worker::agent::Request>>> {
        let socket = paths.relay_agent_socket();
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut line = Vec::new();
                    let _ = tokio::io::BufReader::new(read).read_until(b'\n', &mut line).await;
                    let req = ai_env_worker::agent::decode_request(&line).unwrap();
                    log.lock().unwrap().push(req);
                    let answer = match script {
                        Script::Mint => Response::Minted { token: format!("v1.{}.{}", "eyJh".repeat(10), "c2ln".repeat(5)), exp: 0 },
                        Script::Refuse => Response::Refused { error: "unknown_grant".into(), message: "no such grant".into() },
                        Script::Mute => {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            return;
                        }
                    };
                    let _ = write.write_all(&ai_env_worker::agent::encode_response(&answer)).await;
                });
            }
        });
        seen
    }

    /// A bridge root under /tmp holding `config` and, when `ca`, `state/relay-ca.der`; a workspace in it.
    fn world(config: &str, ca: bool) -> (tempfile::TempDir, Paths, WorkspaceRef) {
        let t = tempfile::Builder::new().prefix("aem").tempdir_in("/tmp").unwrap();
        let paths = Paths::from_root_and_env(t.path().join("b"), None);
        std::fs::create_dir_all(paths.root.join("state")).unwrap();
        let work = std::fs::canonicalize(t.path()).unwrap().join("w");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(&paths.config, config.replace("@W@", &work.display().to_string())).unwrap();
        if ca {
            std::fs::write(paths.root.join("state").join("relay-ca.der"), ca_der()).unwrap();
        }
        let kind = WsKind::Git { git_dir: work.join(".git"), common_dir: work.join(".git"), object_format: ObjectFormat::Sha1 };
        let ws = WorkspaceRef { cwd: work.clone(), root: work.clone(), vm_cwd: work.display().to_string(), vm_root: work.display().to_string(), slug: "w".into(), kind, head: Head::Detached { sha: "a".repeat(40) }, seed_branch: None };
        (t, paths, ws)
    }

    /// A DER-shaped stand-in for the CA's certificate (only its bytes travel here).
    fn ca_der() -> Vec<u8> {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(std::iter::repeat_n(0x5a, 256));
        der
    }

    fn row(caps: Option<&[&str]>, wall: Option<u64>) -> VmRow {
        VmRow { id: VM.into(), caps: caps.map(|c| c.iter().map(|s| (*s).to_string()).collect()), wall_deadline: wall, egress: "vpc".into(), ..VmRow::default() }
    }

    fn cfg_of(paths: &Paths) -> BridgeConfig {
        BridgeConfig::load(paths).unwrap().unwrap()
    }

    const GRANTED: &str = "[relay]\ngrant = \"default\"\n";
    const RELAY: &[&str] = &["credential_cache_v1", "relay_v1"];

    /// WM-T36: the mint asks only with a grant, a cap, a wall and an agent, in WM-R51's order, and its token's
    /// relay session names the private face, the IP as the server name and the CA; a workspace's grant wins;
    /// `no_agent` and `agent_error` say WM-R53's notes, the refusal's code in its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_mint_asks_only_with_a_grant_a_cap_a_wall_and_an_agent() {
        let now = crate::wire::time::unix_now();
        let spawn = SpawnId::new_v7();
        let word = |o: &MintOutcome| o.word();
        // No grant, a bad one, no cap (lacking it, or none read yet), a wall under a minute away.
        let (_t, paths, ws) = world("", true);
        let seen = fake_agent(&paths, Script::Mint);
        assert_eq!(word(&for_spawn(&cfg_of(&paths), &paths, &ws, &row(Some(RELAY), None), &spawn, None, now).await), "off");
        let (_t2, p2, ws2) = world("[relay]\ngrant = \"A\"\n", true);
        assert_eq!(word(&for_spawn(&cfg_of(&p2), &p2, &ws2, &row(Some(RELAY), None), &spawn, None, now).await), "bad_config");
        let (_t3, p3, ws3) = world(GRANTED, true);
        let agent3 = fake_agent(&p3, Script::Mint);
        let cfg3 = cfg_of(&p3);
        assert_eq!(word(&for_spawn(&cfg3, &p3, &ws3, &row(Some(&["credential_cache_v1"]), None), &spawn, None, now).await), "no_cap");
        assert_eq!(word(&for_spawn(&cfg3, &p3, &ws3, &row(None, None), &spawn, None, now).await), "no_cap");
        assert_eq!(word(&for_spawn(&cfg3, &p3, &ws3, &row(Some(RELAY), Some(now + 59)), &spawn, None, now).await), "wall");
        assert!(agent3.lock().unwrap().is_empty() && seen.lock().unwrap().is_empty(), "nothing asked of an agent so far");
        // Minted: the request and the session.
        let wall = now + 3600;
        let out = for_spawn(&cfg3, &p3, &ws3, &row(Some(RELAY), Some(wall)), &spawn, Some(CHAT), now).await;
        assert_eq!(out.word(), "minted");
        let session = out.into_spawn().unwrap();
        let base64 = |b: &[u8]| -> String {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(b)
        };
        assert_eq!((session.addr.as_str(), session.server_name.as_str(), session.ca_der_b64.clone()), ("10.42.0.20:7443", "10.42.0.20", base64(&ca_der())));
        assert!(session.token.expose().starts_with("v1.") && session.check().is_ok());
        let req = agent3.lock().unwrap().pop().unwrap();
        let Request::MintSession(m) = req else { panic!("not a mint: {req:?}") };
        assert_eq!(m, MintRequest { vm_id: VM.into(), session_id: spawn.to_string(), chat_id: Some(CHAT.into()), grant_id: "default".into(), exp: wall }, "exp is min(now + 8 h, the wall)");
        let _ = for_spawn(&cfg3, &p3, &ws3, &row(Some(RELAY), None), &spawn, None, now).await;
        let Request::MintSession(m) = agent3.lock().unwrap().pop().unwrap() else { panic!("not a mint") };
        assert_eq!((m.exp, m.chat_id), (now + 28_800, None), "no wall: now + 8 h");
        // No CA (before the socket), no socket, a refusal, an agent that never answers.
        let (_t4, p4, ws4) = world(GRANTED, false);
        let agent4 = fake_agent(&p4, Script::Mint);
        assert_eq!(word(&for_spawn(&cfg_of(&p4), &p4, &ws4, &row(Some(RELAY), None), &spawn, None, now).await), "no_ca");
        assert!(agent4.lock().unwrap().is_empty(), "no_ca is checked before the socket");
        let (_t5, p5, ws5) = world(GRANTED, true);
        assert_eq!(word(&for_spawn(&cfg_of(&p5), &p5, &ws5, &row(Some(RELAY), None), &spawn, None, now).await), "no_agent", "no socket file");
        let _refuser = fake_agent(&p5, Script::Refuse);
        assert_eq!(word(&for_spawn(&cfg_of(&p5), &p5, &ws5, &row(Some(RELAY), None), &spawn, None, now).await), "agent_error");
        // WM-R53's notes: the refusal's code rides its note, no agent has its own, every other word none.
        let (refused, code) = ask(&cfg_of(&p5), &p5, &ws5, &row(Some(RELAY), None), &spawn, None, now).await;
        assert_eq!(note_of(&refused, code.as_deref()).as_deref(), Some("relay: the relay agent refused this chat's token (unknown_grant): this chat runs without relay tools"));
        assert_eq!(note_of(&MintOutcome::Skipped("no_agent"), None).as_deref(), Some("relay: no relay agent answers on this Mac (ai-env relay agent): this chat runs without relay tools"));
        for quiet in ["off", "bad_config", "no_cap", "wall", "no_ca"] {
            assert_eq!(note_of(&MintOutcome::Skipped(quiet), None), None, "{quiet}");
        }
        let _mute = fake_agent(&p5, Script::Mute);
        let t0 = std::time::Instant::now();
        assert_eq!(word(&for_spawn(&cfg_of(&p5), &p5, &ws5, &row(Some(RELAY), None), &spawn, None, now).await), "no_agent", "no answer");
        assert!(t0.elapsed() < MINT_BUDGET + Duration::from_millis(200), "within 2 s and 200 ms: {:?}", t0.elapsed());
        // The workspace's grant wins over [relay].grant; its "" turns the token off.
        let (_t6, p6, ws6) = world("[relay]\ngrant = \"default\"\n\n[[workspace]]\npath = \"@W@\"\nrelay_grant = \"ws-grant\"\n", true);
        let agent6 = fake_agent(&p6, Script::Mint);
        assert_eq!(word(&for_spawn(&cfg_of(&p6), &p6, &ws6, &row(Some(RELAY), None), &spawn, None, now).await), "minted");
        let Request::MintSession(m) = agent6.lock().unwrap().pop().unwrap() else { panic!("not a mint") };
        assert_eq!(m.grant_id, "ws-grant");
        let (_t7, p7, ws7) = world("[relay]\ngrant = \"default\"\n\n[[workspace]]\npath = \"@W@\"\nrelay_grant = \"\"\n", true);
        assert_eq!(word(&for_spawn(&cfg_of(&p7), &p7, &ws7, &row(Some(RELAY), None), &spawn, None, now).await), "off");
    }
}
