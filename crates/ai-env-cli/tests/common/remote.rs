//! S8's remote link (phase 0; plans/s8-plan.md Part A, plans/s8-design-tests.md
//! §1.2 and §2.2): the rig `Prepared::spawn_on(Link::Remote, …)` runs the real
//! `ai-env-claude` against, all of it in the test's tempdir `<tmp>` (the
//! wrapper's `HOME`):
//! * an in-process native shim (its hooks, app and code routers on loopback,
//!   its own runtime, this user's uid): `--fs-root` `<tmp>/vm`, so a VM path
//!   `/x` is `<tmp>/vm/x` on this disk; `--home` the VM path `<tmp>` there
//!   (`<tmp>/vm<tmp>`): the agent's home is the Mac's `HOME`, as the image's
//!   `/Users/mike` is (Design A), so the workspace's VM path is under it (the
//!   shim's "under `--home`" rule, plan section 6) and the agent's
//!   `CLAUDE_CONFIG_DIR` (`<tmp>/vm<tmp>/.claude`) is never the Mac's
//!   `<tmp>/.claude`; `--claude` the fake (`<tmp>/vm-claude`); `--git` the
//!   fake git (`<tmp>/vm-git`, its log `<tmp>/git-vm.log`), `--helper` the
//!   built `ai-env` and (S9) `--curl` the fake curl (`<tmp>/vm-curl`, its
//!   log `<tmp>/curl-vm.log`);
//! * (S9) the tests' S3 (`fake_s3`), held by the rig: every process's
//!   `AI_ENV_BRIDGE_LAB_S3_ADDR` (the Mac's presigns reach it with the fake
//!   API), and the VM's through the fake curl, which runs the real curl
//!   ([`REAL_CURL`], `S3CURL_REAL`) unless a test gives it knobs of its own
//!   (`RemoteRig::set_vm_curl_knobs`): since the S3 cut-over a remote
//!   session's transcript goes to S3 after each turn and a resume pulls it
//!   back, so the rig's VM moves real bytes to and from the tests' S3;
//! * the routed fake endpoint in front of it (8080 to the app listener, 9418
//!   to the code listener; the platform's hook client for the shim: a VM's
//!   first request runs it there) and the file-backed fake API
//!   (`<tmp>/fake.json`, `auto_advance`; its `/health` names the credential
//!   cache, `workspace_v1`, `git_http_v1` and `transcript_s3_v1`: the VM an
//!   S9 image runs, as the in-process shim serves them). Every process's
//!   `/health/detail` goes through the endpoint to the shim
//!   (`FakeState::health_detail_at`), so a closing suspend reads the VM's
//!   live spawns and S7's `cached_on_vm` its credential cache, as from a real
//!   VM; `/health` stays the fake's, per VM (one shim stands for one VM, and
//!   a `vm run` of a VM no session uses would otherwise run the shim for it);
//! * the green vpc world (`green_world`), its one root the wrapper's cwd
//!   `<tmp>/work`, combined.env built (one Touch ID per credentialed run, D1),
//!   and the Mac's fake git first on `PATH` (`<tmp>/bin/git`, its log
//!   `<tmp>/git-mac.log`);
//! * `<tmp>/work` a git repository with one commit, its author, committer and
//!   dates fixed through the environment (the same id on every run).
//!
//! The shim clears its spawns' environment, so the fake claude's knobs reach
//! it through `<tmp>/vm-claude.knobs`, single-quoted export lines it sources
//! first (`tests/fakes/claude-v2.sh`); its logs are the local link's
//! (`<tmp>/argv.log`, `stdin.log`, `env.log`, `spawn.count`), so a test reads
//! them alike on both links. It reports the workspace's VM path as its cwd
//! (`FAKE_CWD`; the fs_root prefixes the real one) and the Mac's config dir
//! in its mirror frames (`FAKE_CONFIG_DIR`). Every fake here is a hard link
//! of a cached master, never a fresh file (macOS assesses each new
//! executable's first exec, ≈0.3 s, serialised system-wide), so none is
//! ever written over in place.
//!
//! The remote session itself (the link, the pipeline, the data plane) is S8
//! wave 1's (W1 to W4), merged by the lead's integration: the wrapper in
//! remote mode runs through the rig end to end (tests/remote_pump.rs), as do
//! the rig's parts on their own (the routed endpoint, the shim, the green
//! world, `vm exec` through them). The rig's drop first waits, bounded, for
//! the platform hooks the shim is owed and the workspace helpers it runs
//! (`RemoteRig::settle_hooks`), so neither a closing suspend's `/suspend`
//! snapshot nor a per-result code-out's is cut short at a test's end. Every
//! rig holds its binary's wall-clock lane shared while it lives, so a test
//! that measures a close budget, holding the lane alone ([`alone`]), runs
//! beside no other remote session.
//!
//! S10 (plans/s10-contracts.md §8.2): one shim and one disk per VM. The
//! endpoint is routed per VM (`FakeEndpoint::start_per_vm`): the first VM a
//! request reaches gets the shim made with the rig (`rig.shim`, its disk
//! `<tmp>/vm`, so `vm_root()`, `vm_path()`, `vm_projects()` and
//! `vm_spawns()` keep meaning that VM), and each later one, at its first
//! request, a shim of its own, as at its boot: its fs_root `<tmp>/vm-<n>`
//! (n = 2, 3, … in the order of the VMs' first requests), its home the
//! Mac's `HOME` under it, the same fakes and knobs files (`vm-claude`,
//! `vm-git`, `vm-curl`: the fake claude's generations still count on, and
//! its logs stay the rig's), its listeners on the rig's runtime, its fake
//! claude probed. [`RemoteRig::vm_ids`], [`RemoteRig::shim_of`] and the
//! other `_of` accessors name each VM's. The fake API plays the platform's
//! wall (`FakeState::enforce_wall`, set here): a VM ends at `started +
//! max_duration_s`, and the endpoint's tick posts its `/terminate`;
//! [`RemoteRig::bring_wall_near`] ages a VM on both sides. Its end waits
//! for the VM's shim, as the platform's VM ends once its terminate hook
//! returned (`FakeState::terminate_after_hook`, set here too): the
//! endpoint's factory records each VM it runs on a shim (`hook_ran`), each
//! shim's hooks listener its `/terminate` answer (`terminate_answered`,
//! [`answering_terminate`]), and a TERMINATING VM a shim ran turns
//! TERMINATED at the first look after that answer.
//! [`RemoteRig::config`] edits bridge.toml as TOML. The rig's drop waits on
//! every shim's helpers and stops every shim's spawns.
#![allow(dead_code)]

use super::fake_endpoint::{FakeEndpoint, VmFactory, VmRoutes};
use super::green_world::{self, Green};
use super::fake_s3::FakeS3;
use super::{curl_calls, fake_master, git_calls, install_fake_curl, install_fake_git, link_fake, write_knobs, CurlCall, GitCall, FAKE_V2, REMOVED_ENV, SESSION_ARGV};
use ai_env_cli::bridge::api::{Call, FakeState};
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use ai_env_cli::shim::health::{BoundPorts, ProbeSpec, ShimOpts, ShimState};
use ai_env_cli::shim::peer::Peer;
use ai_env_cli::shim::sys::RealSys;
use ai_env_cli::wire::frame::{SpawnStatus, CAP_GIT_HTTP_V1, CAP_PARK_V1, CAP_TRANSCRIPT_S3_V1, CAP_WORKSPACE_V1};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

/// Every wait of the rig: one of its commands, a request through the endpoint.
pub const LIMIT: Duration = Duration::from_secs(60);
/// The lab knob of the remote link's wrapper and of the rig's commands: one
/// second of the session's policy is this many ms.
pub const BACKOFF_MS: u64 = 100;
/// The image version the green world's egress check is recorded for (the fake's one version).
pub const IMAGE_VERSION: &str = "1.0";
/// The real curl the VM's fake curl runs by default (`S3CURL_REAL`): the
/// shim's transfers then reach the tests' S3 as the image's curl reaches S3.
pub const REAL_CURL: &str = "/usr/bin/curl";
/// The fixture repository's branch, its one commit's author (name, email), date and message.
pub const FIXTURE_BRANCH: &str = "main";
pub const FIXTURE_AUTHOR: (&str, &str) = ("ai-env fixture", "fixture@ai-env.invalid");
pub const FIXTURE_DATE: &str = "2026-10-12T08:00:00+00:00";
pub const FIXTURE_MESSAGE: &str = "fixture";
/// S13 (WM-J1): where a test plants, under the rig's tempdir and before the
/// rig, the relay client its shims start (a copy of
/// `tests/fakes/relay-client.sh`) and the MCP config they give a relay
/// spawn's claude: host paths, as `vm-curl`. Each shim names `relay_v1`
/// (and the fake API's `/health` with it) only when both are files at its
/// start (`shim::relay::opts_for`); without them nothing changes.
pub const RELAY_CLIENT: &str = "vm-relay-client";
pub const RELAY_MCP_CONFIG: &str = "vm-relay-mcp.json";

/// Whether a test's variable belongs to the VM side on the remote link: the
/// fake claude's knobs and logs (`FAKE_*`, `ARGV_LOG`), but not the fake
/// age's (`FAKE_AGE_*`: the Mac's Touch ID) nor the fake git's
/// (`FAKE_GIT_*`: the Mac's git; the VM's through
/// [`RemoteRig::set_vm_git_knobs`]).
#[must_use]
pub fn on_vm(name: &str) -> bool {
    name == "ARGV_LOG" || (name.starts_with("FAKE_") && !name.starts_with("FAKE_AGE_") && !name.starts_with("FAKE_GIT_"))
}

/// One request through the routed endpoint ([`RemoteRig::send`]).
pub struct Req<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// Its `x-aws-proxy-port` (the token's own, unless a test says otherwise).
    pub port: u16,
    /// Its `x-aws-proxy-auth`: a token [`RemoteRig::mint`] made.
    pub token: &'a str,
    /// More headers (an `Authorization: Bearer`, a `Content-Type`).
    pub headers: &'a [(&'a str, &'a str)],
    /// The body, sent with its `Content-Length`.
    pub body: &'a [u8],
}

impl<'a> Req<'a> {
    /// `GET path`, its token minted for `port`.
    #[must_use]
    pub fn get(path: &'a str, port: u16, token: &'a str) -> Req<'a> {
        Req { method: "GET", path, port, token, headers: &[], body: &[] }
    }
}

/// The answer to one request through the endpoint.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The status; 0 when no answer's head came (a cut).
    pub status: u16,
    /// Lowercased name and value, in order.
    pub headers: Vec<(String, String)>,
    /// The body (de-chunked).
    pub body: Vec<u8>,
}

impl Reply {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON; panics with it otherwise.
    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {} {}", self.status, self.text()))
    }

    /// An HTTP/1.1 answer as read to its end (a `Connection: close` one).
    fn parse(raw: &[u8]) -> Reply {
        let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
            return Reply { status: 0, headers: Vec::new(), body: Vec::new() };
        };
        let head = String::from_utf8_lossy(&raw[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
        let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
        let rest = &raw[end + 4..];
        let mut reply = Reply { status, headers, body: Vec::new() };
        reply.body = if reply.header("transfer-encoding").is_some_and(|t| t.eq_ignore_ascii_case("chunked")) {
            dechunk(rest)
        } else {
            let len = reply.header("content-length").and_then(|l| l.parse().ok()).unwrap_or(rest.len());
            rest[..len.min(rest.len())].to_vec()
        };
        reply
    }
}

/// A chunked body's data, as far as it came.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(end) = b.windows(2).position(|w| w == b"\r\n") {
        let size_text = String::from_utf8_lossy(&b[..end]).into_owned();
        let Ok(size) = usize::from_str_radix(size_text.split(';').next().unwrap_or_default().trim(), 16) else { break };
        b = &b[end + 2..];
        if size == 0 || b.len() < size {
            out.extend_from_slice(&b[..size.min(b.len())]);
            break;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[(size + 2).min(b.len())..];
    }
    out
}

/// The remote link's world in one tempdir (the module doc).
pub struct RemoteRig {
    root: PathBuf,
    /// The in-process shim of the first VM a request reaches (made with the
    /// rig, probed at its start): the VM of every test before S10.
    pub shim: Arc<ShimState>,
    /// Its listeners on loopback: the runtime hooks, the app port's, the code port's.
    pub hooks: SocketAddr,
    pub app: SocketAddr,
    pub code: SocketAddr,
    /// The endpoint in front of every VM's listeners, routed per VM and
    /// port, the platform's hook client for each VM's shim.
    pub endpoint: FakeEndpoint,
    /// The tests' S3 (S9): every process's `AI_ENV_BRIDGE_LAB_S3_ADDR`.
    s3: FakeS3,
    token: String,
    head: String,
    /// S10: each VM's shim, in the order of its first request (the endpoint's factory, [`vm_factory`], fills it).
    shims: Arc<Mutex<Shims>>,
    /// Every shim's routers and spawns run here; dropped last but for `lane`.
    rt: tokio::runtime::Runtime,
    /// Its share of the binary's wall-clock lane ([`alone`]), kept until all of the rig is gone.
    lane: LaneShare,
}

/// The rig's VMs and their shims (S10), in the order of their first
/// requests; the shim made with the rig waits in `first` for the first VM.
struct Shims {
    first: Option<(Arc<ShimState>, VmRoutes)>,
    vms: Vec<VmShim>,
}

/// One VM's shim and its listeners.
struct VmShim {
    vm: String,
    shim: Arc<ShimState>,
    routes: VmRoutes,
}

impl Drop for RemoteRig {
    fn drop(&mut self) {
        // A closing suspend's `/suspend` (its snapshot) and a code-out still
        // in the VM run to their answer before the shims' helpers are
        // stopped below (bounded).
        self.settle_hooks(SETTLE_LIMIT);
        // Every VM's shim stops its spawns (S10: a shim per VM), side by side.
        let shims = self.all_shims();
        self.rt.block_on(async move {
            let stops: Vec<_> = shims.into_iter().map(|shim| tokio::spawn(async move { tokio::time::timeout(Duration::from_secs(6), shim.spawns.shutdown("test")).await })).collect();
            for stop in stops {
                let _ = stop.await;
            }
        });
    }
}

impl RemoteRig {
    /// The rig in `root` (a canonical tempdir; the module doc's layout). The
    /// shim's first `claude --version` is probed here, as at its boot, so
    /// `/health` and `hello_ok` name the fake's version.
    #[must_use]
    pub fn new(root: &Path) -> RemoteRig {
        RemoteRig::with_vm_knobs(root, &[])
    }

    /// [`RemoteRig::new`] with `knobs` on the VM side's fake from the start,
    /// before the shim's probe, whose answer it keeps (`FAKE_VERSION`: the
    /// claude the VM names in `/health` and `hello_ok`).
    #[must_use]
    pub fn with_vm_knobs(root: &Path, knobs: &[(&str, &str)]) -> RemoteRig {
        // Never beside a test that holds the lane alone (one that measures a close).
        let lane = LaneShare::take();
        for dir in [root.join("bridge"), root.join("keys"), root.join("bin"), root.join("work")] {
            std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
        }
        let work = root.join("work");
        let head = fixture_repo(&work);
        let fake = root.join("fake.json");
        // S10: the platform's wall, asked for (`FakeState::enforce_wall`), and its end waiting for the VM's shim (`terminate_after_hook`).
        std::fs::write(&fake, serde_json::to_string_pretty(&FakeState { auto_advance: true, enforce_wall: true, terminate_after_hook: true, ..FakeState::new() }).expect("the fake's state")).expect("write fake.json");
        link_fake(fake_master(), FAKE_V2, &root.join("vm-claude"));
        install_fake_git(&root.join("bin").join("git"), &root.join("git-mac.log"), &[]);
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().expect("the rig's runtime");
        // The first VM's shim, made now (probed below, once the knobs are
        // written): the endpoint hands it to the first VM a request reaches,
        // and builds every later VM a shim of its own.
        let (shim, routes) = vm_shim(rt.handle(), root, "vm").unwrap_or_else(|e| panic!("the first VM's shim: {e}"));
        let shims = Arc::new(Mutex::new(Shims { first: Some((shim.clone(), routes)), vms: Vec::new() }));
        let endpoint = FakeEndpoint::start_per_vm(&fake, vm_factory(&shims, rt.handle(), root));
        let VmRoutes { hooks, app, code } = routes;
        let rig = RemoteRig { root: root.to_path_buf(), shim, hooks, app, code, endpoint, s3: FakeS3::start(), token: green_world::setup_token("Rr"), head, shims, rt, lane };
        rig.set_vm_knobs(knobs);
        // Installs the VM's fake git (its knobs file with it), which the shim runs only once asked to.
        rig.set_vm_git_knobs(&[]);
        // And the VM's fake curl (S9), which the transcript transfers run: the real curl behind it, to the tests' S3.
        rig.set_vm_curl_knobs(&[("S3CURL_REAL", REAL_CURL)]);
        if let Err(e) = rig.rt.block_on(rig.shim.probe_once()) {
            panic!("the shim's probe of the fake claude: {e}");
        }
        let roots = [work];
        Green { root, fake: &fake, roots: &roots }.seed(&rig.token, IMAGE_VERSION, true, &|args| rig.ai_env(args));
        // An S9 image's VM: its `/health` also names the workspace routes',
        // git smart-HTTP's and the transcript store's capabilities (the S3
        // cut-over: a session reuses no VM without `transcript_s3_v1`), and its
        // `/health/detail` is the shim's own (the VM's live spawns, its
        // credential cache), through the endpoint.
        let at = rig.endpoint.addr;
        let relay = rig.shim.serves_relay();
        rig.update_fake(|s| {
            s.health_caps.extend([CAP_WORKSPACE_V1, CAP_GIT_HTTP_V1, CAP_TRANSCRIPT_S3_V1].map(str::to_string));
            // S10: `park_v1` too once the shim parks (`shim::agent::PARK_SERVED`), as its `hello_ok` names it.
            if ai_env_cli::shim::agent::PARK_SERVED {
                s.health_caps.push(CAP_PARK_V1.to_string());
            }
            // S11, each under its flag as the shim names it (§1 of the contracts' index): part C's three (the rig's
            // shims have a helper; the transfer caps also need `s3xfer::SERVED`), then part A's (they have a store).
            if ai_env_cli::shim::code::MANIFEST_SERVED {
                s.health_caps.push(ai_env_cli::wire::frame::CAP_CODEOUT_MANIFEST_V1.to_string());
            }
            if ai_env_cli::shim::s3xfer::SERVED && ai_env_cli::shim::s3xfer::VIEW_PARENT_SERVED {
                s.health_caps.push(ai_env_cli::wire::frame::CAP_VIEW_PARENT_V1.to_string());
            }
            if ai_env_cli::shim::s3xfer::SERVED && ai_env_cli::shim::s3xfer::GZIP_SERVED {
                s.health_caps.push(ai_env_cli::wire::frame::CAP_TRANSCRIPT_GZIP_V1.to_string());
            }
            if ai_env_cli::shim::claudebin::SERVED {
                s.health_caps.push(ai_env_cli::wire::frame::CAP_CLAUDE_STAGE_V1.to_string());
            }
            // S13 (WM-J1): `relay_v1` when the shims name it (a test planted RELAY_CLIENT and RELAY_MCP_CONFIG).
            if relay {
                s.health_caps.push(ai_env_cli::wire::frame::CAP_RELAY_V1.to_string());
            }
            s.health_detail_at = Some(at);
        });
        rig
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The Mac's workspace: the wrapper's cwd, the fixture repository.
    #[must_use]
    pub fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    /// The workspace's VM path (`wire::workspace::vm_path_of`): the only form
    /// the Mac sends, and the cwd the VM's fake claude reports.
    #[must_use]
    pub fn vm_cwd(&self) -> String {
        ai_env_cli::wire::workspace::vm_path_of(&self.work()).unwrap_or_else(|e| panic!("the workspace's VM path: {e}"))
    }

    /// The fixture repository's one commit.
    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }

    /// The dummy setup-token the green world sealed (built at run time).
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// `<tmp>/bridge`: the wrapper's and the commands' `AI_ENV_BRIDGE_DIR`.
    #[must_use]
    pub fn bridge(&self) -> PathBuf {
        self.root.join("bridge")
    }

    /// A1: the rig's bridge root as ai-env's own `Paths`, which the
    /// accounts' store API takes (`bridge::accounts`).
    #[must_use]
    pub fn paths(&self) -> ai_env_cli::bridge::config::Paths {
        ai_env_cli::bridge::config::Paths::from_root_and_env(self.bridge(), None)
    }

    /// A1: Claude account `name` sealed as `creds account add NAME` seals
    /// one, with no CLI: `CLAUDE_CODE_OAUTH_TOKEN=<token>` encrypted by the
    /// rig's fake age to the keystore's recipients (no `age.log` line: no
    /// decrypt counted), in a container noting `kind`, `chars` and
    /// `account`, written as `credentials/accounts/<name>.env`. The store is
    /// reconciled before (the green world's token adopted as `default`,
    /// byte for byte) and after (the new account's row). Its token, built at
    /// run time from `tail` (`green_world::setup_token`).
    pub fn seal_account(&self, name: &str, tail: &str) -> String {
        let paths = self.paths();
        ai_env_cli::bridge::accounts::reconcile(&paths).unwrap_or_else(|e| panic!("reconcile: {e}"));
        let token = green_world::setup_token(tail);
        let recipients = self.root.join("keys").join("keys").join("ai-env-bridge").join("recipients.txt");
        let mut age = Command::new(self.root.join("bin").join("age"))
            .args(["-e", "-R"])
            .arg(&recipients)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the fake age");
        age.stdin.take().expect("its stdin").write_all(format!("CLAUDE_CODE_OAUTH_TOKEN={token}\n").as_bytes()).expect("the plaintext");
        let out = age.wait_with_output().expect("the fake age's output");
        assert!(out.status.success(), "age -e: {}", String::from_utf8_lossy(&out.stderr));
        let chars = token.len().to_string();
        let text = ai_env_cli::container::write_annotated(&out.stdout, &[("kind", "setup-token"), ("chars", &chars), ("account", name)]).expect("the container");
        for dir in [paths.credentials(), paths.accounts_dir()] {
            std::fs::create_dir_all(&dir).expect("the accounts' dir");
            std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).expect("0700");
        }
        ai_env_cli::store::write_atomic(&paths.account_env(name), text.as_bytes()).expect("the account's file");
        ai_env_cli::bridge::accounts::reconcile(&paths).unwrap_or_else(|e| panic!("reconcile: {e}"));
        token
    }

    #[must_use]
    pub fn fake_path(&self) -> PathBuf {
        self.root.join("fake.json")
    }

    /// The fake API's state (under its lock: `ai-env` processes may be using it).
    #[must_use]
    pub fn fake(&self) -> FakeState {
        FileFakeMicrovmApi::open(&self.fake_path()).and_then(|api| api.snapshot()).expect("the fake's state")
    }

    pub fn update_fake(&self, f: impl FnOnce(&mut FakeState)) {
        FileFakeMicrovmApi::open(&self.fake_path())
            .and_then(|api| {
                api.with(|s| {
                    f(s);
                    Ok(())
                })
            })
            .expect("update the fake's state");
    }

    /// The control-plane calls the fake API recorded, in order.
    #[must_use]
    pub fn fake_calls(&self) -> Vec<Call> {
        self.fake().calls
    }

    /// `<tmp>/vm`: the shim's fs_root, under which every VM path lives.
    #[must_use]
    pub fn vm_root(&self) -> PathBuf {
        self.root.join("vm")
    }

    /// Where the VM's `path` (absolute, as in the VM: a workspace's VM path)
    /// is on this disk: under the shim's fs_root (`ShimState::at`).
    #[must_use]
    pub fn vm_path(&self, path: &Path) -> PathBuf {
        self.shim.at(path)
    }

    /// The VM agent's `HOME` on this disk (the shim's `--home`): the Mac's
    /// `HOME`, its VM path, under the fs_root (`vm_path(root)`).
    #[must_use]
    pub fn vm_home(&self) -> PathBuf {
        self.shim.opts.home.clone()
    }

    /// The VM's transcripts: its `CLAUDE_CONFIG_DIR` (`<home>/.claude`, set by the shim) `/projects`.
    #[must_use]
    pub fn vm_projects(&self) -> PathBuf {
        self.vm_home().join(".claude").join("projects")
    }

    /// The shim's spawns now (id, pid, state).
    #[must_use]
    pub fn vm_spawns(&self) -> Vec<SpawnStatus> {
        self.shim.spawns.status(None)
    }

    /// How many decrypts (Touch IDs) the fake age served so far (the green world's seal made one).
    #[must_use]
    pub fn decrypts(&self) -> usize {
        green_world::decrypts(&self.root.join("age.log"))
    }

    /// The calls the Mac's fake git logged (`<tmp>/bin/git`, first on the wrapper's and the commands' `PATH`).
    #[must_use]
    pub fn mac_git_calls(&self) -> Vec<GitCall> {
        git_calls(&self.root.join("git-mac.log"))
    }

    /// The calls the VM's fake git logged (the shim's `--git`).
    #[must_use]
    pub fn vm_git_calls(&self) -> Vec<GitCall> {
        git_calls(&self.root.join("git-vm.log"))
    }

    /// The VM's fake git's knobs from now on (`FAKE_GIT_FAIL`,
    /// `FAKE_GIT_KEEP_PACK`): the helper runs it with an empty environment.
    pub fn set_vm_git_knobs(&self, knobs: &[(&str, &str)]) {
        install_fake_git(&self.root.join("vm-git"), &self.root.join("git-vm.log"), knobs);
    }

    /// The tests' S3 the rig holds (S9; `AI_ENV_BRIDGE_LAB_S3_ADDR` of its processes).
    #[must_use]
    pub fn s3(&self) -> &FakeS3 {
        &self.s3
    }

    /// The VM's fake curl's knobs from now on (`S3CURL_REAL`, `S3CURL_FAIL`,
    /// `S3CURL_STATUS`, …; S9): the shim runs it with an empty environment.
    /// They replace the rig's default ([`REAL_CURL`]): a test that still wants
    /// the real curl names it again.
    pub fn set_vm_curl_knobs(&self, knobs: &[(&str, &str)]) {
        install_fake_curl(&self.root.join("vm-curl"), &self.root.join("curl-vm.log"), knobs);
    }

    /// The calls the VM's fake curl logged (the shim's `--curl`; S9).
    #[must_use]
    pub fn vm_curl_calls(&self) -> Vec<CurlCall> {
        curl_calls(&self.root.join("curl-vm.log"))
    }

    /// The VM side's fake claude's knobs from now on (`<tmp>/vm-claude.knobs`):
    /// its logs (the local link's files), `FAKE_CWD` (the workspace's VM
    /// path), `FAKE_CONFIG_DIR` (the Mac's `~/.claude`), then `knobs` (a
    /// later one wins).
    pub fn set_vm_knobs(&self, knobs: &[(&str, &str)]) {
        let at = |name: &str| self.root.join(name).display().to_string();
        let (argv, stdin, env, count, config) = (at("argv.log"), at("stdin.log"), at("env.log"), at("spawn.count"), at(".claude"));
        let cwd = self.vm_cwd();
        let mut vars = vec![
            ("ARGV_LOG", argv.as_str()),
            ("FAKE_STDIN_LOG", stdin.as_str()),
            ("FAKE_ENV_LOG", env.as_str()),
            ("FAKE_SPAWN_COUNT", count.as_str()),
            ("FAKE_CWD", cwd.as_str()),
            ("FAKE_CONFIG_DIR", config.as_str()),
        ];
        vars.extend_from_slice(knobs);
        write_knobs(&self.root.join("vm-claude.knobs"), &vars);
    }

    /// What every process of the rig gets: `HOME`, `PATH` (the fake age and
    /// the Mac's fake git first, then `/usr/bin:/bin`), the bridge and key
    /// dirs, no AWS profile, the fake API (its runtime key unsealed with the
    /// fake age), the agent-address knob at the routed endpoint, the S3
    /// knob at the tests' S3 (S9), the lab knob at [`BACKOFF_MS`] and the
    /// fake age's log; what a developer's shell may carry removed first.
    fn environ(&self, cmd: &mut Command) {
        for k in REMOVED_ENV {
            cmd.env_remove(k);
        }
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().into_owned();
            if ["AWS_", "AI_ENV_", "PULUMI_", "CLAUDE_", "FAKE_", "GIT_"].iter().any(|p| k.starts_with(p)) || k == "RUST_LOG" {
                cmd.env_remove(&k);
            }
        }
        cmd.env("HOME", &self.root)
            .env("PATH", format!("{}:/usr/bin:/bin", self.root.join("bin").display()))
            .env("AI_ENV_BRIDGE_DIR", self.bridge())
            .env("AI_ENV_DIR", self.root.join("keys"))
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AI_ENV_BRIDGE_LAB_FAKE_API", self.fake_path())
            .env("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1")
            .env("AI_ENV_BRIDGE_LAB_AGENT_ADDR", self.endpoint.addr.to_string())
            .env("AI_ENV_BRIDGE_LAB_S3_ADDR", self.s3.addr().to_string())
            .env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", BACKOFF_MS.to_string())
            .env("FAKE_AGE_LOG", self.root.join("age.log"));
    }

    /// `ai-env <args>` of this rig (`environ`, the hidden paste read from
    /// stdin, stdin /dev/null), SIGINT, SIGTERM and SIGHUP at their defaults.
    #[must_use]
    pub fn ai_env(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env"));
        default_signals(&mut cmd);
        self.environ(&mut cmd);
        cmd.args(args).env("AI_ENV_PASTE_STDIN", "1").stdin(Stdio::null());
        cmd
    }

    /// `ai-env <args>` run to its end with `stdin` (`None`: /dev/null), bounded by [`LIMIT`].
    pub fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Output {
        bounded(self.ai_env(args), stdin)
    }

    /// `vm run --egress vpc --workspace <work> --json`: the workspace's vpc
    /// VM, which the endpoint runs on the shim at its first request; its id.
    pub fn start_vm(&self) -> String {
        self.vm_run(&[])
    }

    /// `vm run … --new` (S10): one more vpc VM for the workspace, beside the
    /// one it has, which the endpoint runs on a shim of its own at its first
    /// request; its id.
    pub fn start_new_vm(&self) -> String {
        self.vm_run(&["--new"])
    }

    /// `vm run --egress vpc --workspace <work> <more> --json`: the VM's id.
    fn vm_run(&self, more: &[&str]) -> String {
        let work = self.work().display().to_string();
        let mut args = vec!["vm", "run", "--egress", "vpc", "--workspace", &work];
        args.extend_from_slice(more);
        args.push("--json");
        let o = self.run(&args, None);
        assert!(o.status.success(), "vm run: {}", String::from_utf8_lossy(&o.stderr));
        let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("vm run --json ({e}): {}", String::from_utf8_lossy(&o.stdout)));
        v["id"].as_str().unwrap_or_else(|| panic!("no id in {v}")).to_string()
    }

    /// A 5-minute token for `vm`'s `port`, as `CreateMicrovmAuthToken` makes one (recorded with the fake's calls).
    #[must_use]
    pub fn mint(&self, vm: &str, port: u16) -> String {
        let token = FileFakeMicrovmApi::open(&self.fake_path()).and_then(|api| api.with(|s| s.create_auth_token(vm, 5, port))).expect("mint a token");
        token.value().expect("the token's header").expose().to_string()
    }

    /// One request through the routed endpoint to `vm` (its `Host` the VM's
    /// endpoint), `Connection: close`, read to its end within [`LIMIT`]; a
    /// cut gives what came (status 0 without a head).
    pub fn send(&self, vm: &str, req: &Req<'_>) -> Reply {
        let host = self.fake().vms.get(vm).unwrap_or_else(|| panic!("no VM {vm} in the fake")).endpoint.clone();
        let mut head = format!("{} {} HTTP/1.1\r\nHost: {host}\r\nx-aws-proxy-auth: {}\r\nx-aws-proxy-port: {}\r\nConnection: close\r\n", req.method, req.path, req.token, req.port);
        for (k, v) in req.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        if !req.body.is_empty() || matches!(req.method, "PUT" | "POST") {
            head.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
        }
        head.push_str("\r\n");
        let mut s = std::net::TcpStream::connect(self.endpoint.addr).expect("connect to the endpoint");
        s.set_read_timeout(Some(LIMIT)).expect("read timeout");
        s.set_write_timeout(Some(LIMIT)).expect("write timeout");
        // A cut mid-body fails the write; what came back is still read.
        let _ = s.write_all(head.as_bytes()).and_then(|()| s.write_all(req.body));
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        Reply::parse(&raw)
    }

    /// The remote link's wrapper (`Prepared::spawn_on`): `ai-env-claude
    /// <tmp>/claude SESSION_ARGV… extra_args…` in `<tmp>/work` with
    /// `environ` and `AI_ENV_BRIDGE_MODE=remote`; of `envs`, what [`on_vm`]
    /// claims becomes the VM side's knobs ([`RemoteRig::set_vm_knobs`]) and
    /// the rest is set on the wrapper, in order.
    #[must_use]
    pub fn wrapper(&self, extra_args: &[&str], envs: &[(&str, &str)]) -> Command {
        let (vm, mac): (Vec<_>, Vec<_>) = envs.iter().copied().partition(|(k, _)| on_vm(k));
        self.set_vm_knobs(&vm);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env-claude"));
        cmd.arg(self.root.join("claude")).args(SESSION_ARGV).args(extra_args).current_dir(self.work());
        self.environ(&mut cmd);
        cmd.env("AI_ENV_BRIDGE_MODE", "remote");
        for (k, v) in mac {
            cmd.env(k, v);
        }
        cmd
    }
}

/// `work` made a git repository with one commit on [`FIXTURE_BRANCH`]
/// (`README.md`), by the real git with neither the system's nor a global
/// config, its author, committer and dates fixed through the environment:
/// the same commit id on every run. That id.
fn fixture_repo(work: &Path) -> String {
    let git = |args: &[&str]| -> Output {
        let o = Command::new(super::git_real())
            .args(args)
            .current_dir(work)
            .env_clear()
            .env("HOME", work.parent().unwrap_or(work))
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", FIXTURE_AUTHOR.0)
            .env("GIT_AUTHOR_EMAIL", FIXTURE_AUTHOR.1)
            .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
            .env("GIT_COMMITTER_NAME", FIXTURE_AUTHOR.0)
            .env("GIT_COMMITTER_EMAIL", FIXTURE_AUTHOR.1)
            .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
            .stdin(Stdio::null())
            .output()
            .expect("run the real git");
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        o
    };
    git(&["init", "-q", "-b", FIXTURE_BRANCH]);
    std::fs::write(work.join("README.md"), "fixture\n").expect("write README.md");
    git(&["add", "README.md"]);
    git(&["commit", "-q", "-m", FIXTURE_MESSAGE]);
    String::from_utf8_lossy(&git(&["rev-parse", "HEAD"]).stdout).trim().to_string()
}

/// A VM's in-process shim (S10: one per VM), its three listeners served on
/// `rt`: its fs_root `<root>/<dir>`, its home the Mac's `HOME` (`root`)
/// under it, made as the image's /Users/mike is; the rig's fakes and their
/// knobs files (`vm-claude`, `vm-git`, `vm-curl`), this user's uid and gid,
/// the built `ai-env` its helper; its hooks' `/terminate` answers recorded
/// in the rig's fake ([`answering_terminate`]). Bound, not probed.
fn vm_shim(rt: &tokio::runtime::Handle, root: &Path, dir: &str) -> std::io::Result<(Arc<ShimState>, VmRoutes)> {
    let fs_root = root.join(dir);
    let home = fs_root.join(root.strip_prefix("/").unwrap_or(root));
    std::fs::create_dir_all(&home)?;
    // SAFETY: getuid and getgid cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let opts = ShimOpts {
        fs_root: Some(fs_root),
        home,
        uid,
        gid,
        helper: Some(PathBuf::from(env!("CARGO_BIN_EXE_ai-env"))),
        git: root.join("vm-git"),
        curl: root.join("vm-curl"),
        relay_client: root.join(RELAY_CLIENT),
        relay_mcp_config: root.join(RELAY_MCP_CONFIG),
        ..ShimOpts::default()
    };
    let shim = Arc::new(ShimState::with(root.join("vm-claude"), opts, ProbeSpec::default(), Arc::new(RealSys)));
    shim.set_bound();
    let hooks_router = answering_terminate(ai_env_cli::shim::hooks::router(shim.clone()), shim.clone(), root.join("fake.json"));
    let (hooks, app, code) = rt.block_on(async {
        (
            serve(hooks_router).await,
            serve(ai_env_cli::shim::health::router(shim.clone())).await,
            serve(ai_env_cli::shim::code::router(shim.clone())).await,
        )
    });
    shim.set_ports(BoundPorts { hooks: hooks.port(), app: app.port(), code: code.port() });
    Ok((shim, VmRoutes { hooks, app, code }))
}

/// How long the endpoint waits for a hook's answer (its `STEP_LIMIT`):
/// past it the platform's end no longer waits for the shim.
const HOOK_POST_LIMIT: Duration = Duration::from_secs(10);

/// What a shim's hooks listener needs to record its `/terminate` answers ([`answering_terminate`]).
#[derive(Clone)]
struct TerminateMark {
    shim: Arc<ShimState>,
    fake: PathBuf,
}

/// `router`, a VM shim's hooks, with each `/terminate` answer recorded in
/// the rig's fake at `fake` (S10, `FakeState::terminate_answered`, which
/// `terminate_after_hook` waits for): once the shim's answer is ready,
/// before it goes back (the endpoint records the hook only once it has
/// it), or once the endpoint's post gives up ([`HOOK_POST_LIMIT`], the
/// request then dropped). The VM is the one the shim's `/run` named; a
/// shim no `/run` reached records nothing.
fn answering_terminate(router: axum::Router, shim: Arc<ShimState>, fake: PathBuf) -> axum::Router {
    router.layer(axum::middleware::from_fn_with_state(TerminateMark { shim, fake }, mark_terminate))
}

async fn mark_terminate(axum::extract::State(m): axum::extract::State<TerminateMark>, req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let terminate = req.method() == axum::http::Method::POST && req.uri().path().ends_with("/terminate");
    let Some(vm) = terminate.then(|| m.shim.run.view().microvm_id).flatten() else {
        return next.run(req).await;
    };
    // Detached: it still records the give-up when the endpoint drops the request.
    let gave_up = tokio::spawn(record_terminate_answered(m.fake.clone(), vm.clone(), Some(HOOK_POST_LIMIT)));
    let answer = next.run(req).await;
    gave_up.abort();
    record_terminate_answered(m.fake, vm, None).await;
    answer
}

/// `vm` into the fake's `terminate_answered` (after `after`, when given),
/// under the file's lock, off the runtime's threads; a failure is said on
/// stderr (the VM's wait then ends at `TERMINATE_HOOK_WAIT_S`).
async fn record_terminate_answered(fake: PathBuf, vm: String, after: Option<Duration>) {
    if let Some(after) = after {
        tokio::time::sleep(after).await;
    }
    let saved = tokio::task::spawn_blocking(move || {
        FileFakeMicrovmApi::open(&fake).and_then(|api| {
            api.with(|s| {
                s.terminate_answered.insert(vm);
                Ok(())
            })
        })
    })
    .await;
    if !matches!(saved, Ok(Ok(()))) {
        eprintln!("the rig: a shim's /terminate answer is not recorded in the fake: {saved:?}");
    }
}

/// The endpoint's factory (S10): the first VM a request reaches gets the
/// shim made with the rig; each later one, `<root>/vm-<n>`, a shim of its
/// own (n = 2, 3, …), its fake claude probed as at its boot; a VM keeps its
/// shim. Each VM it hands a shim is recorded in the fake (`hook_ran`): the
/// endpoint runs it there next (`/run`, then every later hook), so its end
/// waits for that shim's `/terminate` answer (`terminate_after_hook`). It
/// runs on the endpoint's blocking threads and blocks on the rig's
/// runtime, `rt`.
fn vm_factory(shims: &Arc<Mutex<Shims>>, rt: &tokio::runtime::Handle, root: &Path) -> VmFactory {
    let (shims, rt, root) = (shims.clone(), rt.clone(), root.to_path_buf());
    Arc::new(move |vm: &str| {
        let routes = {
            let mut s = shims.lock().unwrap_or_else(PoisonError::into_inner);
            match s.vms.iter().find(|v| v.vm == vm) {
                Some(known) => known.routes,
                None => {
                    let (shim, routes) = match s.first.take() {
                        Some(first) => first,
                        None => {
                            let (shim, routes) = vm_shim(&rt, &root, &format!("vm-{}", s.vms.len() + 1))?;
                            rt.block_on(shim.probe_once()).map_err(std::io::Error::other)?;
                            (shim, routes)
                        }
                    };
                    s.vms.push(VmShim { vm: vm.to_string(), shim, routes });
                    routes
                }
            }
        };
        // Outside the shims' lock: the fake's lock never nests in it.
        FileFakeMicrovmApi::open(&root.join("fake.json"))
            .and_then(|api| {
                api.with(|s| {
                    s.hook_ran.insert(vm.to_string());
                    Ok(())
                })
            })
            .map_err(std::io::Error::other)?;
        Ok(routes)
    })
}

/// The `[name]` table of a TOML document, made when it is missing (S10, for
/// [`RemoteRig::config`]'s edits); panics when `name` holds anything else.
pub fn toml_table<'a>(doc: &'a mut toml::Table, name: &str) -> &'a mut toml::Table {
    doc.entry(name).or_insert_with(|| toml::Value::Table(toml::Table::new())).as_table_mut().unwrap_or_else(|| panic!("bridge.toml's {name} is not a table"))
}

/// Serve `router` on 127.0.0.1 (a free port) on the current runtime, as the shim's worker does.
async fn serve(router: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("bind a shim listener");
    let addr = listener.local_addr().expect("the listener's address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service_with_connect_info::<Peer>()).await;
    });
    addr
}

/// The child starts with SIGINT, SIGTERM and SIGHUP at their defaults, as
/// from a terminal (a run under `nohup` would hand them over ignored).
fn default_signals(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: signal(2) is async-signal-safe, and the closure allocates nothing between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::signal(sig, libc::SIG_DFL);
            }
            Ok(())
        });
    }
}

/// Run `cmd` to its end with `stdin` (`None`: /dev/null), bounded by [`LIMIT`]
/// (killed and failed past it; its pipes' readers bounded too: `common::bounded`).
fn bounded(cmd: Command, stdin: Option<&[u8]>) -> Output {
    let what = format!("{:?}", cmd.get_program());
    super::bounded::run_within(cmd, stdin, LIMIT, &what)
}

// ---- S8 wave 2 (W10): what the remote session's own tests add -----------------------------

/// The rig's drop waits this long at most for the hooks the shim is owed
/// and its workspace helpers ([`RemoteRig::settle_hooks`]): one hook post's
/// step limit (10 s) holds a `/suspend` snapshot's 8 s, and a suspend may
/// follow a resume (a code-out the close abandoned can wake the VM again).
pub const SETTLE_LIMIT: Duration = Duration::from_secs(20);

/// What a hook tells the shim of its VM (the endpoint's view, `fake_endpoint::Told`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Told {
    Running,
    Suspended,
    Terminated,
}

/// The wall-clock lane of a test binary (plan R5: a flake is a finding, as
/// `tests/race.rs`'s `SERIAL` keeps it): a test that measures a close
/// budget holds it alone ([`alone`]), every rig holds it shared while it
/// lives ([`LaneShare`]), so no other remote session of the binary runs
/// beside the measurement. A failed test lets it go as it unwinds: a
/// poisoned lane is taken as it is.
static LANE: RwLock<()> = RwLock::new(());

thread_local! {
    /// Whether this thread holds the lane alone: its own rigs take no share.
    static ALONE: Cell<bool> = const { Cell::new(false) };
    /// This thread's share of the lane and how many of its rigs live under
    /// it: a second rig asks for none (a read queued behind a waiting
    /// writer would wait for itself).
    static SHARE: RefCell<(usize, Option<RwLockReadGuard<'static, ()>>)> = const { RefCell::new((0, None)) };
}

/// The lane alone for the calling test until the guard is dropped: the
/// first line of a test that measures a wall-clock budget. Waits until no
/// rig of another test lives; none starts meanwhile. The test's own rigs,
/// made on its thread after this, take no share.
#[must_use]
pub fn alone() -> Alone {
    assert!(SHARE.with_borrow(|(n, _)| *n == 0), "alone() comes before the test's first rig (that rig's share would keep it waiting)");
    let guard = LANE.write().unwrap_or_else(PoisonError::into_inner);
    ALONE.set(true);
    Alone { _guard: guard }
}

/// The lane held alone ([`alone`]).
pub struct Alone {
    _guard: RwLockWriteGuard<'static, ()>,
}

impl Drop for Alone {
    fn drop(&mut self) {
        ALONE.set(false);
    }
}

/// A rig's share of the lane: the read half, taken by its thread's first
/// rig and let go with the last one; none under [`alone`].
pub struct LaneShare {
    counted: bool,
}

/// A rig's share of the lane ([`LaneShare`]) for a test that runs a rig's
/// session out of this process (S13 WM-J1: in a child of the test binary),
/// held until the guard is dropped: no test measures a close budget alone
/// meanwhile.
#[must_use]
pub fn lane_share() -> LaneShare {
    LaneShare::take()
}

impl LaneShare {
    fn take() -> LaneShare {
        if ALONE.get() {
            return LaneShare { counted: false };
        }
        SHARE.with_borrow_mut(|(n, guard)| {
            if *n == 0 {
                *guard = Some(LANE.read().unwrap_or_else(PoisonError::into_inner));
            }
            *n += 1;
        });
        LaneShare { counted: true }
    }
}

impl Drop for LaneShare {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        // Never panics: a rig dropped as its thread ends finds the share gone already.
        let _ = SHARE.try_with(|share| {
            let mut share = share.borrow_mut();
            share.0 = share.0.saturating_sub(1);
            if share.0 == 0 {
                share.1 = None;
            }
        });
    }
}

impl RemoteRig {
    /// Until each VM's shim was told, and answered, every move the fake's
    /// state made for each VM the endpoint ran (a closing suspend's
    /// `SuspendMicrovm` is a `/suspend` and its snapshot): the last hook
    /// recorded per VM (each recorded once answered, or once its post gave
    /// up) agrees with the VM's state as the endpoint reads it; and until no
    /// workspace helper runs in any shim (a per-result code-out, its WIP
    /// snapshot, still on its way when the wrapper exited). At most
    /// `within`; whether it settled. Never panics (the rig's drop).
    pub fn settle_hooks(&self, within: Duration) -> bool {
        let until = Instant::now() + within;
        loop {
            let state = std::fs::read_to_string(self.fake_path()).ok().and_then(|text| serde_json::from_str::<FakeState>(&text).ok());
            let settled = state.is_some_and(|st| {
                let mut told = std::collections::BTreeMap::new();
                for hook in self.endpoint.hooks() {
                    let to = match hook.name {
                        "run" | "resume" => Told::Running,
                        "suspend" => Told::Suspended,
                        _ => Told::Terminated,
                    };
                    told.insert(hook.vm, to);
                }
                // As the endpoint reads a state (a VM still starting owes nothing yet).
                told.iter().all(|(vm, told)| match st.vms.get(vm).map(|v| &v.state) {
                    Some(ai_env_cli::bridge::api::VmState::Running) => *told == Told::Running,
                    Some(ai_env_cli::bridge::api::VmState::Suspending | ai_env_cli::bridge::api::VmState::Suspended) => *told == Told::Suspended,
                    Some(s) if s.is_terminal() => *told == Told::Terminated,
                    None => *told == Told::Terminated,
                    Some(_) => true,
                })
            });
            if settled && self.all_shims().iter().all(|shim| shim.spawns.helpers() == 0) {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// The VM side's environment dumps (`FAKE_ENV_DUMP` at `<tmp>/vm-env.log`,
    /// tests/fakes/claude-v2.sh): one map of name to value per generation,
    /// in spawn order.
    #[must_use]
    pub fn vm_env_dumps(&self) -> Vec<std::collections::BTreeMap<String, String>> {
        let mut out: Vec<std::collections::BTreeMap<String, String>> = Vec::new();
        for line in std::fs::read_to_string(self.vm_env_log()).unwrap_or_default().lines() {
            if line.starts_with("--- gen ") {
                out.push(std::collections::BTreeMap::new());
            } else if let (Some(dump), Some((name, value))) = (out.last_mut(), line.split_once('=')) {
                dump.insert(name.to_string(), value.to_string());
            }
        }
        out
    }

    /// Where the VM side's fake dumps its environment (`FAKE_ENV_DUMP`).
    #[must_use]
    pub fn vm_env_log(&self) -> PathBuf {
        self.root.join("vm-env.log")
    }
}

// ---- S10 (R): a shim and a disk per VM, the wall, bridge.toml as TOML ----------------------------

impl RemoteRig {
    fn shims(&self) -> MutexGuard<'_, Shims> {
        self.shims.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every shim of the rig: the one made with it first (whether or not a
    /// VM took it), then each later VM's.
    fn all_shims(&self) -> Vec<Arc<ShimState>> {
        let mut out = vec![self.shim.clone()];
        out.extend(self.shims().vms.iter().filter(|v| !Arc::ptr_eq(&v.shim, &self.shim)).map(|v| v.shim.clone()));
        out
    }

    /// The VMs a request through the endpoint reached, in the order of their
    /// first ones: each has a shim and a disk of its own (the first
    /// `rig.shim` and `<tmp>/vm`, the n-th `<tmp>/vm-<n>`).
    #[must_use]
    pub fn vm_ids(&self) -> Vec<String> {
        self.shims().vms.iter().map(|v| v.vm.clone()).collect()
    }

    /// The last VM a request reached first.
    #[must_use]
    pub fn newest_vm(&self) -> Option<String> {
        self.shims().vms.last().map(|v| v.vm.clone())
    }

    /// `vm`'s shim; panics naming `vm` when no request reached it yet.
    #[must_use]
    pub fn shim_of(&self, vm: &str) -> Arc<ShimState> {
        let found = self.shims().vms.iter().find(|v| v.vm == vm).map(|v| v.shim.clone());
        found.unwrap_or_else(|| panic!("no shim for {vm}: no request reached it yet (the rig's VMs: {:?})", self.vm_ids()))
    }

    /// `vm`'s disk: its shim's fs_root (`vm_root()` for the first VM).
    #[must_use]
    pub fn vm_root_of(&self, vm: &str) -> PathBuf {
        self.shim_of(vm).opts.fs_root.clone().unwrap_or_else(|| panic!("{vm}'s shim has no fs_root"))
    }

    /// Where `vm`'s `path` (absolute, as in the VM) is on this disk.
    #[must_use]
    pub fn vm_path_of(&self, vm: &str, path: &Path) -> PathBuf {
        self.shim_of(vm).at(path)
    }

    /// `vm`'s agent `HOME` on this disk: the Mac's `HOME` under its fs_root.
    #[must_use]
    pub fn vm_home_of(&self, vm: &str) -> PathBuf {
        self.shim_of(vm).opts.home.clone()
    }

    /// `vm`'s transcripts: its `CLAUDE_CONFIG_DIR` `/projects`.
    #[must_use]
    pub fn vm_projects_of(&self, vm: &str) -> PathBuf {
        self.vm_home_of(vm).join(".claude").join("projects")
    }

    /// `vm`'s spawns now (id, pid, state).
    #[must_use]
    pub fn vm_spawns_of(&self, vm: &str) -> Vec<SpawnStatus> {
        self.shim_of(vm).spawns.status(None)
    }

    /// Edit bridge.toml as TOML (in place of appending text, which breaks on
    /// a second `[vm]` table): `edit` gets the document ([`toml_table`]
    /// finds or makes a table), written back whole, its comments not kept.
    pub fn config(&self, edit: impl FnOnce(&mut toml::Table)) {
        let path = self.bridge().join("bridge.toml");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut doc: toml::Table = toml::from_str(&text).unwrap_or_else(|e| panic!("{} is no TOML document: {e}", path.display()));
        edit(&mut doc);
        let text = toml::to_string(&doc).unwrap_or_else(|e| panic!("render {}: {e}", path.display()));
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }

    /// Age `vm` so `left_s` seconds of its wall are left: its start in the
    /// fake moved back (`FakeState::age`), and its row's `started_at` and
    /// `wall_deadline` on the Mac set to the same start and wall (a VM with
    /// no row: the fake's alone), so the fake's wall (the rig's
    /// `enforce_wall`: at 0 left the next look ends it) and the Mac's
    /// `wall_left` agree. The row moves first: once the fake is aged, the
    /// rig's tick may end the VM at its wall, which the platform never does
    /// before the row's deadline. Panics when the fake lacks the VM or its
    /// start, or when less than `left_s` is left already.
    pub fn bring_wall_near(&self, vm: &str, left_s: u64) {
        let now = ai_env_cli::wire::time::unix_now();
        let st = self.fake();
        let v = st.vms.get(vm).unwrap_or_else(|| panic!("no VM {vm} in the fake"));
        let started = v.started_at_unix.and_then(|t| u64::try_from(t).ok()).unwrap_or_else(|| panic!("{vm} has no start in the fake"));
        let wall = started + u64::try_from(v.max_duration_s).unwrap_or(0);
        let by = wall.checked_sub(now + left_s).unwrap_or_else(|| panic!("{vm} has less than {left_s} s of its wall left already ({} s)", wall.saturating_sub(now)));
        let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(self.bridge(), None);
        ai_env_cli::bridge::vm::registry::update_row(&paths, vm, |row| {
            row.started_at = Some(started.saturating_sub(by));
            row.wall_deadline = Some(wall - by);
        })
        .unwrap_or_else(|e| panic!("{vm}'s row: {e}"));
        // Only `age` moves a start: the copy above still holds. Apart from
        // the row's update, so the rows' lock and the fake's never nest.
        self.update_fake(|s| s.age(vm, by));
    }
}

impl super::Prepared {
    /// This tempdir's rig made with `knobs` on the VM side's fake before the
    /// shim's probe ([`RemoteRig::with_vm_knobs`]), unless it was made
    /// already; a later [`RemoteRig::wrapper`] writes the knobs again.
    pub fn rig_with_vm_knobs(&mut self, knobs: &[(&str, &str)]) -> &RemoteRig {
        let root = self.root.clone();
        self.rig.get_or_insert_with(|| RemoteRig::with_vm_knobs(&root, knobs))
    }

    /// Start `cmd`, a wrapper [`RemoteRig::wrapper`] built (in another cwd,
    /// or a second session beside a first), as this tempdir's harness. A
    /// tempdir without the rig only drives the process: the census, the
    /// audit and the fakes' logs it writes are the rig's tempdir's.
    pub fn launch_wrapper(self, cmd: Command) -> super::Harness {
        self.launch(cmd)
    }
}

// ---- S11 (A3): a staged claude for the rig (plans/s11-contracts-A.md §9.5) -----------------------------------

impl RemoteRig {
    /// S11 (A.4): `version`'s staged binary: claude-v2.sh's bytes reporting `version` and reading the rig's
    /// `vm-claude.knobs`, with `defaults` embedded (`curl::fake_claude_bytes`), put in the rig's fake S3 at its
    /// `S3Key::Claude`, and a `staged` record of it under the rig's bridge root (signed, admitted and staged as
    /// A2's writers leave one). A VM fetches it through the real route (`POST /claude/stage`). Its ref.
    pub fn stage_claude(&self, version: &str, defaults: &[(&str, &str)]) -> ai_env_cli::wire::workspace::ClaudeRef {
        use ai_env_cli::bridge::claude::{AdmissionRow, Record, SignatureRow, StagingRow};
        use sha2::Digest as _;
        let bytes = super::curl::fake_claude_bytes(version, Some(&self.root.join("vm-claude.knobs")), defaults);
        let sha256 = hex::encode(sha2::Sha256::digest(&bytes));
        let cref = ai_env_cli::wire::workspace::ClaudeRef { version: version.to_string(), sha256: sha256.clone() };
        let key = cref.key().render();
        let version_id = self.s3.put(&key, &bytes);
        let size = u64::try_from(bytes.len()).expect("a size");
        Record::update(&self.paths(), version, |r| {
            let at = "2026-10-23T10:00:00Z".to_string();
            r.signature = Some(SignatureRow { outcome: "ok".into(), linux_sha256: Some(sha256.clone()), linux_size: Some(size), at: at.clone(), ..SignatureRow::default() });
            r.admission = Some(AdmissionRow { outcome: "admitted".into(), markers: Some("ok".into()), ai_env: "0.1.0".into(), at: at.clone(), ..AdmissionRow::default() });
            r.staging = Some(StagingRow { state: "staged".into(), s3_key: key.clone(), s3_version_id: Some(version_id.clone()), at, ..StagingRow::default() });
        })
        .expect("the staged record");
        cref
    }

    /// S11: [`RemoteRig::wrapper`] handed the claude of the Cursor bundle `ext` (a hard link of the rig's claude
    /// at `<root>/extensions/anthropic.claude-code-<ext>-darwin-arm64/resources/native-binary/claude`): argv[1]
    /// names V, as Cursor's does.
    pub fn wrapper_for_bundle(&self, ext: &str, extra_args: &[&str], envs: &[(&str, &str)]) -> Command {
        let (vm, mac): (Vec<_>, Vec<_>) = envs.iter().copied().partition(|(k, _)| on_vm(k));
        self.set_vm_knobs(&vm);
        let dir = self.root.join("extensions").join(format!("anthropic.claude-code-{ext}-darwin-arm64")).join("resources").join("native-binary");
        std::fs::create_dir_all(&dir).expect("the bundle's directory");
        let claude = dir.join("claude");
        if !claude.exists() {
            std::fs::hard_link(self.root.join("claude"), &claude).or_else(|_| std::fs::copy(self.root.join("claude"), &claude).map(|_| ())).expect("the bundle's claude");
        }
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env-claude"));
        cmd.arg(&claude).args(SESSION_ARGV).args(extra_args).current_dir(self.work());
        self.environ(&mut cmd);
        cmd.env("AI_ENV_BRIDGE_MODE", "remote");
        for (k, v) in mac {
            cmd.env(k, v);
        }
        cmd
    }
}
