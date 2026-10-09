//! `vm exec --with-credential` and `--credential-file` (S7): the Mac side of
//! a credential's way into a VM, around the session's delivery
//! ([`super::Delivery`], `session`).
//!
//! The order makes a local refusal cost no Touch ID, and sends the token only
//! to a VM the gate has just passed:
//! 1. [`check`] (no AWS, no Touch ID): the flags, `[creds]`, `claude --bare`,
//!    the row's shim capabilities, the sealed file, and the gate's local half
//!    ([`credential_precheck`]). `vm warm` and `vm smoke --with-credential`
//!    choose their VM after the Touch ID: before it they run the local half
//!    on the row a run would make, for the image version the configuration
//!    names (`active`: the one `state/infra.toml` records), and `check` once
//!    the VM is chosen.
//! 2. The runtime key ([`backend_for_credential`]): in container mode with a
//!    current `combined.env`, one Touch ID unseals the key and the token
//!    together (D4), before any AWS call, and the token waits in memory for
//!    the pass; otherwise the key alone.
//! 3. [`gate`]: the live reads and [`credential_gate`], which mints the
//!    [`GatePass`]. A refusal drops a token in hand unsent.
//! 4. Without the token in hand, [`cached_on_vm`] reads `/health/detail` and
//!    records the shim's capabilities; only when the VM does not hold this
//!    seal, and its shim can, is the token unsealed: after the gate.
//! 5. [`prepare`] sends a token only under the seal id of the bytes it was
//!    decrypted from, the one [`check`] read, and binds the delivery to the
//!    pass (gating again, without a prompt, once the pass is past half its
//!    life, 45 s, as after a slow Touch ID); the session delivers.
//!
//! Every unseal here is [`unseal_killable`]: a countdown, the
//! `[creds].unseal_timeout_s` deadline, and SIGINT, SIGTERM or SIGHUP close
//! the dialog. Its listeners stay with the command afterwards
//! (`crate::bridge::signals`), so a stop that comes between two phases is
//! never lost, and one that came before an unseal spares its dialog.
//!
//! Audit rows: `credential_gate` (passed, or the refused condition and which
//! half), `credential_unseal` (what, ms, outcome: `ok`, `exit N`, or
//! `stopped` when the command's own stop dropped the unseal), and the
//! session's `credential_deliver`. None carries a value.
use super::{Delivery, DeliveryParts};
use crate::age_cmd::AgeTool;
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo};
use crate::bridge::config::{BridgeConfig, CredentialsSource, Paths};
use crate::bridge::creds::{aws_env_state, AwsEnvState};
use crate::bridge::egress::{credential_gate, credential_precheck, newest_dns_path, ConnectorAlias, ConnectorFacts, EgressVerified, GatePass, LiveEcho};
use crate::bridge::errors::BridgeError;
use crate::bridge::setup_token::{combined_state, parse_combined, parse_token_env, sealed_text, CombinedState, RuntimeKey, SetupToken, TOKEN_VAR};
use crate::bridge::unseal::UnsealJob;
use crate::bridge::vm::cmd::{audit_event, backend, Backend, Ctx};
use crate::bridge::vm::registry::VmRow;
use crate::errors::{CliError, Result};
use crate::store::{validate_key_name, Keystore};
use crate::wire::frame::{Deliver, CAP_CREDENTIAL_CACHE};
use crate::wire::redact::{register_secret, Secret};
use crate::wire::time::unix_now;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// `vm exec`'s credential flags, as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialFlags {
    pub with_credential: bool,
    pub deliver: Option<Deliver>,
    pub file: Option<PathBuf>,
}

/// A credentialed `vm exec`, validated before any Touch ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPlan {
    pub deliver: Deliver,
    /// `--credential-file`: this container's token, for this one spawn.
    pub file: Option<PathBuf>,
    /// The seal id of the file the token comes from ([`seal_tag`]).
    pub tag: String,
}

/// What a credentialed command brings to [`prepare`]: the keystore for a
/// second unseal, and the token when it came with the runtime key, with the
/// seal id the `combined.env` it was decrypted from records for it
/// ([`backend_for_credential`]): [`prepare`] sends it only under the seal id
/// [`check`] read.
pub struct CredentialSupply<'a> {
    pub store: &'a Keystore,
    pub token: Option<(SetupToken, String)>,
}

/// The seal id of a sealed file: the first 16 hex digits of the sha256 of
/// its bytes. It names the container (a token sealed anew is another id),
/// never anything of the token.
#[must_use]
pub fn seal_tag(path: &Path) -> Option<String> {
    let text = crate::bridge::registry::read_regular_file(path).ok()??;
    Some(tag_of(&text))
}

/// [`seal_tag`]'s rule over a sealed text already read: what an unseal says
/// of the bytes it decrypted, never of a second read of the file.
pub(crate) fn tag_of(sealed: &str) -> String {
    use sha2::Digest as _;
    let mut hex = hex::encode(sha2::Sha256::digest(sealed.as_bytes()));
    hex.truncate(16);
    hex
}

/// The seal id a `combined.env` text records for the setup-token it holds:
/// the first 16 hex digits of its `token_file_sha256`, which `creds
/// setup-token` and `creds aws-set` write as the sha256 of the
/// `setup-token.env` text that token came from (the text the one sealed, the
/// one the other unsealed), and build it only while that file still is that
/// text (F2): so it is the [`seal_tag`] of the token's own container. `None`
/// when it records none.
fn combined_token_tag(sealed: &str) -> Option<String> {
    let sha = crate::container::meta(sealed).remove("token_file_sha256")?;
    (sha.len() == 64 && sha.bytes().all(|c| c.is_ascii_hexdigit())).then(|| sha[..16].to_string())
}

/// Is `argv` a `claude` command?
pub(crate) fn is_claude(argv: &[String]) -> bool {
    argv.first().is_some_and(|a| a.rsplit('/').next() == Some("claude"))
}

/// Exit 7 for a VM whose shim, as last read (a `/health` refresh, or
/// [`cached_on_vm`]), does not offer the credential cache. Never read (`vm
/// run` does not read `/health`) is no refusal: the session's `hello_ok`
/// then refuses before any value is sent.
fn cannot_hold(row: &VmRow) -> Option<CliError> {
    row.caps.as_ref().filter(|caps| !caps.iter().any(|c| c == CAP_CREDENTIAL_CACHE)).map(|_| {
        BridgeError::Endpoint(format!(
            "{}'s shim does not offer the {CAP_CREDENTIAL_CACHE} capability (image version {}): an older image cannot hold a credential; start a VM of the current image",
            row.id, row.image_version
        ))
        .into()
    })
}

/// Everything about a credentialed `vm exec` that is decided on this Mac
/// alone (see the module doc); `None` without the credential flags.
pub fn check(cfg: &BridgeConfig, paths: &Paths, row: &VmRow, argv: &[String], flags: &CredentialFlags) -> Result<Option<CredentialPlan>> {
    if !flags.with_credential && flags.file.is_none() {
        if flags.deliver.is_some() {
            return Err(CliError::Usage("--deliver goes with --with-credential or --credential-file".into()));
        }
        return Ok(None);
    }
    cfg.creds.validate()?;
    let deliver = deliver_for(cfg.creds.deliver == "env", flags.deliver)?;
    if is_claude(argv) && argv.iter().skip(1).any(|a| a == "--bare") {
        return Err(CliError::Usage(format!("claude --bare never reads {TOKEN_VAR}: drop --bare, or the credential")));
    }
    // A one-shot `--credential-file` rides its spawn inline: it needs no cache.
    if let Some(e) = cannot_hold(row).filter(|_| flags.file.is_none()) {
        return Err(e);
    }
    let verified = EgressVerified::load(paths)?;
    let dns = newest_dns_path(paths);
    if let Err(r) = credential_precheck(cfg, row, &verified, &dns, unix_now()) {
        audit_event(paths, "credential_gate", &[("id", row.id.clone()), ("result", "refused".into()), ("condition", r.condition.into()), ("half", "local".into())]);
        return Err(r.policy(&row.id).into());
    }
    let (path, hint) = match &flags.file {
        Some(f) => (f.clone(), "give a container that `ai-env creds setup-token` or `ai-env encrypt` made"),
        None => (paths.setup_token_env(), "seal it with `ai-env creds setup-token`"),
    };
    match aws_env_state(&path) {
        AwsEnvState::Sealed => {}
        AwsEnvState::Absent => return Err(CliError::AuthUnavailable(format!("{} does not exist: {hint}", path.display()))),
        AwsEnvState::NotSealed(why) => return Err(CliError::AuthUnavailable(format!("{} {why}: {hint}", path.display()))),
    }
    let tag = seal_tag(&path).ok_or_else(|| CliError::AuthUnavailable(format!("{} cannot be read: {hint}", path.display())))?;
    refuse_rejected(paths, &tag)?;
    Ok(Some(CredentialPlan { deliver, file: flags.file.clone(), tag }))
}

/// How the token reaches the command: `--deliver` when given, else what
/// `[creds] deliver` says (`configured_env`: it says `env`). `env` puts the
/// token where everything the command starts can read it, so only that
/// setting allows it, and it then becomes the default too (exit 9 without
/// it); fd is always allowed.
fn deliver_for(configured_env: bool, flag: Option<Deliver>) -> Result<Deliver> {
    let deliver = flag.unwrap_or(if configured_env { Deliver::Env } else { Deliver::Fd });
    if deliver == Deliver::Env && !configured_env {
        return Err(BridgeError::Policy(
            "--deliver env puts the token in the command's environment, where everything it starts can read it: allow that with [creds] deliver = \"env\", which also makes env the default (README, Credentials), or deliver on fd".into(),
        )
        .into());
    }
    Ok(deliver)
}

/// What `state/creds.toml` knows against sealed containers (S7 D6).
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct CredsState {
    rejected: Vec<Rejection>,
}

/// A sealed token Anthropic refused: by seal id, when, and on which VM.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Rejection {
    pub tag: String,
    pub at: String,
    pub vm: String,
}

/// `state/creds.toml`, or an empty store when it does not exist. One that
/// cannot be read or parsed (a link, not a regular file, broken TOML) is an
/// error naming it, never "nothing refused": it may hold refusals. The
/// error is one line (the parser's own message may span two), as the status
/// row, the doctor row and the wrapper's note that show it are.
fn read_creds_state(paths: &Paths) -> std::result::Result<CredsState, String> {
    let path = paths.creds_state();
    match crate::bridge::registry::read_regular_file(&path) {
        Ok(None) => Ok(CredsState::default()),
        Ok(Some(text)) => toml::from_str(&text).map_err(|e| format!("{} cannot be parsed ({})", path.display(), e.message().lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(", "))),
        // Each names the file already.
        Err(BridgeError::Config(m)) => Err(m),
        Err(e) => Err(e.to_string()),
    }
}

/// The recorded rejection of the token sealed as `tag`, if any; `Err` names
/// a store that cannot be read. Every reader takes that `Err` as "which
/// seals were refused is unknown", never as no refusal (M53): what decides
/// whether to unseal refuses ([`refuse_rejected`], the wrapper's
/// `local-scratch` login), and what only shows it (`creds status`, doctor)
/// says so.
pub fn read_rejection(paths: &Paths, tag: &str) -> std::result::Result<Option<Rejection>, String> {
    Ok(read_creds_state(paths)?.rejected.into_iter().find(|r| r.tag == tag))
}

/// Exit 5, before any Touch ID, for a seal Anthropic already refused: S8's
/// wrapper would otherwise unseal and deliver a known-bad token again and
/// again. A newly sealed token has another seal id, so sealing one clears it.
/// A seal other than `setup-token.env`'s is a `--credential-file` container:
/// only that container is refused. A store that cannot be read refuses too
/// (exit 5, naming it): which seals were refused is then unknown.
pub fn refuse_rejected(paths: &Paths, tag: &str) -> Result<()> {
    let r = read_rejection(paths, tag).map_err(|e| CliError::AuthUnavailable(format!("{e}: which tokens Anthropic refused is unknown, so nothing is unsealed; repair it, or remove it to forget every recorded refusal")))?;
    let Some(r) = r else { return Ok(()) };
    if seal_tag(&paths.setup_token_env()).as_deref() == Some(tag) {
        Err(CliError::AuthUnavailable(format!(
            "the sealed token (seal {tag}) was refused by Anthropic on {} ({}): seal a fresh one with `claude setup-token`, then `ai-env creds setup-token`; nothing was unsealed",
            r.at, r.vm
        )))
    } else {
        Err(CliError::AuthUnavailable(format!(
            "the token given with --credential-file (seal {tag}) was refused by Anthropic on {} ({}): give another container; the sealed setup-token is not affected; nothing was unsealed",
            r.at, r.vm
        )))
    }
}

/// Record that the token sealed as `tag` was refused on `vm_id`: the
/// `state/creds.toml` marker [`refuse_rejected`] reads, and the audit row
/// `credential_rejected` (`how`: `retries` or `text`). Failures are warnings;
/// a store that cannot be read is left as it is (and refuses every seal).
pub(crate) fn record_rejection(paths: &Paths, vm_id: &str, tag: &str, how: &str) {
    let written = update_creds_state(paths, |state| {
        if !state.rejected.iter().any(|r| r.tag == tag) {
            state.rejected.push(Rejection { tag: tag.to_string(), at: crate::wire::time::rfc3339_utc(unix_now()), vm: vm_id.to_string() });
        }
    });
    if let Err(e) = written {
        // Never a panic: `vm exec` gets here after its pump, when a stop may have closed the terminal.
        crate::bridge::signals::say(&format!("ai-env: warning: the rejection of seal {tag} is not recorded ({e})"));
    }
    audit_event(paths, "credential_rejected", &[("id", vm_id.to_string()), ("tag", tag.to_string()), ("how", how.to_string())]);
}

/// Read `state/creds.toml`, apply `f`, write it back — under
/// `flock(state/creds.toml.lock)`, so two refusals recorded at once never
/// undo each other. A store that cannot be read is not written: rewriting it
/// would discard the refusals it holds.
fn update_creds_state(paths: &Paths, f: impl FnOnce(&mut CredsState)) -> std::result::Result<(), String> {
    let path = paths.creds_state();
    if let Some(dir) = path.parent() {
        crate::bridge::registry::ensure_private_dir(dir).map_err(|e| e.to_string())?;
    }
    let mut lock = path.clone().into_os_string();
    lock.push(".lock");
    let _guard = crate::bridge::vm::lock::lock_blocking(Path::new(&lock)).map_err(|e| e.to_string())?;
    let mut state = read_creds_state(paths).map_err(|e| format!("{e}; it is left as it is"))?;
    f(&mut state);
    let text = toml::to_string(&state).map_err(|e| e.to_string())?;
    crate::store::write_atomic(&path, text.as_bytes()).map_err(|e| e.to_string())
}

/// A live read the gate needs failed: exit 7 naming it (`make deploy` grants
/// the runtime key what the gate reads).
fn read_failed(op: &str, e: BridgeError) -> CliError {
    match e {
        BridgeError::AccessDenied(m) => CliError::Aws(format!("{op}, which the credential gate reads, was denied ({m}): `make deploy` grants the runtime key {op}")),
        e => CliError::Aws(format!("{op}, which the credential gate reads, failed: {e}")),
    }
}

/// The gate's live half: the image version's build and the connector's facts
/// read now, concurrently, then [`credential_gate`] on them and `vm`'s
/// `GetMicrovm` echo. Exit 7 for a read that failed (not audited: it returns
/// before the gate runs), 9 for a refusal (audited `credential_gate`).
pub async fn gate<A: MicrovmApi>(cfg: &BridgeConfig, paths: &Paths, api: &A, row: &VmRow, vm: &VmInfo) -> Result<GatePass> {
    let configured = cfg.aws.egress_connector_arn.clone().unwrap_or_default();
    let (versions, connector) = tokio::join!(api.list_image_versions(&vm.image_arn), api.get_network_connector(configured.trim()));
    let versions = versions.map_err(|e| read_failed("ListMicrovmImageVersions", e))?;
    let doc = connector.map_err(|e| read_failed("GetNetworkConnector", e))?;
    let facts = ConnectorFacts::from_get(&doc);
    let created = versions.iter().find(|v| v.version == vm.image_version).and_then(|v| v.created_at_unix);
    let alias = ConnectorAlias::load(paths, configured.trim());
    let live = LiveEcho { connectors: &vm.egress, ingress: &vm.ingress, image: (&vm.image_arn, &vm.image_version), alias: alias.as_ref(), connector: facts.as_ref(), image_created_at: created };
    let verified = EgressVerified::load(paths)?;
    let dns = newest_dns_path(paths);
    match credential_gate(cfg, row, &live, &verified, &dns, unix_now()) {
        Ok(pass) => {
            audit_event(paths, "credential_gate", &[("id", row.id.clone()), ("result", "passed".into()), ("image_version", pass.image_version().to_string())]);
            Ok(pass)
        }
        Err(r) => {
            audit_event(paths, "credential_gate", &[("id", row.id.clone()), ("result", "refused".into()), ("condition", r.condition.into()), ("half", "live".into())]);
            Err(r.policy(&row.id).into())
        }
    }
}

/// Does the VM's cache hold the token sealed as `tag` now? One
/// `/health/detail` read with the row's session token. Anything unreadable
/// is "no": the token is then unsealed rather than a hit assumed, and the
/// session checks again on its `hello_ok` either way. The shim's caps it
/// reads go into the row, as a `/health` refresh records them: a shim
/// without the credential cache holds nothing, and [`unseal_token`] then
/// refuses before the token's Touch ID (the next command, at [`check`]).
pub async fn cached_on_vm<A: MicrovmApi, E: EndpointClient>(paths: &Paths, api: &A, ep: &E, row: &VmRow, vm: &VmInfo, tag: &str) -> bool {
    let endpoint = Some(vm.endpoint.clone()).filter(|e| !e.is_empty()).or_else(|| row.endpoint.clone()).unwrap_or_default();
    let bearer = Secret::new(row.session_token.clone().unwrap_or_default());
    register_secret(bearer.expose());
    let Ok(token) = crate::bridge::vm::token::mint_internal(api, paths, &row.id).await else { return false };
    match ep.get_health_detail(&endpoint, &token, &bearer).await {
        Ok(reply) if reply.status == 200 => reply.detail.is_some_and(|d| {
            record_caps(paths, &row.id, &d.health.caps);
            d.health.caps.iter().any(|c| c == CAP_CREDENTIAL_CACHE) && d.has_credentials && d.credential.credential_name.as_deref() == Some(TOKEN_VAR) && d.credential.credential_tag.as_deref() == Some(tag)
        }),
        _ => false,
    }
}

/// The shim's caps a `/health/detail` read showed, into the VM's row. A
/// failure is a warning: the session's `hello_ok` still refuses a shim that
/// cannot hold the credential before any value is sent.
fn record_caps(paths: &Paths, vm_id: &str, caps: &[String]) {
    if let Err(e) = crate::bridge::vm::registry::update_row(paths, vm_id, |r| r.caps = Some(caps.to_vec())) {
        tracing::warn!("vm {vm_id}: its shim's capabilities are not recorded in its row: {e}");
    }
}

/// The budget of one unseal: `[creds].unseal_timeout_s` (the range is
/// checked by `CredsCfg::validate`, which [`check`] ran), or the lab knob's
/// (`VmKnobs::unseal_timeout`, debug builds only).
fn budget(ctx: &Ctx) -> Duration {
    ctx.knobs.unseal_timeout.unwrap_or_else(|| ctx.cfg.creds.unseal_budget())
}

/// One timed, killable unseal of a sealed credentials file with
/// `[creds].key`: the countdown goes to stderr; the deadline is exit 5 with
/// `deadline`'s advice; SIGINT (130), SIGTERM or SIGHUP (143) close the dialog
/// first, since `age` runs in its own process group and a terminal's signal
/// no longer reaches it. The listeners exist before the dialog does, and stay
/// with the command afterwards (`crate::bridge::signals`): a stop that came
/// before its first prompt, while no phase listened, ends it with no dialog
/// at all; the token's unseal runs inside a phase that listens
/// (`signals::stoppable`), which answers a stop first and drops the unseal
/// before its dialog.
/// Dropping this future (an outer select or timeout) closes the dialog too.
/// Returns the plaintext and the sealed text it was decrypted from (a
/// container: no secret), read once before the dialog: what is said of the
/// plaintext's seal ([`tag_of`], [`combined_token_tag`]) is said of these
/// bytes, never of a second read of a file that may have been sealed anew
/// meanwhile. `checked`: the seal id those bytes must have (what [`check`]
/// read); bytes of another seal are refused before the dialog, exit 5 with
/// nothing unsealed (F16), since the delivery would refuse them once unsealed.
/// The `age --version` probe before the dialog runs in ai-env's own process
/// group, so a terminal's Ctrl-C ends it too: the listeners are taken first,
/// and a stop that came while it ran is the answer (130 or 143), never the
/// failed probe it caused (F19).
pub async fn unseal_killable(store: &Keystore, ctx: &Ctx, path: &Path, what: &str, hint: &str, deadline: &str, checked: Option<&str>) -> Result<(Zeroizing<Vec<u8>>, String)> {
    let key = ctx.cfg.creds.key.as_str();
    validate_key_name(key).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    let text = sealed_text(path, hint)?;
    if let Some(checked) = checked {
        let now = tag_of(&text);
        if now != checked {
            return Err(sealed_anew(path, checked, &now, false));
        }
    }
    let cont = crate::container::read(&text)?;
    let name = crate::select::resolve_for_decrypt(store, Some(key), &cont)?;
    let mut stops = crate::bridge::signals::Stops::take()?;
    let probed = AgeTool::probe();
    let outcome = match stops.pending().await {
        Some(stop) => Err((stop, "before Touch ID was asked for", "")),
        None => match probed {
            Ok(age) => UnsealJob::start(Arc::new(age), store.identity_path(&name), cont.data, budget(ctx), what)
                .with_deadline(deadline)
                .wait_or(stops.next())
                .await
                .map_err(|stop| (stop, "while waiting for Touch ID", "the dialog was closed and ")),
            Err(e) => {
                stops.keep();
                return Err(e);
            }
        },
    };
    stops.keep();
    let plain = outcome.unwrap_or_else(|(stop, when, closed)| {
        crate::bridge::signals::say(&format!("ai-env: stopped {when} ({}): {closed}{what} stayed sealed", stop.name()));
        Err(CliError::Exit(stop.status()))
    })?;
    Ok((plain, text))
}

/// Exit 5 for a token's container sealed anew after [`check`] read it (M38):
/// `checked` its seal id then, `now` the seal id of the bytes read to unseal
/// it. `unsealed`: those bytes were decrypted already (a token in hand); else
/// they were refused before their dialog (F16).
fn sealed_anew(path: &Path, checked: &str, now: &str, unsealed: bool) -> CliError {
    let (bytes, what) = if unsealed { ("in what was unsealed", "nothing was sent") } else { ("in what was about to be unsealed", "nothing was unsealed, nothing was sent") };
    CliError::AuthUnavailable(format!("{} was sealed anew while this command ran (seal {checked} when it was checked, {now} {bytes}): {what}; run the command again", path.display()))
}

/// What a deadline says on an unseal that comes before anything else, and
/// that every credentialed command asks for (so `vm warm` cannot spare it).
const FIRST_PROMPT_DEADLINE: &str = "nothing was started; every credentialed command asks for this prompt: answer the dialog sooner or raise [creds].unseal_timeout_s";

/// One unseal's `credential_unseal` row, written once: `ok` or `exit N` when
/// the unseal ends ([`UnsealRow::end`]), or `stopped` when it is dropped
/// before that. The command's own stop drops it to close its dialog (`vm
/// exec` before its command starts, `vm warm`, the smoke, a lab probe:
/// `signals::stoppable`), and the row still says the unseal was asked for,
/// for how long, and that the command's stop ended it (the command's own
/// row says which signal).
struct UnsealRow<'a> {
    paths: &'a Paths,
    /// The VM (none for `combined`, which comes before one is chosen), then the source.
    fields: Vec<(&'static str, String)>,
    started: Instant,
    written: bool,
}

impl<'a> UnsealRow<'a> {
    fn start(paths: &'a Paths, vm_id: Option<&str>, source: &str) -> UnsealRow<'a> {
        let mut fields: Vec<(&'static str, String)> = vm_id.map(|id| ("id", id.to_string())).into_iter().collect();
        fields.push(("source", source.to_string()));
        UnsealRow { paths, fields, started: Instant::now(), written: false }
    }

    /// The unseal ended: `ok`, or `exit N` for its own failure (a dismissed
    /// dialog, the deadline, a stop its own listeners took).
    fn end<T>(mut self, r: &Result<T>) {
        let outcome = match r {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("exit {}", e.exit_code()),
        };
        self.write(outcome);
    }

    fn write(&mut self, outcome: String) {
        self.written = true;
        let mut pairs = std::mem::take(&mut self.fields);
        pairs.push(("ms", self.started.elapsed().as_millis().to_string()));
        pairs.push(("outcome", outcome));
        audit_event(self.paths, "credential_unseal", &pairs);
    }
}

impl Drop for UnsealRow<'_> {
    fn drop(&mut self) {
        // A panic unwinding through the unseal is no stop.
        if !self.written && !std::thread::panicking() {
            self.write("stopped".into());
        }
    }
}

/// [`unseal_killable`] of the token at `path`, audited `credential_unseal`
/// ([`UnsealRow`]): the token and the seal id of the bytes it was decrypted
/// from, which must be `checked` (a file sealed anew is refused before its
/// dialog, audited `exit 5`). The setup-token is never unsealed for a VM
/// whose shim, as last read, cannot hold it ([`cached_on_vm`] has just read
/// it): exit 7 with no Touch ID, and no row. `--credential-file`'s one-shot
/// delivery needs no cache, and comes only with `vm exec`, before anything
/// started.
async fn unseal_token(store: &Keystore, ctx: &Ctx, path: &Path, what: &'static str, source: &str, vm_id: &str, checked: &str) -> Result<(SetupToken, String)> {
    let one_shot = source == "file";
    if let Some(e) = crate::bridge::vm::registry::read_row(&ctx.paths, vm_id).ok().flatten().as_ref().and_then(cannot_hold).filter(|_| !one_shot) {
        return Err(e);
    }
    let deadline = if one_shot { "nothing was started; answer the dialog sooner or raise [creds].unseal_timeout_s" } else { "nothing was delivered; answer the dialog sooner or raise [creds].unseal_timeout_s" };
    let row = UnsealRow::start(&ctx.paths, Some(vm_id), source);
    let r = unseal_killable(store, ctx, path, what, "seal it with `ai-env creds setup-token`", deadline, Some(checked)).await.and_then(|(plain, sealed)| Ok((parse_token_env(&plain)?, tag_of(&sealed))));
    row.end(&r);
    r
}

/// The backend of a credentialed command, and the token when it came with
/// the runtime key. In container mode the runtime key is unsealed here
/// through [`unseal_killable`], as every unseal of a credentialed command is
/// (a deadline, a countdown, a dialog a signal closes): with a current
/// `combined.env` one Touch ID unseals the key and the token together (D4);
/// otherwise the key alone (a note says the token may cost a second Touch
/// ID). Profile mode, and the fake API without its unseal knob, unseal
/// nothing here ([`backend`]). The token comes with the seal id the text it
/// was decrypted from records for it ([`from_combined`]); a text that
/// records none hands over no token (it is unsealed on its own if needed).
pub async fn backend_for_credential(store: &Keystore, ctx: &Ctx, plan: &CredentialPlan) -> Result<(Backend, Option<(SetupToken, String)>)> {
    let container = matches!(CredentialsSource::parse(&ctx.cfg.aws.credentials)?, CredentialsSource::Container);
    let real_unseal = ctx.knobs.fake_api.is_none() || ctx.knobs.fake_api_unseal;
    if !container || !real_unseal {
        return Ok((backend(store, ctx).await?, None));
    }
    // `--credential-file` always unseals its own file: combined.env's token is not the one it delivers.
    let combined = plan.file.is_none()
        && match combined_state(&ctx.paths) {
            CombinedState::Current => true,
            state => {
                eprintln!("ai-env: combined.env is {}: the setup token is a second Touch ID if the VM does not hold it (`ai-env creds setup-token` rebuilds combined.env)", state.word());
                false
            }
        };
    if !combined {
        let hint = "seal the runtime key with `make runtime-key` (or set [aws] credentials = \"profile:<name>\")";
        let (plain, _) = unseal_killable(store, ctx, &ctx.paths.aws_env(), "the runtime key", hint, FIRST_PROMPT_DEADLINE, None).await?;
        let (id, secret) = crate::bridge::vm::client::parse_runtime_env(&plain)?;
        drop(plain);
        return Ok((connected(ctx, &id, &secret).await?, None));
    }
    let row = UnsealRow::start(&ctx.paths, None, "combined");
    let unsealed = unseal_killable(store, ctx, &ctx.paths.combined_env(), "the runtime key and the setup token", "rebuild it with `ai-env creds setup-token`", FIRST_PROMPT_DEADLINE, None).await;
    row.end(&unsealed);
    let (plain, sealed) = unsealed?;
    let ((id, secret), token) = from_combined(&plain, &sealed)?;
    drop(plain);
    Ok((connected(ctx, &id, &secret).await?, token))
}

/// What a `combined.env` unsealed to hands a credentialed command: the
/// runtime key, and the token with the seal id `sealed`, the text it was
/// decrypted from, records for it ([`combined_token_tag`]), never the one
/// [`check`] read: [`prepare`] compares the two (M38). A text that records
/// none hands over no token, said on stderr (it is unsealed on its own if
/// the VM does not hold it).
fn from_combined(plain: &[u8], sealed: &str) -> Result<(RuntimeKey, Option<(SetupToken, String)>)> {
    let (key, token) = parse_combined(plain)?;
    match combined_token_tag(sealed) {
        Some(tag) => Ok((key, Some((token, tag)))),
        None => {
            // Rebuilt meanwhile by something that records no seal: its token cannot be bound to the one checked.
            eprintln!("ai-env: the combined.env just unsealed records no seal for its setup token: it is not used (the token is unsealed on its own if the VM does not hold it)");
            Ok((key, None))
        }
    }
}

/// The backend on a runtime key unsealed here: the fake API (which does not
/// use it), or the SDK client and the HTTPS endpoint.
async fn connected(ctx: &Ctx, id: &str, secret: &str) -> Result<Backend> {
    let creds = crate::bridge::vm::client::static_creds(id, secret);
    Ok(match &ctx.knobs.fake_api {
        Some(path) => {
            eprintln!("ai-env: {} (unsealed; the fake API does not use it)", creds.describe());
            Backend::Fake(crate::bridge::vm::fake_file::FileFakeMicrovmApi::open(path)?)
        }
        None => {
            eprintln!("ai-env: {}", creds.describe());
            Backend::Sdk(crate::bridge::vm::client::connect(&creds).await, crate::bridge::vm::health::HttpsEndpoint::new()?)
        }
    })
}

/// A delivery ready for the session, and where its token came from:
/// `combined` (with the runtime key), `setup-token` (unsealed now), `cached`
/// (the VM holds it; nothing unsealed) or `file` (`--credential-file`).
pub struct Prepared {
    pub delivery: Delivery,
    pub source: &'static str,
}

impl Prepared {
    /// When the gate pass the delivery is bound to was given (unix seconds):
    /// a re-gate past half the first pass's life binds it to the new one,
    /// which a test of `prepare` checks (the pass itself stays private).
    #[must_use]
    pub fn gated_at(&self) -> u64 {
        self.delivery.pass.at_unix()
    }
}

/// The gate, the token (in hand, cached on the VM, or unsealed now) and the
/// delivery bound to the pass (see the module doc).
pub async fn prepare<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: &VmRow, vm: &VmInfo, plan: &CredentialPlan, supply: CredentialSupply<'_>) -> Result<Prepared> {
    let CredentialSupply { store, token } = supply;
    let mut pass = gate(&ctx.cfg, &ctx.paths, api, row, vm).await?;
    // The token and the seal id of the bytes it was decrypted from; none when the VM holds this seal.
    let (token, source) = if let Some(file) = &plan.file {
        drop(token);
        (Some(unseal_token(store, ctx, file, "the token in --credential-file", "file", &row.id, &plan.tag).await?), "file")
    } else if let Some(t) = token {
        (Some(t), "combined")
    } else if cached_on_vm(&ctx.paths, api, ep, row, vm, &plan.tag).await {
        // The VM holds this seal: its row names it, even if no delivery recorded it.
        record_holder(&ctx.paths, &row.id, &plan.tag, Held::Seen);
        (None, "cached")
    } else {
        (Some(unseal_token(store, ctx, &ctx.paths.setup_token_env(), "the setup token", "setup-token", &row.id, &plan.tag).await?), "setup-token")
    };
    // One rule (M38): the value goes out only under the seal id of the bytes
    // it was decrypted from, which must be the one `check` read. A file sealed
    // anew in between (a `creds setup-token` while this command waited, a
    // `combined.env` rebuilt from it) is refused, never delivered under the
    // old id, which the row, the cache and a rejection would then name. A
    // token unsealed here was held to that before its dialog (F16); a token
    // in hand came with the runtime key, and is held to it now.
    if let Some((_, tag)) = token.as_ref().filter(|(_, tag)| *tag != plan.tag) {
        let path = plan.file.clone().unwrap_or_else(|| ctx.paths.setup_token_env());
        return Err(sealed_anew(&path, &plan.tag, tag, true));
    }
    // An unseal past half the pass's life (a slow Touch ID): gated again,
    // with no new prompt, so the session's dial never starts on a pass about
    // to age out (it sends nothing on one that did: exit 9).
    if !fresh_enough(&pass, &row.id, unix_now()) {
        pass = gate(&ctx.cfg, &ctx.paths, api, row, vm).await?;
    }
    let token = token.map(|(t, _)| t);
    let parts = DeliveryParts { name: TOKEN_VAR.to_string(), tag: plan.tag.clone(), deliver: plan.deliver, secret: token.as_ref().map(SetupToken::frame_secret), one_shot: plan.file.is_some() };
    let mut delivery = Delivery::new(&pass, &row.id, unix_now(), parts)?;
    // A token of a shape the scrubber's rules do not mask whole is masked only
    // while a handle registered it (`parse_token`): the delivery's copy takes
    // that over before this handle goes, until the delivery drops it (M46).
    if token.as_ref().is_some_and(|t| t.prefix().is_none()) {
        delivery.keep_masked();
    }
    drop(token);
    Ok(Prepared { delivery, source })
}

/// Does `pass` still stand for `vm_id` with at least half its life left?
/// [`prepare`] hands the session only such a pass: an 89 s old one, after a
/// Touch ID approved late, would age out on the way to the VM's `hello_ok`.
pub(super) fn fresh_enough(pass: &GatePass, vm_id: &str, now_unix: u64) -> bool {
    pass.check(vm_id, now_unix).is_ok() && now_unix - pass.at_unix() <= crate::bridge::egress::GATE_PASS_MAX_AGE_S / 2
}

/// How [`record_holder`] knows that a VM may hold the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Held {
    /// The value is about to leave the Mac for it (a `credential` frame, or a
    /// one-shot spawn): recorded first, so an answer lost with its socket
    /// never leaves the VM unlisted.
    Sent,
    /// It was seen holding the seal (a cache hit, a spawn found running):
    /// recorded only when the row names no delivery yet (one lost before
    /// this fix, or whose record failed), keeping that one's time.
    Seen,
}

/// The VMs this process already warned about (one warning each says it).
static UNRECORDED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// The VM may hold the credential sealed as `tag` from now on: its row's
/// `credential_at` and `credential_tag`, which `creds status` and `creds
/// forget` list until it is terminated (an over-approximation by design:
/// recorded before the value leaves, whatever comes back). A row that cannot
/// be written, or none at all, is a warning on stderr (once per VM): the
/// holder list would miss the VM.
pub(crate) fn record_holder(paths: &Paths, vm_id: &str, tag: &str, how: Held) {
    use crate::bridge::vm::registry::{read_row, update_row};
    if how == Held::Seen && matches!(read_row(paths, vm_id), Ok(Some(r)) if r.credential_at.is_some()) {
        return;
    }
    let now = unix_now();
    let why = match update_row(paths, vm_id, |r| {
        if how == Held::Sent || r.credential_at.is_none() {
            r.credential_at = Some(now);
            r.credential_tag = Some(tag.to_string());
        }
    }) {
        Ok(Some(_)) => return,
        Ok(None) => "it has no row".to_string(),
        Err(e) => format!("its row was not updated ({e})"),
    };
    tracing::warn!("vm {vm_id}: not recorded as a credential holder: {why}");
    let mut warned = UNRECORDED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !warned.iter().any(|v| v == vm_id) {
        warned.push(vm_id.to_string());
        eprintln!("ai-env: warning: {vm_id} may hold the setup-token (seal {tag}), but {why}: `ai-env creds status` and `creds forget` will not list it; only `ai-env vm terminate {vm_id}` clears its copies");
    }
}

/// The VM acknowledged the credential (`credential_ok`, or a one-shot spawn
/// that started): the audit row `credential_deliver` says how. It means
/// acknowledged; the row recorded the VM before the value left
/// ([`record_holder`]). Shared by the session and `vm warm`.
pub(crate) fn record_delivery(paths: &Paths, vm_id: &str, spawn: Option<&str>, delivery: &Delivery, source: &str) {
    let deliver = if delivery.deliver() == Deliver::Env { "env" } else { "fd" };
    let mut pairs = vec![("id", vm_id.to_string())];
    if let Some(s) = spawn {
        pairs.push(("spawn", s.to_string()));
    }
    pairs.extend([("name", delivery.name().to_string()), ("tag", delivery.tag().to_string()), ("source", source.to_string()), ("deliver", deliver.to_string())]);
    audit_event(paths, "credential_deliver", &pairs);
}

/// What `vm warm` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warmed {
    /// The VM's cache held this seal already: nothing was sent.
    AlreadyHeld,
    Delivered,
}

/// `vm warm`'s delivery, with no spawn: one socket, `hello`, then, unless the
/// VM's cache holds this seal already, the `credential` frame and its
/// answer. The delivery goes only to its own VM, and its value only while
/// its gate pass stands (exit 9, nothing sent). The socket waits out what
/// the session waits out (`warm_socket`). Exit 7 for a shim without the
/// cache or a refusal that does not pass, 8 for a socket that ends first or
/// a VM that never lets one in, 5 for a miss with no value in hand. The
/// delivery is dropped (zeroized) when this returns.
pub async fn deliver_only<A: MicrovmApi, E: EndpointClient>(env: &super::AgentEnv<'_, A, E>, mut delivery: Delivery) -> std::result::Result<Warmed, BridgeError> {
    warm(env, &mut delivery).await
}

/// [`deliver_only`]'s body. The value leaves `delivery` as its frame is
/// built: nothing sends it twice, so the Mac keeps no copy while it waits
/// for the answer.
pub(super) async fn warm<A: MicrovmApi, E: EndpointClient>(env: &super::AgentEnv<'_, A, E>, delivery: &mut Delivery) -> std::result::Result<Warmed, BridgeError> {
    use crate::wire::frame::{CredentialErrCode, EventKind, Frame, CLOSE_NORMAL};
    let vm = env.target.vm_id.as_str();
    delivery.check_target(vm)?;
    register_secret(env.target.session_token.expose());
    let token = crate::bridge::vm::token::mint(env.api, env.paths, vm, crate::bridge::api::APP_PORT, env.policy.token_minutes).await?;
    let (mut conn, ok) = warm_socket(env, &token).await?;
    if !ok.caps.iter().any(|c| c == CAP_CREDENTIAL_CACHE) {
        conn.close(CLOSE_NORMAL).await;
        return Err(BridgeError::Endpoint(format!("{vm} runs a shim that cannot hold a credential (image version {}): start a VM of the current image", ok.image_version.as_deref().unwrap_or("unknown"))));
    }
    if ok.has_credentials && ok.credential.credential_name.as_deref() == Some(delivery.name()) && ok.credential.credential_tag.as_deref() == Some(delivery.tag()) {
        // Its row names it, even if the delivery that put it there was never recorded.
        record_holder(env.paths, vm, delivery.tag(), Held::Seen);
        conn.close(CLOSE_NORMAL).await;
        return Ok(Warmed::AlreadyHeld);
    }
    let Some(secret) = delivery.frame_secret() else {
        conn.close(CLOSE_NORMAL).await;
        return Err(delivery.missing(vm, "nothing was sent; run `ai-env vm warm` again"));
    };
    if let Err(e) = delivery.still_gated(unix_now(), false) {
        conn.close(CLOSE_NORMAL).await;
        return Err(e);
    }
    delivery.drop_value();
    // Recorded before it leaves: an answer lost with the socket must not leave the VM unlisted.
    record_holder(env.paths, vm, delivery.tag(), Held::Sent);
    conn.send(&Frame::Credential { name: delivery.name().to_string(), secret, tag: Some(delivery.tag().to_string()) }).await?;
    let answer = tokio::time::timeout(env.policy.dead_after, async {
        loop {
            match conn.recv().await? {
                Some(Frame::CredentialOk { cached: true, .. }) => return Ok(()),
                Some(Frame::CredentialErr { code: CredentialErrCode::Suspended, .. }) => return Err(BridgeError::Transport(format!("{vm} is suspending: run `ai-env vm warm` again once it runs"))),
                Some(Frame::CredentialErr { code: CredentialErrCode::Draining, .. }) => return Err(BridgeError::Terminated(format!("{vm} is stopping"))),
                Some(Frame::CredentialErr { name, message, .. }) => return Err(BridgeError::Protocol(format!("the shim refused credential {name}: {}", crate::wire::redact::scrub(&message)))),
                Some(Frame::Event { kind: EventKind::HookSuspend | EventKind::HookTerminate, .. }) => return Err(BridgeError::Transport(format!("{vm} was suspended or is terminating"))),
                Some(_) => {}
                None => return Err(BridgeError::Transport(format!("{vm}: the socket closed before credential_ok"))),
            }
        }
    })
    .await
    .map_err(|_| BridgeError::Transport(format!("{vm}: no answer to the credential")))?;
    answer?;
    record_delivery(env.paths, vm, None, delivery, "warm");
    conn.close(CLOSE_NORMAL).await;
    Ok(Warmed::Delivered)
}

/// `vm warm`'s socket and its `hello_ok`, under the session's rules for the
/// answers that pass: 503 `not_run` again every `backoff_min` within
/// `not_run_budget`; a 429 after max(Retry-After, the backoff), audited
/// `endpoint_429`; 503 `busy` and `hello_err busy` after the backoff
/// (doubling up to `backoff_max`); all within `reconnect_budget`. Any other
/// refusal ends it at once (exit 7), as before.
async fn warm_socket<A: MicrovmApi, E: EndpointClient>(env: &super::AgentEnv<'_, A, E>, token: &crate::bridge::api::AuthToken) -> std::result::Result<(super::conn::AgentConn, super::conn::HelloOk), BridgeError> {
    use crate::bridge::transport::DialError;
    let (p, vm) = (&env.policy, env.target.vm_id.as_str());
    let since = Instant::now();
    let (mut step, mut not_run_since) = (p.backoff_min, None::<Instant>);
    let mut backoff = || {
        let wait = step;
        step = step.saturating_mul(2).min(p.backoff_max);
        wait
    };
    loop {
        // How long to wait, why, and a 429's Retry-After (past the budget: `EndpointThrottled`).
        let (wait, why, throttled) = match super::conn::AgentConn::open(&env.dial, &env.target.endpoint, token.value()?).await {
            Ok(mut conn) => match tokio::time::timeout(p.dead_after, conn.hello(&env.target.session_token, vec![], p.idle_s)).await {
                Ok(Ok(ok)) => return Ok((conn, ok)),
                Ok(Err(BridgeError::HelloRefused { code, message })) if code == "busy" => (backoff(), format!("hello_err busy: {message}"), None),
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(BridgeError::Transport(format!("{vm}: no hello_ok"))),
            },
            Err(DialError::NotRun) => {
                if not_run_since.get_or_insert_with(Instant::now).elapsed() >= p.not_run_budget {
                    return Err(BridgeError::ShimUnavailable(format!("{vm}: its /run hook has not returned after {:.1} s (HTTP 503 not_run)", p.not_run_budget.as_secs_f64())));
                }
                (p.backoff_min, DialError::NotRun.to_string(), None)
            }
            Err(e @ DialError::Throttled { retry_after_s }) => {
                let b = backoff();
                let wait = retry_after_s.map_or(b, |s| p.backoff_min.saturating_mul(u32::try_from(s).unwrap_or(u32::MAX)).max(b));
                let retry_after = retry_after_s.map_or_else(|| "none".to_string(), |s| s.to_string());
                audit_event(env.paths, "endpoint_429", &[("id", vm.to_string()), ("retry_after", retry_after), ("waited_ms", wait.as_millis().to_string())]);
                eprintln!("ai-env: the endpoint throttled /agent (HTTP 429); retrying in {:.1} s", wait.as_secs_f64());
                (wait, e.to_string(), Some(retry_after_s))
            }
            Err(e @ DialError::Busy) => (backoff(), e.to_string(), None),
            Err(e) => return Err(BridgeError::Endpoint(format!("{vm}: /agent: {e}"))),
        };
        if since.elapsed() + wait > p.reconnect_budget {
            return Err(match throttled {
                Some(retry_after_s) => BridgeError::EndpointThrottled { retry_after_s },
                None => BridgeError::ShimUnavailable(format!("{vm}: no /agent connection for {:.1} s (last: {why})", since.elapsed().as_secs_f64())),
            });
        }
        tracing::info!("vm {vm}: /agent for vm warm: {why}; again in {wait:?}");
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seal_tag_names_the_file_not_the_token() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("setup-token.env");
        assert_eq!(seal_tag(&p), None);
        std::fs::write(&p, "sealed one").unwrap();
        let a = seal_tag(&p).unwrap();
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(seal_tag(&p), Some(a.clone()), "stable");
        std::fs::write(&p, "sealed two").unwrap();
        assert_ne!(seal_tag(&p).unwrap(), a, "a new seal is a new id");
    }

    /// A refusal is recorded once per seal and refuses only that seal: the
    /// sealed setup-token's with the advice to seal a fresh one; another
    /// seal's (a `--credential-file` container, M15) with its own words,
    /// since the sealed setup-token is not affected.
    #[test]
    fn a_rejection_is_recorded_once_and_refuses_only_its_seal() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        std::fs::create_dir_all(paths.setup_token_env().parent().unwrap()).unwrap();
        std::fs::write(paths.setup_token_env(), "sealed one").unwrap();
        let main = seal_tag(&paths.setup_token_env()).unwrap();
        assert!(refuse_rejected(&paths, &main).is_ok());
        record_rejection(&paths, "microvm-1", &main, "retries");
        record_rejection(&paths, "microvm-2", &main, "text");
        let r = read_rejection(&paths, &main).unwrap().unwrap();
        assert_eq!((r.vm.as_str(), r.tag.as_str()), ("microvm-1", main.as_str()), "the first refusal is kept");
        let e = refuse_rejected(&paths, &main).unwrap_err();
        assert_eq!(e.exit_code(), 5);
        assert!(e.to_string().contains("ai-env creds setup-token") && e.to_string().contains("nothing was unsealed"), "{e}");
        assert!(refuse_rejected(&paths, "seal-b").is_ok(), "a newly sealed token is another seal");
        record_rejection(&paths, "microvm-3", "seal-file", "retries");
        let e = refuse_rejected(&paths, "seal-file").unwrap_err();
        assert_eq!(e.exit_code(), 5);
        let said = e.to_string();
        assert!(said.contains("--credential-file (seal seal-file)") && said.contains("give another container; the sealed setup-token is not affected") && !said.contains("ai-env creds setup-token"), "{said}");
        let rows = crate::bridge::audit::read_rows(&paths.audit(), None).unwrap();
        assert_eq!(rows.iter().filter(|r| r["event"] == "credential_rejected").count(), 3, "each refusal is audited");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(paths.creds_state()).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// M53: a rejection store that cannot be read or parsed never reads as
    /// "nothing refused": every seal is refused (exit 5, naming the file,
    /// nothing unsealed), the reader that only shows it gets the error (on
    /// one line), and recording another refusal leaves the file's bytes as
    /// they were (it may hold refusals). A link in its place too.
    #[test]
    fn an_unreadable_rejection_store_refuses_and_is_never_overwritten() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        record_rejection(&paths, "microvm-1", "seal-a", "retries");
        let mut bytes = std::fs::read(paths.creds_state()).unwrap();
        bytes.extend_from_slice(b"\n[[rejected]\n");
        std::fs::write(paths.creds_state(), &bytes).unwrap();
        for tag in ["seal-a", "seal-b"] {
            let e = refuse_rejected(&paths, tag).unwrap_err();
            assert_eq!(e.exit_code(), 5, "{e}");
            assert!(e.to_string().contains(&format!("{} cannot be parsed", paths.creds_state().display())) && e.to_string().contains("nothing is unsealed"), "{e}");
        }
        assert!(read_rejection(&paths, "seal-a").is_err_and(|e| e.contains("cannot be parsed") && !e.contains('\n')), "never read as no refusal, and said on one line");
        record_rejection(&paths, "microvm-2", "seal-b", "text");
        assert_eq!(std::fs::read(paths.creds_state()).unwrap(), bytes, "left as it was");
        let rows = crate::bridge::audit::read_rows(&paths.audit(), None).unwrap();
        assert_eq!(rows.iter().filter(|r| r["event"] == "credential_rejected").count(), 2, "the refusal is still audited");
        std::fs::remove_file(paths.creds_state()).unwrap();
        std::os::unix::fs::symlink(d.path().join("elsewhere.toml"), paths.creds_state()).unwrap();
        let e = refuse_rejected(&paths, "seal-c").unwrap_err();
        assert!(e.exit_code() == 5 && e.to_string().contains("symlink"), "{e}");
        record_rejection(&paths, "microvm-3", "seal-c", "text");
        assert!(std::fs::symlink_metadata(paths.creds_state()).unwrap().file_type().is_symlink() && !d.path().join("elsewhere.toml").exists(), "nothing written through the link");
    }

    /// M53: refusals recorded at the same moment (several `vm exec`) never
    /// undo each other: the store's read, change and write hold its lock.
    #[test]
    fn refusals_recorded_at_once_are_all_kept() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let tags: Vec<String> = (0..16).map(|i| format!("seal-{i:02}")).collect();
        std::thread::scope(|s| {
            for tag in &tags {
                let paths = &paths;
                s.spawn(move || record_rejection(paths, "microvm-1", tag, "text"));
            }
        });
        let kept: Vec<&String> = tags.iter().filter(|t| matches!(read_rejection(&paths, t), Ok(Some(_)))).collect();
        assert_eq!(kept.len(), tags.len(), "every refusal is kept: {kept:?}");
    }

    /// `[creds] deliver = "env"` both allows env delivery and makes it the
    /// default: no `--deliver` gives env, `--deliver fd` still gives fd.
    /// Without it fd is the default, and `--deliver env` is refused (exit 9)
    /// naming the setting and that it would also make env the default.
    #[test]
    fn the_configured_delivery_is_the_default_and_env_needs_it() {
        assert_eq!(deliver_for(true, None).unwrap(), Deliver::Env);
        assert_eq!(deliver_for(true, Some(Deliver::Fd)).unwrap(), Deliver::Fd);
        assert_eq!(deliver_for(true, Some(Deliver::Env)).unwrap(), Deliver::Env);
        assert_eq!(deliver_for(false, None).unwrap(), Deliver::Fd);
        assert_eq!(deliver_for(false, Some(Deliver::Fd)).unwrap(), Deliver::Fd);
        let e = deliver_for(false, Some(Deliver::Env)).unwrap_err();
        assert_eq!(e.exit_code(), 9, "{e}");
        assert!(e.to_string().contains("allow that with [creds] deliver = \"env\", which also makes env the default"), "{e}");
    }

    /// M38: the seal id an unseal names is [`seal_tag`]'s rule over the very
    /// text it decrypted, and the one a `combined.env` text records for its
    /// token is the first 16 hex digits of its `token_file_sha256`: the
    /// setup-token.env it was built from, as `seal_tag` named that file then.
    /// A text that records none, or no sha256, names none.
    #[test]
    fn an_unseal_names_the_seal_of_the_bytes_it_read() {
        use sha2::Digest as _;
        let d = tempfile::tempdir().unwrap();
        let token_env = d.path().join("setup-token.env");
        std::fs::write(&token_env, "sealed token text").unwrap();
        assert_eq!(Some(tag_of("sealed token text")), seal_tag(&token_env));
        let sha = hex::encode(sha2::Sha256::digest(b"sealed token text"));
        let blob = b"age-encryption.org/v1\n-> x\n--- y\n";
        let combined = crate::container::write_annotated(blob, &[("kind", "combined"), ("token_file_sha256", &sha)]).unwrap();
        assert_eq!(combined_token_tag(&combined), seal_tag(&token_env));
        assert_eq!(combined_token_tag(&crate::container::write(blob)), None, "no record");
        let short = crate::container::write_annotated(blob, &[("token_file_sha256", &sha[..20])]).unwrap();
        assert_eq!(combined_token_tag(&short), None, "not a sha256");
    }

    /// M38 with a current `combined.env` (the default path): what its unseal
    /// hands a credentialed command is the runtime key, and the token with the
    /// seal id the unsealed text itself records, here setup-token.env's seal
    /// as it was when this combined.env was built from it, never the
    /// combined.env's own; `prepare` then sends it only if that is the seal
    /// `check` read. A text that records no seal hands over the runtime key
    /// alone.
    #[test]
    fn a_combined_token_carries_the_seal_its_own_text_records() {
        use sha2::Digest as _;
        let token = crate::bridge::setup_token::parse_token(&format!("sk-ant-oat01-{}Cb", "Kq4_".repeat(20))).unwrap_or_else(|f| panic!("{}", f.message));
        let (id, secret) = (format!("AKIA{}", "CMBT".repeat(4)), format!("{}{}", "Tq8+".repeat(9), "cmbt"));
        let plain = crate::bridge::setup_token::render_combined(&id, &secret, &token);
        let blob = b"age-encryption.org/v1\n-> x\n--- y\n";
        let source = "setup-token.env as it was sealed when combined.env was built";
        let built = crate::container::write_annotated(blob, &[("kind", "combined"), ("token_file_sha256", &hex::encode(sha2::Sha256::digest(source.as_bytes())))]).unwrap();
        let ((kid, ksecret), handed) = from_combined(plain.as_bytes(), &built).unwrap();
        assert!(kid == id && ksecret.as_str() == secret, "the runtime key ({} and {} chars)", kid.len(), ksecret.len());
        let (t, tag) = handed.expect("the token, with a seal id");
        assert!(t.expose() == token.expose(), "the token ({} chars)", t.len());
        assert_eq!(tag, tag_of(source), "the seal the text records");
        assert_ne!(tag, tag_of(&built), "never combined.env's own seal");
        let ((kid, _), handed) = from_combined(plain.as_bytes(), &crate::container::write(blob)).unwrap();
        assert!(kid == id && handed.is_none(), "no seal recorded: the runtime key alone");
    }

    #[test]
    fn claude_is_told_by_its_basename() {
        let v = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert!(is_claude(&v(&["claude", "-p", "x"])) && is_claude(&v(&["/usr/local/bin/claude"])));
        assert!(!is_claude(&v(&["claude-code"])) && !is_claude(&v(&["/bin/sh", "claude"])) && !is_claude(&[]));
    }
}


/// The whole chain in one process (S7, the lead's check after wave 1): the
/// real shim (its routers on loopback, its credential cache) and the real
/// session with a delivery. A miss delivers and the spawn reads the value on
/// fd 3, and the VM's row names it as a holder; a hit sends nothing and the
/// spawn still reads it, from the cache; `/suspend` empties the cache, so a
/// predicted hit then ends `CredentialMissing` before any spawn; after
/// `/resume` a delivery works again. `vm warm` fills the cache with no spawn
/// and keeps no copy once it did; a second finds it held.
#[cfg(all(test, feature = "shim"))]
mod e2e {
    use super::super::{run_spawn_with, spawn_channels, AgentEnv, AgentTarget, RunPolicy, SpawnEvent, SpawnSpec, Start};
    use super::*;
    use crate::bridge::api::{FakeMicrovmApi, IdleSpec, RunSpec, FAKE_IMAGE_ARN};
    use crate::bridge::config::TransportCfg;
    use crate::bridge::transport::AgentDial;
    use crate::shim::health::{ProbeSpec, ShimOpts, ShimState};
    use crate::shim::peer::Peer;
    use crate::wire::frame::RunHookPayload;
    use std::collections::BTreeMap;
    use std::io::{Read as _, Write as _};
    use std::net::SocketAddr;

    const LIMIT: Duration = Duration::from_secs(60);

    async fn serve(router: axum::Router) -> SocketAddr {
        let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, router.into_make_service_with_connect_info::<Peer>()).await.unwrap() });
        addr
    }

    fn post(addr: SocketAddr, path: &str, body: &str) -> u16 {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(LIMIT)).unwrap();
        s.write_all(format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
    }

    async fn hook(addr: SocketAddr, name: &str, body: String) -> u16 {
        let path = format!("/aws/lambda-microvms/runtime/v1/{name}");
        tokio::task::spawn_blocking(move || post(addr, &path, &body)).await.unwrap()
    }

    /// Run `argv` with `delivery`: stdout, or the session's error.
    async fn run(env: &AgentEnv<'_, FakeMicrovmApi, FakeMicrovmApi>, argv: &[&str], delivery: Delivery) -> std::result::Result<Vec<u8>, BridgeError> {
        let (io, c) = spawn_channels(8);
        drop(c.input);
        let consumed = c.consumed.clone();
        let mut events = c.events;
        let consumer = tokio::spawn(async move {
            let mut out = Vec::new();
            while let Some(ev) = events.recv().await {
                match ev {
                    SpawnEvent::Stdout { seq, bytes } => {
                        out.extend_from_slice(&bytes);
                        consumed.stdout_done(seq);
                    }
                    SpawnEvent::Stderr { seq, .. } => consumed.stderr_done(seq),
                    _ => {}
                }
            }
            out
        });
        let spec = SpawnSpec { argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: BTreeMap::new(), detach_grace_s: None };
        let outcome = tokio::time::timeout(LIMIT, run_spawn_with(env, Start::New(spec), io, Some(delivery))).await.expect("the spawn ends in time");
        drop(c.control);
        let out = tokio::time::timeout(LIMIT, consumer).await.expect("the events end").unwrap();
        outcome.map(|o| {
            assert_eq!(o.exit.code, Some(0));
            out
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_credential_reaches_the_spawn_through_the_real_shim_and_its_cache() {
        let home = tempfile::tempdir().unwrap();
        // SAFETY: getuid/getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let opts = ShimOpts { home: std::fs::canonicalize(home.path()).unwrap(), uid, gid, ..ShimOpts::default() };
        let shim = Arc::new(ShimState::with(PathBuf::from("/nonexistent/claude"), opts, ProbeSpec::default(), Arc::new(crate::shim::sys::RealSys)));
        shim.set_bound();
        let hooks = serve(crate::shim::hooks::router(shim.clone())).await;
        let app = serve(crate::shim::health::router(shim.clone())).await;
        let api = FakeMicrovmApi::new();
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: uuid::Uuid::now_v7().to_string(),
        };
        let vm = api.run(&spec).await.unwrap();
        api.advance_all();
        let session = format!("e2e-session-{}", "s".repeat(24));
        let payload = RunHookPayload::new(&Secret::new(session.clone()), "mike@mbp", "2026-10-07T08:00:00Z").to_json().unwrap();
        assert_eq!(hook(hooks, "run", serde_json::json!({ "microvmId": vm.id, "runHookPayload": payload }).to_string()).await, 200);
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(root.path().join("bridge"), None);
        let row = VmRow { id: vm.id.clone(), status: crate::bridge::vm::registry::RowStatus::Running, client_token: spec.client_token.clone(), ..VmRow::default() };
        crate::bridge::vm::registry::write_row(&paths, &row).unwrap();
        let env = AgentEnv {
            api: &api,
            ep: &api,
            paths: &paths,
            target: AgentTarget { vm_id: vm.id.clone(), endpoint: vm.endpoint.clone(), session_token: Secret::new(session), vpc: false, shell: false },
            policy: RunPolicy::from_cfg(&TransportCfg::default(), &VmRow::default(), None),
            dial: AgentDial { local: Some(app) },
        };
        let value = format!("dummy-credential-e2e-{}", "w".repeat(20));
        let delivery = |secret: Option<&str>| {
            let now = unix_now();
            let parts = DeliveryParts { name: TOKEN_VAR.into(), tag: "seal00000000e2e0".into(), deliver: Deliver::Fd, secret: secret.map(|s| Secret::new(s.to_string())), one_shot: false };
            Delivery::new(&GatePass::for_tests(&vm.id, now), &vm.id, now, parts).unwrap()
        };
        let read_fd3 = ["/bin/sh", "-c", "cat <&3"];
        // A miss: delivered, cached, read on fd 3; the row names the VM.
        assert_eq!(run(&env, &read_fd3, delivery(Some(&value))).await.unwrap(), value.as_bytes());
        assert!(shim.spawns.credential().has(), "the shim keeps it");
        let held = crate::bridge::vm::registry::read_row(&paths, &vm.id).unwrap().unwrap();
        assert_eq!((held.credential_at.is_some(), held.credential_tag.as_deref()), (true, Some("seal00000000e2e0")));
        // A hit: nothing sent, the cache serves the spawn.
        assert_eq!(run(&env, &read_fd3, delivery(None)).await.unwrap(), value.as_bytes());
        let rows = crate::bridge::audit::read_rows(&paths.audit(), None).unwrap();
        let delivered: Vec<_> = rows.iter().filter(|r| r["event"] == "credential_deliver").collect();
        assert_eq!(delivered.len(), 1, "one delivery for two spawns: {delivered:?}");
        // Suspended: the cache is empty, a predicted hit ends before any spawn.
        assert_eq!(hook(hooks, "suspend", "{}".into()).await, 200);
        assert!(!shim.spawns.credential().has());
        let e = run(&env, &read_fd3, delivery(None)).await.unwrap_err();
        assert!(matches!(e, BridgeError::CredentialMissing(_)), "{e}");
        assert_eq!(hook(hooks, "resume", "{}".into()).await, 200);
        assert_eq!(run(&env, &read_fd3, delivery(Some(&value))).await.unwrap(), value.as_bytes());
        // `vm warm`'s delivery: emptied by a suspend, filled again with no spawn; a second finds it held.
        assert_eq!(hook(hooks, "suspend", "{}".into()).await, 200);
        assert_eq!(hook(hooks, "resume", "{}".into()).await, 200);
        assert!(!shim.spawns.credential().has());
        let spawns = shim.spawns.status(None).len();
        let mut warmed = delivery(Some(&value));
        assert_eq!(warm(&env, &mut warmed).await.unwrap(), Warmed::Delivered);
        assert!(!warmed.holds_value(), "the Mac keeps no copy once vm warm delivered it");
        assert!(shim.spawns.credential().has());
        assert_eq!(deliver_only(&env, delivery(None)).await.unwrap(), Warmed::AlreadyHeld);
        assert_eq!(shim.spawns.status(None).len(), spawns, "warming starts nothing");
        // No file under the Mac's root (the audit, the row) or the agent's home holds the value.
        let mut todo = vec![root.path().to_path_buf(), home.path().to_path_buf()];
        while let Some(dir) = todo.pop() {
            for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                match e.file_type() {
                    Ok(t) if t.is_dir() => todo.push(e.path()),
                    Ok(t) if t.is_file() => assert!(!std::fs::read(e.path()).is_ok_and(|b| b.windows(value.len()).any(|w| w == value.as_bytes())), "{} holds the value", e.path().display()),
                    _ => {}
                }
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(6), shim.spawns.shutdown("test")).await;
    }
}
