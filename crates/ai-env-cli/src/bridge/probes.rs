//! `lab/probes.jsonl`: one version-stamped verdict per line (plan §7). S1
//! records the extension probes (`ai-env wrapper census --record-probes`), S3
//! the image-version probe (`ai-env infra versions-diff --record-probe`), S4
//! the platform probes (`ai-env lab run …`). Every writer appends through
//! [`append_row`] (one `write` per row on the 0600 `O_APPEND` file), so rows
//! from different commands never interleave.
use crate::bridge::census::read_rows;
use crate::bridge::logging::open_log_file;
use crate::errors::{CliError, Result};
use crate::outln;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

/// One line of `lab/probes.jsonl`. The four trailing fields arrived with S4;
/// they are omitted when unset, so S1/S3 rows keep their exact shape and old
/// rows still parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRow {
    /// The probe name (`entrypoint`, `image-version-delete`, `hooks-port`, …).
    pub probe: String,
    /// The stage that recorded the row (`S1`, `S3`, `S4`).
    pub stage: String,
    /// The extension bundle version (S1), or the image's claude version (S3/S4) when known.
    pub ext: Option<String>,
    /// `CLAUDE_AGENT_SDK_VERSION` of the session, when recorded (S1).
    pub sdk: Option<String>,
    /// What was observed.
    pub verdict: String,
    /// The rendered expectation: a literal verdict, `any-of:a|b|c`, or
    /// `recorded` (see [`expectation_holds`]).
    pub expected: String,
    /// RFC 3339 seconds, when the verdict was derived.
    pub ts: String,
    /// The image version the probe ran against (S4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_version: Option<String>,
    /// The shim version `/health` reported (S4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<String>,
    /// The claude version `/health` reported (S4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude: Option<String>,
    /// Free text: what the verdict was derived from, VM ids, a manual note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl ProbeRow {
    /// A row stamped now, without the S4 fields.
    #[must_use]
    pub fn new(probe: &str, stage: &str, verdict: &str, expected: &Expectation) -> ProbeRow {
        ProbeRow {
            probe: probe.to_string(),
            stage: stage.to_string(),
            ext: None,
            sdk: None,
            verdict: verdict.to_string(),
            expected: expected.render(),
            ts: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()),
            image_version: None,
            shim: None,
            claude: None,
            note: None,
        }
    }
}

/// What a probe expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expectation {
    /// Exactly this verdict.
    Exact(String),
    /// One of these verdicts.
    AnyOf(Vec<String>),
    /// Anything: the row records a measurement.
    Recorded,
}

impl Expectation {
    /// The `expected` field: the literal, `any-of:a|b`, or `recorded`.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Expectation::Exact(v) => v.clone(),
            Expectation::AnyOf(vs) => format!("any-of:{}", vs.join("|")),
            Expectation::Recorded => "recorded".to_string(),
        }
    }
}

/// Does `verdict` satisfy the rendered expectation `expected`?
#[must_use]
pub fn expectation_holds(expected: &str, verdict: &str) -> bool {
    if expected == "recorded" {
        return true;
    }
    match expected.strip_prefix("any-of:") {
        Some(list) => list.split('|').any(|v| v == verdict),
        None => expected == verdict,
    }
}

/// The last recorded row of `probe` in `path` (as JSON), if any.
pub fn last_row(path: &Path, probe: &str) -> Result<Option<serde_json::Value>> {
    Ok(read_rows(path, None)?.into_iter().rev().find(|r| r.get("probe").and_then(|p| p.as_str()) == Some(probe)))
}

/// Append `row` to `path` with one `write` (0700 dir, 0600 file, `O_APPEND`,
/// `O_NOFOLLOW`), printing `probe X: old -> new` first when the last recorded
/// verdict of that probe differs. A short write is an error, never completed
/// by a second write. Returns whether the verdict satisfies the row's
/// expectation; callers decide whether that fails the command (after writing).
pub fn append_row(path: &Path, row: &ProbeRow) -> Result<bool> {
    if let Some(old) = last_row(path, &row.probe)?.as_ref().and_then(|r| r.get("verdict")).and_then(|v| v.as_str()) {
        if old != row.verdict {
            outln!("probe {}: {old} -> {}", row.probe, row.verdict);
        }
    }
    let mut line = serde_json::to_vec(row).map_err(|e| CliError::Msg(format!("probe row: {e}")))?;
    line.push(b'\n');
    let mut file = open_log_file(path)?;
    let written = file.write(&line)?;
    if written != line.len() {
        return Err(CliError::Msg(format!("short probe write: {written} of {} bytes to {}", line.len(), path.display())));
    }
    Ok(expectation_holds(&row.expected, &row.verdict))
}

// ---- the catalog (`ai-env lab list`) ---------------------------------------------------

/// Where a probe's verdict comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The wrapper's invocation census (S1).
    Census,
    /// Snapshots around `make deploy` (S3).
    Deploy,
    /// The image's runtime log (`make logs`), passed with `--log FILE`.
    Log,
    /// VMs started by the probe itself (runtime key, one Touch ID).
    Live,
    /// The operator's own `aws` CLI identity (CloudTrail).
    AwsCli,
    /// A live pass, then a `--log FILE` pass that pairs the run reports.
    LiveThenLog,
    /// This Mac only (S7): no VM, no AWS call, no runtime key.
    Mac,
    /// What the operator saw in Cursor (S8): recorded by hand only
    /// (`lab run PROBE --manual VERDICT`).
    Cursor,
}

impl Source {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Source::Census => "census",
            Source::Deploy => "deploy",
            Source::Log => "log",
            Source::Live => "live",
            Source::AwsCli => "aws-cli",
            Source::LiveThenLog => "live+log",
            Source::Mac => "mac",
            Source::Cursor => "cursor",
        }
    }
}

/// A static expectation (the catalog's form of [`Expectation`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Exact(&'static str),
    AnyOf(&'static [&'static str]),
    Recorded,
}

impl Expect {
    #[must_use]
    pub fn expectation(self) -> Expectation {
        match self {
            Expect::Exact(v) => Expectation::Exact(v.to_string()),
            Expect::AnyOf(vs) => Expectation::AnyOf(vs.iter().map(|v| (*v).to_string()).collect()),
            Expect::Recorded => Expectation::Recorded,
        }
    }
}

/// One known probe.
#[derive(Debug, Clone, Copy)]
pub struct ProbeSpec {
    pub name: &'static str,
    pub stage: &'static str,
    pub source: Source,
    pub expect: Expect,
    /// The command that records it.
    pub recorded_by: &'static str,
    /// What it answers.
    pub what: &'static str,
}

/// Every probe the stages record (plan §7), S1 and S3 included so `lab list`
/// shows the whole picture.
pub const CATALOG: [ProbeSpec; 33] = [
    ProbeSpec { name: "entrypoint", stage: "S1", source: Source::Census, expect: Expect::Exact("claude-vscode"), recorded_by: "ai-env wrapper census --record-probes", what: "CLAUDE_CODE_ENTRYPOINT the extension sets for the wrapper" },
    ProbeSpec { name: "stock-ext-oauth", stage: "S1", source: Source::Census, expect: Expect::Exact("absent"), recorded_by: "ai-env wrapper census --record-probes", what: "whether the stock extension advertises OAuth refresh (CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH among a session's environment names: its Agent SDK sets it only for a host that passes a getOAuthToken callback, which the extension's own chats do not); S7's second half in the note: with the debug-build knob AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS the wrapper's pump sends the extension one oauth_token_refresh of its own once the session is initialized, the census end row records the class of the answer (synthetic_oauth:<class>; the stock extension answers error(getOAuthToken callback is not provided.)), and --record-probes puts it in this row's note" },
    ProbeSpec { name: "image-version-delete", stage: "S3", source: Source::Deploy, expect: Expect::Exact("kept"), recorded_by: "make deploy RECORD_PROBE=1", what: "whether an image update deletes earlier versions" },
    ProbeSpec { name: "hooks-port", stage: "S4", source: Source::Log, expect: Expect::Exact("9000"), recorded_by: "ai-env lab run hooks-port --log FILE", what: "the local port runtime hooks arrive on (= the configured hooks.port)" },
    ProbeSpec { name: "hooks-source-ip", stage: "S4", source: Source::Log, expect: Expect::Exact("loopback"), recorded_by: "ai-env lab run hooks-source-ip --log FILE", what: "where runtime hooks come from" },
    ProbeSpec { name: "payload-size", stage: "S4", source: Source::Live, expect: Expect::Exact("4096=accepted 4097=rejected"), recorded_by: "ai-env lab run payload-size", what: "the service's run-hook payload limit" },
    // Recorded, not expected: the AWS docs promise no traffic before /run, but the live endpoint forwarded a /health
    // while the control plane still said PENDING (30 Sep 2026); it is a race, so the shim must refuse everything but
    // /health until /run (a hello without the run's commitment already fails).
    ProbeSpec { name: "no-traffic-before-run", stage: "S4", source: Source::Live, expect: Expect::Recorded, recorded_by: "ai-env lab run no-traffic-before-run", what: "whether the endpoint forwards anything before /run returned, and for how long" },
    ProbeSpec { name: "runtime-env", stage: "S4", source: Source::Log, expect: Expect::Recorded, recorded_by: "ai-env lab run runtime-env --log FILE", what: "PID 1's environment in a MicroVM (names; credential variables)" },
    ProbeSpec { name: "cloudtrail-payload", stage: "S4", source: Source::AwsCli, expect: Expect::AnyOf(&["not-logged", "hidden", "absent", "commitment-only"]), recorded_by: "ai-env lab run cloudtrail-payload ID [--log FILE]", what: "what CloudTrail keeps of a run-hook payload (RunMicrovm is a data event, off by default)" },
    ProbeSpec { name: "disk-budget", stage: "S4", source: Source::Log, expect: Expect::Recorded, recorded_by: "ai-env lab run disk-budget --log FILE", what: "disk used by the image in a fresh VM" },
    ProbeSpec { name: "snapshot-uniqueness", stage: "S4", source: Source::LiveThenLog, expect: Expect::Exact("nonce-differs"), recorded_by: "ai-env lab run snapshot-uniqueness [--log FILE]", what: "per-VM boot nonces (boot_id is shared by snapshot clones)" },
    ProbeSpec { name: "idle-policy-limits", stage: "S4", source: Source::Live, expect: Expect::Recorded, recorded_by: "ai-env lab run idle-policy-limits", what: "which suspended durations the service accepts" },
    ProbeSpec { name: "connector-pending", stage: "S5", source: Source::Live, expect: Expect::Recorded, recorded_by: "ai-env lab run connector-pending ARN (make connector-probe CONFIRM=create-probe-connector)", what: "what RunMicrovm does with an egress connector that is still PENDING (rejected:<code>, or accepted[:echo-mismatch|:internet|:terminated])" },
    ProbeSpec { name: "dns-path", stage: "S5", source: Source::Live, expect: Expect::Exact("no-dns"), recorded_by: "ai-env lab run dns-path", what: "whether a vpc VM reaches any DNS server, asked a fresh name d<nonce>.example.com A (and example.com A of each server that replied): no-dns; platform-dns:<ip>[,<ip>…] when platform resolvers replied only with an empty NOERROR (no answer, no authority); platform-dns-answered:<ip>[,…] for any other platform reply; platform-dns-resolves:<ip>[,…] when one returned an address; open-dns:<ip>[,…] for any other server; resolves=yes|no in the note" },
    // S6 (plan S6 "Probes"): the agent transport through the live endpoint. Each owns its VMs on the lab path with its
    // own budget and terminate guard; in-vm-firewall runs a default VM and a `--shell` VM.
    ProbeSpec { name: "e0", stage: "S6", source: Source::Live, expect: Expect::Exact("101 HTTP/1.1 403 403 403"), recorded_by: "ai-env lab run e0", what: "the /agent upgrade through the endpoint: headers-only token (a 101 the client accepted, 101-refused when it refused one; the HTTP version as the client parsed the answer, always HTTP/1.1: the shim's own view is the http= field of its agent upgrade log line), no token, a Port(8081) token, a Port(9418) token with port header 8080; in the note the subprotocol form, the bearer through the endpoint, and eight sockets held open after hello, then a 9th (its answer) and the shim's socket count, read once one held socket closed (with all eight open the endpoint's cap would likely refuse the read)" },
    ProbeSpec { name: "e1", stage: "S6", source: Source::Live, expect: Expect::Recorded, recorded_by: "ai-env lab run e1", what: "whether an open /agent socket survives its endpoint token's expiry (a 2-min token held 4 min with pings): survives (pongs kept arriving past the expiry), cut-at-expiry:<s> or silent-at-expiry:<s> (open, but nothing came back); WS#2 hello-resume keeps the pid" },
    ProbeSpec { name: "e5", stage: "S6", source: Source::Live, expect: Expect::Recorded, recorded_by: "ai-env lab run e5", what: "which traffic keeps a VM with max idle 60 s from suspending: a silent socket, pings only, VM-to-Mac output only, a GET /health every 30 s (silent:<kept|suspended> pings:<…> outbound:<…> http:<…>; http is suspended when GetMicrovm saw it at any point of the phase); a reconnect to the suspended VM, timed, with the state after, in the note (whether 8080 traffic reaches the shim before /resume returns cannot be measured from the Mac: the endpoint holds the request through /resume, and the note says so)" },
    ProbeSpec { name: "frames", stage: "S6", source: Source::Live, expect: Expect::Exact("byte-identical"), recorded_by: "ai-env lab run frames", what: "vm exec through the endpoint: 1 000 lines incl. 1 MiB, a 20 MiB line both ways, non-UTF-8 bytes and an unterminated last line arrive byte-identical (MB/s in the note)" },
    ProbeSpec { name: "reattach", stage: "S6", source: Source::Live, expect: Expect::Exact("no-loss-same-pid"), recorded_by: "ai-env lab run reattach", what: "a client-side cut mid-stream (stdin closed; the producer outlives the cut and the D22 ladder), then a reattach: no line lost or doubled, the same pid, the producer ran to its end (exit 0); a stale from_seq; a full window, a kill, then an attach (reattach ms in the note)" },
    ProbeSpec { name: "clock-after-resume", stage: "S6", source: Source::Live, expect: Expect::AnyOf(&["within-2s"]), recorded_by: "ai-env lab run clock-after-resume", what: "the guest clock against the Mac after at least 15 min suspended (vpc egress): within-2s, else the offset; the monotonic jump and the time to the first proxied success in the note" },
    ProbeSpec { name: "in-vm-firewall", stage: "S6", source: Source::Live, expect: Expect::Exact("guarded"), recorded_by: "ai-env lab run in-vm-firewall", what: "whether the agent uid can reach the VM's privileged listeners: forged hooks via 127.0.0.1 and the VM's own address (resume first, terminate last), the close-before-lookup trick, an RST-aborted GET /health via the VM's own address on 8080 (under agent_guard on the guard's refusal count must rise by two per connection; under log or off it is not judged), 8080/9418 judged by the guard mode in the note (agent_guard on: 403; tree B's log or off: GET /health may answer the public summary, a bearer path must answer 401 or 403), every listener the shim does not own dialed where it listens (8022 on a --shell VM), NoNewPrivs, setuid inventory, IMDS, nf_tables; the endpoint's bearer-less PUT /seed and /health/detail; guarded, exposed:<port>, or gap:<checks> when a check could not run (vm-address, listeners, rst-abort)" },
    ProbeSpec { name: "fd-delivery", stage: "S7", source: Source::Live, expect: Expect::Exact("fd-honoured"), recorded_by: "ai-env lab run fd-delivery", what: "whether claude on the VM takes the setup-token from CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR, custody included: a spawn given the token on fd 3 (always fd, whatever [creds] deliver says) has none in its environ and reads it whole on fd 3 (byte count in the note); claude -p in stream-json host mode answers with the fd alone, and while it still runs a second spawn reads every environment the agent's uid can (claude's own and its children's) for the token's name or a value of its kind; then a suspend and a resume, after which /health/detail's has_credentials must read false. Only when claude did not answer with the fd alone does the probe ask once more, the same way (so the two differ in the delivery alone), with the token in that one claude's environment (whatever [creds] deliver says), to tell env-only apart, on the probe's own VM, which it terminates. fd-honoured, env-only (claude answered only with the token in its environment), fd-unread:<why>, kept-after-resume (the VM still held the token after the resume), claude-environ:<n> (n environment entries held it while claude ran with the fd), or gap:<checks> (fd-scan, claude-environ, has-credentials: a custody check that could not be read is no pass; an unread fd-scan, the first spawn's environ count, also leaves claude's answers unjudged)" },
    ProbeSpec { name: "oauth-t1", stage: "S7", source: Source::Mac, expect: Expect::Recorded, recorded_by: "ai-env lab run oauth-t1", what: "the real CLI's OAuth refresh on this Mac (stream-json host mode with the extension's entrypoint, CLAUDE_CODE_ENTRYPOINT=claude-vscode, and CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH=1: the CLI asks its host for a refresh only with both; the stock extension's Agent SDK sets the variable only for a host that passes a getOAuthToken callback, which 2.1.310's own chats never do, and Tier B would; a refused token): when it asks for a refresh, what a valid, a null and no reply do and how long each takes, and whether CLAUDE_CODE_OAUTH_401_WAIT_MS is honoured (a null reply with it at 5000: the result at least that much later); with no reply its stdin stays open, so an exit would be its own: none is expected, and that run ends at its 150 s bound, since CLAUDE_CODE_AUTH_FAIL_EXIT_MS acts only for a remote child (CLAUDE_CODE_REMOTE_SESSION_ID), which ai-env's CLI never is (it is not set); the valid reply is the sealed setup-token (one Touch ID), skipped when none is sealed, vm exec would refuse to unseal it (Anthropic refused that seal) or no run asked for a refresh: then it is never unsealed or sent; the CLI's path and version in the note, nothing of the image in the row; AUTH_TIMERS holds what it measured on claude 2.1.305 (S10 part B; 2.1.302 in S8 part B, 2.1.296 in S7 B11) and AUTH_TIMERS_REVIEWED 2.1.310's too (S11 part B), measured again for a new version" },
    ProbeSpec { name: "setup-token-prefix", stage: "S7", source: Source::Mac, expect: Expect::Recorded, recorded_by: "ai-env creds setup-token", what: "the kind prefix of the sealed setup-token (sk-ant-oat01-), observed at sealing, never validated" },
    ProbeSpec { name: "touchid-gui", stage: "S7", source: Source::Mac, expect: Expect::Exact("prompted"), recorded_by: "ai-env lab run touchid-gui (from Cursor's integrated terminal)", what: "whether age-plugin-se shows its Touch ID dialog to processes Cursor started: an unseal in the terminal, then one from a detached setsid child without a terminal (S8's prewarm): prompted, terminal-only, or failed:<why>" },
    ProbeSpec { name: "init-budget", stage: "S7", source: Source::Live, expect: Expect::Exact("within-budget"), recorded_by: "ai-env lab run init-budget", what: "how long a credentialed claude takes to answer initialize (stream-json host mode), judged on the answer (each session's close after it is noted, not counted): cold, the sum of the token's unseal (its Touch ID wait: with a current combined.env the one Touch ID lab run takes for the runtime key and the token, before the VM is started; without one the token's own, after the gate, while the runtime key's own Touch ID before the VM is not counted), RunMicrovm to RUNNING and /health, the gate, and the delivery and spawn to the answer; warm (the VM holds the token), the gate and the spawn to the answer. Against 30 s and 5 s: within-budget, over:<cold|warm>, or gap:unseal (the combined unseal's time could not be read); each leg in the note" },
    // S8 (plan L8): what Cursor shows after a resume the VM's transcript missed (the miss, the seed retry and the
    // replay), or (S10) after a move of the chat to a new VM, recorded by hand from Cursor with the newest remote
    // session's census evidence; the trust prompt of a fresh VM; the wrapper's own initialize budget, from the census.
    ProbeSpec { name: "dup-init", stage: "S8", source: Source::Cursor, expect: Expect::Exact("no-duplicate"), recorded_by: "ai-env lab run dup-init --manual VERDICT (after a resume in Cursor)", what: "after a resume whose transcript the VM lacked (T8.5: the transcript put there before the spawn, S8's upload or S9's restore from S3, or the resume miss, the seed retry and the replay) or a move of the chat to a new VM (S10 T10.3: the moved claude's init and the resent message, which the swallow rules hide), whether Cursor shows the session's start twice: no-duplicate, or duplicate:<what>; observed in Cursor, and recorded only with that resume's or move's census evidence, which the note carries: the newest census end row of a remote session that answered initialize and either resumed a conversation (--resume) into a VM without the transcript (transcript:uploaded, restored or staged, or respawns:1 or more) or moved (its moves adding up to 1 or more, not counting the failed last move of an end:move_failed row), with its session (a new chat's row names none), VM, transcript word, respawns, moves, inits and echoes (forwarded/swallowed), init_ms, end and exit" },
    ProbeSpec { name: "dup-user-replay", stage: "S8", source: Source::Cursor, expect: Expect::Exact("no-duplicate"), recorded_by: "ai-env lab run dup-user-replay --manual VERDICT (after a resume in Cursor)", what: "after the same resume or move (a move sends the interrupted message again), whether Cursor shows the replayed user message twice (a doubled bubble): no-duplicate, or duplicate:<what>; observed in Cursor, with the census evidence as dup-init's" },
    ProbeSpec { name: "fresh-claude-json", stage: "S8", source: Source::Live, expect: Expect::Exact("no-stall"), recorded_by: "ai-env lab run fresh-claude-json", what: "whether the image's claude, started as Cursor starts a session (the extension's stream-json argv as the wrapper sends it, its entrypoint, the setup-token on fd 3) in the current directory's workspace seeded into a fresh VM whose .claude.json has no entry for it, answers without a trust dialog or onboarding: no-stall (initialize answered within Cursor's 60 s window, then one turn's result, no error), or stall:initialize (no answer to initialize, or claude exited first), stall:turn (no result for the turn within 120 s, or claude exited first) or stall:turn-error (an error result); the project's .claude.json keys before and after, claude's requests to its host and its first stderr line in the note (on a stall the seed then writes the project's hasTrustDialogAccepted, L7)" },
    ProbeSpec { name: "init-wrapper", stage: "S8", source: Source::Census, expect: Expect::Exact("within-budget"), recorded_by: "ai-env wrapper census --record-probes", what: "how long the wrapper's remote sessions take to answer initialize, from the census end rows (T0 to the forwarded answer, with the legs touchid, select, workspace, gate and spawn): the newest cold row (vm_how:started) against 30 s and the newest warm one against its own VM's budget (vm_how:reused 5 s; resumed 8 s, S10 F9: the VM's resume on top), each with its Touch ID leg in the note: within-budget, over:<cold|warm>, or gap:<cold|warm> while the census holds no such row; a pinned VM's rows and starts that never answered are not judged, nor (S10) sessions that moved the chat, a reopen's carry included (a move rewrites the row's vm_how while its init_ms stays the first answer's), but one past 30 s stands as the cold row, over whatever its first VM was (a pinned chat's never); not recorded until remote end rows exist" },
    // S9 (plan L6): what the endpoint does with git smart-HTTP v2 and with a chunked request body, each measured
    // with ai-env's own clients, never a git child holding a token (design D12).
    ProbeSpec { name: "protocol-v2", stage: "S9", source: Source::Live, expect: Expect::Exact("v2"), recorded_by: "ai-env lab run protocol-v2", what: "whether git smart-HTTP v2 reaches the VM's http-backend through the endpoint: ai-env's own client asks a seeded VM's GET /workspace.git/info/refs?service=git-upload-pack with Git-Protocol: version=2: v2 (the header passed and http-backend answered version 2), v0 (it answered the v0 # service= advertisement: the header was dropped), or failed:<status>; the response's framing (chunked or a length) and the time to the advertisement in the note" },
    ProbeSpec { name: "chunked-put", stage: "S9", source: Source::Live, expect: Expect::Recorded, recorded_by: "ai-env lab run chunked-put", what: "what the endpoint does with a chunked request body: a PUT /seed with Transfer-Encoding: chunked to an unseeded VM: forwarded (the shim saw it chunked and answered 411), dechunked (it arrived with a Content-Length), or refused:<status> (the endpoint answered itself); 1 MB and 20 MB PUT /seed timings with a Content-Length in the note" },
    // S10 (L3): what Cursor shows of the note the wrapper writes the chat when it moves it to a new VM.
    ProbeSpec { name: "move-note", stage: "S10", source: Source::Cursor, expect: Expect::Exact("shown"), recorded_by: "ai-env lab run move-note --manual VERDICT (after a move in Cursor)", what: "after a chat moved to a new VM (T10.3), whether Cursor showed ai-env's informational line in the chat: shown, or not-shown:<what>; observed in Cursor, and recorded with the move's census evidence (the newest remote end row whose moves is above 0)" },
];

/// The catalog entry of `name`.
#[must_use]
pub fn spec(name: &str) -> Option<&'static ProbeSpec> {
    CATALOG.iter().find(|p| p.name == name)
}

// ---- S8: the census's remote sessions ----------------------------------------------------

/// A census note's parts, `(name, value)` in order.
type Parts<'a> = Vec<(&'a str, &'a str)>;

/// The parts of a census row's note (`name:value`, split at the first colon;
/// a part without one has an empty value), in order.
fn note_parts(row: &serde_json::Value) -> Parts<'_> {
    row.get("note").and_then(|n| n.as_str()).unwrap_or_default().split("; ").filter(|p| !p.is_empty()).map(|p| p.split_once(':').unwrap_or((p, ""))).collect()
}

/// The value of the note part `name` (the last, should one repeat).
fn part<'a>(parts: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    parts.iter().rev().find(|(k, _)| *k == name).map(|(_, v)| *v)
}

/// A remote session's census row: its mode note is one of
/// `remote::MODE_NOTES` (the start row's, which its end row keeps).
fn is_remote(parts: &[(&str, &str)]) -> bool {
    parts.iter().any(|(k, v)| crate::bridge::remote::MODE_NOTES.iter().any(|m| m.split_once(':') == Some((k, v))))
}

/// A census end row (the pump's second row of a piped session: `end` set).
fn is_end_row(row: &serde_json::Value) -> bool {
    row.get("end").and_then(serde_json::Value::as_u64).is_some()
}

fn field<'a>(row: &'a serde_json::Value, name: &str) -> &'a str {
    row.get(name).and_then(|v| v.as_str()).unwrap_or("-")
}

/// One remote end row `init-wrapper` judges: one that answered `initialize`
/// (`init_ms`) on a VM started for it (cold) or reused or resumed (warm),
/// `how` its `vm_how`, and never moved the chat; or (S10, `moved`) one that
/// moved it, a reopen's carry included, past the cold budget, which stands
/// as the cold row.
struct InitRow<'a> {
    row: &'a serde_json::Value,
    parts: Parts<'a>,
    init_ms: u64,
    how: &'a str,
    moved: bool,
}

impl InitRow<'_> {
    /// The row in the note's words: its time from the census start to the
    /// forwarded answer, a moved session's named as such, how its VM was
    /// had, its Touch ID leg named first, every leg, the VM and when it
    /// started.
    fn describe(&self, kind: &str) -> String {
        let legs = part(&self.parts, crate::bridge::remote::census_part::LEGS);
        let touchid = legs.and_then(|l| l.split(',').find_map(|leg| leg.strip_prefix("touchid="))).map_or_else(|| "touchid not recorded".to_string(), |ms| format!("touchid {ms} ms"));
        let moved = if self.moved { ", a session that moved the chat, past every budget" } else { "" };
        format!(
            "{kind} {} ms{moved} ({touchid}; vm_how:{}; legs {}; {} at {})",
            self.init_ms,
            part(&self.parts, crate::bridge::remote::census_part::VM_HOW).unwrap_or("-"),
            legs.unwrap_or("-"),
            part(&self.parts, crate::bridge::remote::census_part::VM).unwrap_or("no vm part"),
            field(self.row, "ts")
        )
    }
}

/// init-wrapper's verdict on the newest cold and warm initialize times:
/// `over:<cold|warm|cold,warm>` past [`INIT_COLD_BUDGET_MS`] or the warm
/// row's own budget ([`warm_budget_ms`] of its `vm_how`: S10 F9) (a budget
/// met exactly passes), else `gap:<cold|warm|cold,warm>` for a kind the
/// census has no row of yet, else `within-budget`. `warm` is the newest
/// warm row's time and its `vm_how`.
#[must_use]
pub fn verdict_init_wrapper(cold_ms: Option<u64>, warm: Option<(u64, &str)>) -> String {
    let over: Vec<&str> = [(cold_ms.is_some_and(|c| u128::from(c) > INIT_COLD_BUDGET_MS), "cold"), (warm.is_some_and(|(w, how)| u128::from(w) > warm_budget_ms(how)), "warm")].into_iter().filter(|(o, _)| *o).map(|(_, n)| n).collect();
    if !over.is_empty() {
        return format!("over:{}", over.join(","));
    }
    let gap: Vec<&str> = [(cold_ms.is_none(), "cold"), (warm.is_none(), "warm")].into_iter().filter(|(g, _)| *g).map(|(_, n)| n).collect();
    if !gap.is_empty() {
        return format!("gap:{}", gap.join(","));
    }
    "within-budget".to_string()
}

/// The `init-wrapper` row (S8, plan L8), which `ai-env wrapper census
/// --record-probes` appends after the S1 verdicts: from the census rows
/// (oldest first), the remote sessions' end rows (`remote::MODE_NOTES`)
/// that answered `initialize` (`init_ms`, from the census start to the
/// forwarded answer); the newest whose VM was started for it (cold,
/// `vm_how:started`) against 30 s, the newest on a reused or resumed one
/// (warm) against its VM's budget, 5 s reused and 8 s resumed (S10 F9,
/// [`verdict_init_wrapper`]); the note names each one's Touch ID leg and
/// its legs, and counts the remote starts that never answered (not judged)
/// and the answered sessions that moved the chat (judged only past the cold
/// budget, never a pinned VM's; nor is a pinned VM's row judged). S10: a
/// move rewrites the row's `vm` and `vm_how` while its `init_ms` stays the
/// first answer the host got, and a reopen's carry, counted in `moves` too
/// (§2.7), is not told apart; so a moved row is judged only past
/// [`INIT_COLD_BUDGET_MS`], the largest budget, where it stands as the cold
/// row (`over:cold` whatever its first VM was), unless the chat was pinned
/// (a pinned VM has no budget): `vm_how:pinned`, which a respawn keeps, or
/// `AI_ENV_BRIDGE_VM` among the row's `env_names`, the start row's, which
/// still name it once the chat moved off the pinned VM. `ext` and `claude`
/// are the newest judged row's (the extension's bundle, the VM's claude).
/// `None` while no remote end row exists.
#[must_use]
pub fn init_wrapper_verdict(rows: &[serde_json::Value]) -> Option<ProbeRow> {
    use crate::bridge::remote::census_part::{CLAUDE, VM_HOW};
    let spec = spec("init-wrapper")?;
    let ends: Vec<(usize, &serde_json::Value, Parts<'_>)> = rows.iter().enumerate().filter(|(_, r)| is_end_row(r)).map(|(i, r)| (i, r, note_parts(r))).filter(|(_, _, p)| is_remote(p)).collect();
    if ends.is_empty() {
        return None;
    }
    let newest = |hows: &[&str], slow_moved: bool| {
        ends.iter().rev().find_map(|(i, row, parts)| {
            let how = part(parts, VM_HOW)?;
            let init_ms = part(parts, "init_ms")?.parse::<u64>().ok()?;
            // S10: every generation rewrites the link's vm and vm_how, a move's too, while init_ms stays the first
            // answer's and a move adds no legs, so no budget of its vm_how fits a moved session's row; a reopen's
            // carry (generation 1, counted in moves too) is not told apart. Past the cold budget, the largest, the
            // row is over whatever its first VM was: it stands as the cold row, so a slow start never reads within.
            // Never a pinned chat's (a pinned VM has no budget): vm_how:pinned, which a respawn keeps, or the pin
            // knob among its env_names, the start row's, which still name it once the chat moved off the pinned VM.
            let moved = moves_of(parts) >= 1;
            let pinned = how == "pinned" || row.get("env_names").and_then(serde_json::Value::as_array).is_some_and(|n| n.iter().any(|v| v == crate::bridge::remote::PIN_KNOB));
            let take = if moved { slow_moved && !pinned && u128::from(init_ms) > INIT_COLD_BUDGET_MS } else { hows.contains(&how) };
            take.then(|| (*i, InitRow { row, parts: parts.clone(), init_ms, how, moved }))
        })
    };
    let (cold, warm) = (newest(&["started"], true), newest(&["reused", "resumed"], false));
    let unanswered = ends.iter().filter(|(_, _, p)| part(p, "init_ms").is_none()).count();
    let moved = ends.iter().filter(|(_, _, p)| part(p, "init_ms").is_some() && moves_of(p) >= 1).count();
    let verdict = verdict_init_wrapper(cold.as_ref().map(|(_, c)| c.init_ms), warm.as_ref().map(|(_, w)| (w.init_ms, w.how)));
    let mut note = vec![
        cold.as_ref().map_or_else(|| "no cold row yet (a session whose VM was started for it)".to_string(), |(_, c)| c.describe("cold")),
        warm.as_ref().map_or_else(|| "no warm row yet (a session on a reused or resumed VM)".to_string(), |(_, w)| w.describe("warm")),
        format!("budgets {INIT_COLD_BUDGET_MS} ms cold, {INIT_WARM_BUDGET_MS} ms reused and {INIT_RESUMED_BUDGET_MS} ms resumed, from the census start to the forwarded answer"),
    ];
    if unanswered > 0 {
        note.push(format!("{unanswered} remote end row(s) never answered initialize (not judged)"));
    }
    if moved > 0 {
        note.push(format!("{moved} remote end row(s) moved the chat, a reopen's carry included (judged only past the {INIT_COLD_BUDGET_MS} ms cold budget: a move rewrites the row's vm_how while its init_ms stays the first answer's)"));
    }
    let judged = [cold, warm].into_iter().flatten().max_by_key(|(i, _)| *i).map(|(_, j)| j);
    let text = |k: &str| judged.as_ref().and_then(|j| j.row.get(k)).and_then(|v| v.as_str()).map(str::to_string);
    Some(ProbeRow {
        ext: text("ext"),
        sdk: judged.as_ref().and_then(|j| j.row.pointer("/env_selected/CLAUDE_AGENT_SDK_VERSION")).and_then(|v| v.as_str()).map(str::to_string),
        claude: judged.as_ref().and_then(|j| part(&j.parts, CLAUDE)).map(str::to_string),
        note: Some(note.join("; ")),
        ..ProbeRow::new(spec.name, spec.stage, &verdict, &spec.expect.expectation())
    })
}

/// The conversation a census row's argv resumes (`--resume UUID`, either
/// spelling), its wrapper and bundled claude skipped; `None` for a new chat.
fn resumed_id(row: &serde_json::Value) -> Option<String> {
    let argv: Vec<String> = row.get("argv")?.as_array()?.iter().skip(2).filter_map(|a| a.as_str().map(str::to_string)).collect();
    crate::wire::argv::value_of(&argv, "--resume").filter(|id| crate::wire::workspace::is_uuid(id)).map(str::to_string)
}

/// The moves a census end row counts (S10 §4.1, written once one started):
/// the sum of its `moves:readdress=<n>,respawn=<n>,migrate=<n>`; 0 without
/// the part, and a count that does not parse, or of another kind, adds nothing.
fn moves_of(parts: &[(&str, &str)]) -> u32 {
    part(parts, crate::bridge::remote::census_part::MOVES).map_or(0, |m| {
        m.split(',').filter_map(|kv| kv.split_once('=')).filter(|(kind, _)| matches!(*kind, "readdress" | "respawn" | "migrate")).filter_map(|(_, n)| n.parse::<u32>().ok()).fold(0, u32::saturating_add)
    })
}

/// 1 when a reopen's P0 to P4 carried the row's chat off its `--resume`
/// row's VM (S10 §2.7, `carried:`), which `moves` counts too; else 0.
fn carried_of(parts: &[(&str, &str)]) -> u32 {
    u32::from(part(parts, crate::bridge::remote::census_part::CARRIED).is_some())
}

/// The moves of a census end row whose claude ran (S10): [`moves_of`], less
/// the last one when the row ends `end:move_failed` and less a reopen's
/// carry ([`carried_of`]). `moves` counts the moves started, and a failed
/// move ends the session at its start, so no moved claude ran for it and
/// nothing was sent again; a carry sends nothing again either (its
/// `transcript:restored` keeps S9's rule).
fn moves_done(parts: &[(&str, &str)]) -> u32 {
    let failed = part(parts, "end") == Some(crate::bridge::pump::EndReason::MoveFailed.name());
    moves_of(parts).saturating_sub(u32::from(failed)).saturating_sub(carried_of(parts))
}

/// The census evidence the dup probes are recorded with (S8 T8.5, S10
/// T10.3): the newest end row of a remote session that answered
/// `initialize` (`init_ms`) and either resumed a conversation (`--resume
/// UUID`) into a VM without the transcript (`transcript:uploaded`, S8's
/// upload before the spawn, or S9's `transcript:restored`, its pull from S3,
/// or `transcript:staged`, a chat S3 did not hold yet, begun on this Mac or
/// an S8 mirror, sent up at the reopen and pulled into the VM; or
/// `respawns` of 1 or more, the resume miss's seed retry), or (S10) moved
/// the chat, its `moves` adding up to 1 or more but for a failed last one
/// (`moves_done`: a move that failed at its start sent nothing again),
/// with or without `--resume` (a new chat's row names no session). A start
/// row and its end row pair by the wrapper's pid and the census start, both
/// numbers (a row without them pairs with none). `Ok` is that row in the
/// note's words, with S10's `moves`, `inits` and `echoes` when the row has
/// them, naming the forced replay only when the start row recorded
/// `AI_ENV_BRIDGE_LAB_TRANSCRIPT=skip` and the end row a retry (L8: a
/// release wrapper, or another value, forces nothing); `Err` says what the
/// newest remote resume or move lacks (or that there is none) and how to
/// get the evidence.
pub fn resume_evidence(rows: &[serde_json::Value]) -> std::result::Result<String, String> {
    use crate::bridge::remote::census_part::{ECHOES, INITS, MOVES, TRANSCRIPT, VM, VM_HOW};
    const NEEDS: &str = "a census end row of a remote session (mode:remote) that resumed a conversation (--resume), answered initialize (init_ms) and found its VM without the transcript (transcript:uploaded, restored or staged, or respawns:1 or more), or (S10) one that answered initialize and moved the chat (its moves adding up to 1 or more, not counting the failed last move of an end:move_failed row)";
    // Each run's end row by its (pid, start), both numbers as the wrapper writes them, the newest should one repeat:
    // every remote start is looked up (S10's moves), so the census is read once.
    let key = |r: &serde_json::Value| Some((r.get("pid")?.as_u64()?, r.get("start")?.as_u64()?));
    let ends: std::collections::HashMap<(u64, u64), &serde_json::Value> = rows.iter().filter(|r| is_end_row(r)).filter_map(|r| Some((key(r)?, r))).collect();
    let end_of = |start: &serde_json::Value| key(start).and_then(|k| ends.get(&k).copied());
    // The remote starts that resumed a conversation, and (S10) those whose end row shows a move done, `--resume` or not.
    let starts: Vec<(&serde_json::Value, Option<String>)> = rows
        .iter()
        .filter(|r| !is_end_row(r) && field(r, "route") == "remote" && is_remote(&note_parts(r)))
        .filter_map(|r| {
            let id = resumed_id(r);
            (id.is_some() || end_of(r).is_some_and(|e| moves_done(&note_parts(e)) >= 1)).then_some((r, id))
        })
        .collect();
    let qualifies = |end: &serde_json::Value| {
        let parts = note_parts(end);
        part(&parts, "init_ms").is_some() && (matches!(part(&parts, TRANSCRIPT), Some("uploaded" | "restored" | "staged")) || part(&parts, "respawns").and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| n >= 1) || moves_done(&parts) >= 1)
    };
    let pid = |start: &serde_json::Value| start.get("pid").and_then(serde_json::Value::as_u64).unwrap_or(0);
    if let Some((start, id, end)) = starts.iter().rev().find_map(|(s, id)| end_of(s).filter(|e| qualifies(e)).map(|e| (*s, id, e))) {
        let parts = note_parts(end);
        let p = |name: &str| part(&parts, name).unwrap_or("-");
        // Only `skip` forces the miss, and only a debug wrapper honours it: the value the census recorded, and
        // the retry the end row shows (a release wrapper's run, or another value, shows none).
        let knob = start.get("env_selected").and_then(|s| s.get(crate::bridge::remote::TRANSCRIPT_KNOB)).and_then(serde_json::Value::as_str);
        let forced = knob == Some("skip") && part(&parts, "respawns").and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| n >= 1);
        let exit = end.get("exit").and_then(serde_json::Value::as_i64).map_or_else(|| "null".to_string(), |c| c.to_string());
        let who = id.as_ref().map_or_else(|| "a new chat (no --resume) started".to_string(), |id| format!("session {id} resumed"));
        // S10's counts where the row has them (an S9 wrapper's has none): the moves, and what the swallow rules forwarded and swallowed.
        let counts: String = [MOVES, INITS, ECHOES].iter().filter_map(|k| part(&parts, k).map(|v| format!(", {k}:{v}"))).collect();
        return Ok(format!(
            "census: {who} in remote mode at {} (wrapper pid {}) on {} (vm_how:{}): transcript:{}, respawns:{}{counts}, init_ms:{}, end:{}, exit {exit}{}",
            field(start, "ts"),
            pid(start),
            p(VM),
            p(VM_HOW),
            p(TRANSCRIPT),
            p("respawns"),
            p("init_ms"),
            p("end"),
            if forced { format!(" ({} was set: the forced replay)", crate::bridge::remote::TRANSCRIPT_KNOB) } else { String::new() }
        ));
    }
    let Some((start, id)) = starts.last() else {
        return Err(format!("no remote resume in the census; the dup probes need {NEEDS}: reopen a chat from Cursor's picker into a VM without its transcript (T8.5: ai-env vm terminate, then the picker), or move one to a new VM (T10.3: ai-env vm terminate during a turn), close it, then record"));
    };
    let newest = match id {
        Some(id) => format!("the newest remote resume (session {id}, started {})", field(start, "ts")),
        None => format!("the newest remote move (a new chat, wrapper pid {}, started {})", pid(start), field(start, "ts")),
    };
    let Some(end) = end_of(start) else {
        return Err(format!("{newest} has no census end row yet: close the chat (or reload Cursor), then record; the dup probes need {NEEDS}"));
    };
    let parts = note_parts(end);
    if part(&parts, "init_ms").is_none() {
        let exit = end.get("exit").and_then(serde_json::Value::as_i64).map_or_else(|| "null".to_string(), |c| c.to_string());
        let again = if id.is_some() { "reopen it from Cursor's picker" } else { "move a chat that answered (T10.3), close it" };
        return Err(format!("{newest} never answered initialize (end:{}, exit {exit}): {again}, then record; the dup probes need {NEEDS}", part(&parts, "end").unwrap_or("-")));
    }
    Err(format!(
        "{newest} found its VM holding the transcript (transcript:{}, respawns:{}): the dup probes judge a resume into a VM without it (T8.5: ai-env vm terminate, then reopen the chat from the picker); they need {NEEDS}",
        part(&parts, TRANSCRIPT).unwrap_or("-"),
        part(&parts, "respawns").unwrap_or("-")
    ))
}

/// A dup probe's verdict as Cursor showed it: `no-duplicate`, or
/// `duplicate:<what>` naming what was shown twice; `Err` names the form.
pub fn check_dup_verdict(probe: &str, verdict: &str) -> std::result::Result<(), String> {
    if verdict == "no-duplicate" || verdict.strip_prefix("duplicate:").is_some_and(|what| !what.trim().is_empty()) {
        return Ok(());
    }
    Err(format!("{probe}: the verdict is no-duplicate, or duplicate:<what Cursor showed twice> (got {verdict:?})"))
}

/// move-note's verdict as Cursor showed it (S10 L3): `shown`, or
/// `not-shown:<what>` naming what Cursor showed instead; `Err` names the form.
pub fn check_move_note_verdict(verdict: &str) -> std::result::Result<(), String> {
    if verdict == "shown" || verdict.strip_prefix("not-shown:").is_some_and(|what| !what.trim().is_empty()) {
        return Ok(());
    }
    Err(format!("move-note: the verdict is shown, or not-shown:<what Cursor showed instead> (got {verdict:?})"))
}

/// The census evidence `move-note` is recorded with (S10 L3, T10.3): the
/// newest remote end row whose `moves` add up to 1 or more beyond a reopen's
/// carry ([`carried_of`]), whatever else
/// it shows (a move that failed showed its note at its start too, so it
/// counts here, unlike the dup probes' `moves_done`), in the note's words:
/// its chat (the `--resume` id; a new chat's row names none), when its
/// wrapper started, the VM it was last on, the moves, the last move's time
/// and cut, the swallow rules' counts, `init_ms`, the end and the exit. A
/// reopen's carry (§2.7: it shows no note), counted in `moves` too and told
/// apart by `carried:`, is not taken. `Err` says there is none and how to
/// get one.
pub fn move_evidence(rows: &[serde_json::Value]) -> std::result::Result<String, String> {
    use crate::bridge::remote::census_part::{CUT, ECHOES, INITS, MOVES, MOVE_MS, VM, VM_HOW};
    let newest = rows.iter().rev().filter(|r| is_end_row(r) && field(r, "route") == "remote").map(|r| (r, note_parts(r))).find(|(_, parts)| is_remote(parts) && moves_of(parts) > carried_of(parts));
    let Some((end, parts)) = newest else {
        return Err("no remote end row in the census shows a move (moves adding up to 1 or more, a reopen's carry not counted); move-note is recorded only with that evidence: move a chat to a new VM in Cursor (T10.3: ai-env vm terminate during a turn), close it (or reload Cursor), then record".to_string());
    };
    let p = |name: &str| part(&parts, name).unwrap_or("-");
    let who = resumed_id(end).map_or_else(|| "a new chat (no --resume)".to_string(), |id| format!("session {id}"));
    let exit = end.get("exit").and_then(serde_json::Value::as_i64).map_or_else(|| "null".to_string(), |c| c.to_string());
    Ok(format!(
        "census: {who} moved in remote mode (started {}, wrapper pid {}), last on {} (vm_how:{}): moves:{}, move_ms:{}, cut:{}, inits:{}, echoes:{}, init_ms:{}, end:{}, exit {exit}",
        field(end, "ts"),
        end.get("pid").and_then(serde_json::Value::as_u64).unwrap_or(0),
        p(VM),
        p(VM_HOW),
        p(MOVES),
        p(MOVE_MS),
        p(CUT),
        p(INITS),
        p(ECHOES),
        p("init_ms"),
        p("end")
    ))
}

/// `lab run dup-init|dup-user-replay|move-note --manual VERDICT` (S8 T8.5,
/// S10 T10.3): the verdict's form ([`check_dup_verdict`],
/// [`check_move_note_verdict`]; exit 2), then the census evidence the probe
/// is recorded with, from `logs/census.jsonl`: a remote resume into a VM
/// without the transcript, or a move ([`resume_evidence`]), and for
/// move-note a move ([`move_evidence`]). The row's note carries it; without
/// it nothing is recorded (exit 1, naming the evidence).
pub fn cursor_evidence(paths: &crate::bridge::config::Paths, probe: &str, verdict: &str) -> Result<String> {
    let evidence = if probe == "move-note" {
        check_move_note_verdict(verdict).map_err(CliError::Usage)?;
        move_evidence(&read_rows(&paths.census(), None)?)
    } else {
        check_dup_verdict(probe, verdict).map_err(CliError::Usage)?;
        resume_evidence(&read_rows(&paths.census(), None)?)
    };
    evidence.map_err(|why| CliError::Msg(format!("{probe}: {why}; nothing recorded")))
}

/// fresh-claude-json's verdict: `no-stall` once claude answered
/// `initialize` and then its first turn's result was an answer;
/// `stall:initialize` without the answer to `initialize` (Cursor's window
/// passed, or claude exited first), `stall:turn` without the turn's result,
/// `stall:turn-error` for an error result. (`turn`: whether that result was
/// an answer, `None` when none came.)
#[must_use]
pub fn verdict_fresh_claude_json(initialized: bool, turn: Option<bool>) -> &'static str {
    match (initialized, turn) {
        (false, _) => "stall:initialize",
        (true, None) => "stall:turn",
        (true, Some(false)) => "stall:turn-error",
        (true, Some(true)) => "no-stall",
    }
}

/// A row for `spec` stamped now, with the image's claude version and active
/// image version from `state/infra.toml` when recorded (live probes
/// overwrite them with what `/health` and the VM row say). A Mac probe's row
/// carries none of them: it measured this Mac (its own CLI, age-plugin-se,
/// the sealed token), never the image, and a row stamped with the image's
/// claude version would key what oauth-t1 found to a CLI it never ran (its
/// note names the one it did).
#[must_use]
pub fn stamped(paths: &crate::bridge::config::Paths, spec: &ProbeSpec, verdict: &str, note: Option<String>) -> ProbeRow {
    if spec.source == Source::Mac {
        return ProbeRow { note, ..ProbeRow::new(spec.name, spec.stage, verdict, &spec.expect.expectation()) };
    }
    let infra = crate::bridge::infra::read_infra_state(paths).ok().flatten();
    let claude = infra.as_ref().and_then(|s| s.claude_version.clone());
    ProbeRow {
        ext: claude.clone(),
        claude,
        image_version: infra.and_then(|s| s.latest_active_image_version),
        note,
        ..ProbeRow::new(spec.name, spec.stage, verdict, &spec.expect.expectation())
    }
}

/// Append `row`, audit it (`lab_probe`, plan S4 D24), print `recorded X=V
/// (expected E)`, and fail (after writing) when the verdict misses its
/// expectation.
pub fn record(paths: &crate::bridge::config::Paths, row: &ProbeRow) -> Result<()> {
    let holds = append_row(&paths.probes(), row)?;
    let detail = crate::bridge::audit::detail(&[("probe", row.probe.clone()), ("verdict", row.verdict.clone()), ("expected", row.expected.clone())]);
    if let Err(e) = crate::bridge::audit::append(&paths.audit(), &crate::bridge::audit::AuditRow::new(crate::bridge::audit::event::LAB_PROBE, None, detail)) {
        eprintln!("ai-env: warning: audit row lab_probe not written: {e}");
    }
    outln!("recorded {}={} (expected {})", row.probe, row.verdict, row.expected);
    if let Some(note) = &row.note {
        outln!("  {note}");
    }
    if !holds {
        crate::bail!("probe verdict differs from the expectation: {}={} (expected {})", row.probe, row.verdict, row.expected);
    }
    Ok(())
}

// ---- log parsers ------------------------------------------------------------------------

/// One `ai-env: hook <name> peer=… local=… origin=… len=… status=… ms=…`
/// line of the shim (`shim/hooks.rs`), found anywhere in a log line (the
/// `make logs` output prefixes a timestamp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookLine {
    pub hook: String,
    pub peer: Option<String>,
    pub local: Option<String>,
    pub origin: Option<String>,
    pub status: Option<u16>,
}

/// Every hook line in `text`.
#[must_use]
pub fn parse_hook_lines(text: &str) -> Vec<HookLine> {
    const MARK: &str = "ai-env: hook ";
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(at) = line.find(MARK) else { continue };
        let mut words = line[at + MARK.len()..].split_whitespace();
        let Some(hook) = words.next() else { continue };
        let mut h = HookLine { hook: hook.to_string(), peer: None, local: None, origin: None, status: None };
        for w in words {
            let Some((k, v)) = w.split_once('=') else { continue };
            let v = (v != "-").then(|| v.to_string());
            match k {
                "peer" => h.peer = v,
                "local" => h.local = v,
                "origin" => h.origin = v,
                "status" => h.status = v.and_then(|s| s.parse().ok()),
                _ => {}
            }
        }
        out.push(h);
    }
    out
}

/// The port of `host:port` / `[v6]:port`.
#[must_use]
pub fn local_port(addr: &str) -> Option<u16> {
    addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

/// The runtime hooks (the image hooks `/ready` and `/validate` come from the build).
const RUNTIME_HOOKS: [&str; 4] = ["run", "resume", "suspend", "terminate"];

fn runtime_hooks(lines: &[HookLine]) -> Vec<&HookLine> {
    lines.iter().filter(|h| RUNTIME_HOOKS.contains(&h.hook.as_str())).collect()
}

fn joined<'a>(it: impl Iterator<Item = &'a str>) -> String {
    let set: std::collections::BTreeSet<&str> = it.collect();
    set.into_iter().collect::<Vec<_>>().join(",")
}

fn counts(lines: &[&HookLine]) -> String {
    let mut by: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for h in lines {
        *by.entry(h.hook.as_str()).or_default() += 1;
    }
    by.iter().map(|(k, v)| format!("{k}×{v}")).collect::<Vec<_>>().join(" ")
}

/// hooks-port: the set of local ports of the runtime hook lines (`9000`, or
/// `8080,9000` when they differ); `Err` when the log has none.
pub fn verdict_hooks_port(lines: &[HookLine]) -> std::result::Result<(String, String), String> {
    let rt = runtime_hooks(lines);
    if rt.is_empty() {
        return Err("no runtime hook line (run/resume/suspend/terminate) in the log".into());
    }
    let ports: Vec<String> = rt.iter().filter_map(|h| h.local.as_deref().and_then(local_port)).map(|p| p.to_string()).collect();
    if ports.is_empty() {
        return Err("the runtime hook lines carry no local address".into());
    }
    Ok((joined(ports.iter().map(String::as_str)), format!("{} runtime hook lines: {}", rt.len(), counts(&rt))))
}

/// hooks-source-ip: the set of origins of the runtime hook lines
/// (`loopback`, `remote`, `self`, joined when mixed).
pub fn verdict_hooks_source(lines: &[HookLine]) -> std::result::Result<(String, String), String> {
    let rt = runtime_hooks(lines);
    if rt.is_empty() {
        return Err("no runtime hook line (run/resume/suspend/terminate) in the log".into());
    }
    let origins: Vec<&str> = rt.iter().filter_map(|h| h.origin.as_deref()).collect();
    if origins.is_empty() {
        return Err("the runtime hook lines carry no origin".into());
    }
    let peers = joined(rt.iter().filter_map(|h| h.peer.as_deref().and_then(|p| p.rsplit_once(':').map(|(ip, _)| ip))));
    Ok((joined(origins.into_iter()), format!("{} runtime hook lines: {}; peers {peers}", rt.len(), counts(&rt))))
}

/// Every `ai-env: run-report {json}` object in `text` (plan S4 D19).
#[must_use]
pub fn parse_run_reports(text: &str) -> Vec<serde_json::Value> {
    const MARK: &str = "ai-env: run-report ";
    text.lines().filter_map(|l| l.find(MARK).map(|at| &l[at + MARK.len()..])).filter_map(|j| serde_json::from_str::<serde_json::Value>(j.trim()).ok()).filter(serde_json::Value::is_object).collect()
}

fn reports_of<'a>(reports: &'a [serde_json::Value], hook: &str) -> Vec<&'a serde_json::Value> {
    reports.iter().filter(|r| r.get("hook").and_then(|h| h.as_str()) == Some(hook)).collect()
}

/// The environment values the run report may carry (the shim's allowlist, D19).
const RUNTIME_ENV_VALUES: [&str; 6] = ["HOME", "PATH", "AWS_REGION", "AWS_LAMBDA_MICROVM_IMAGE_NAME", "AWS_LAMBDA_MICROVM_IMAGE_ARN", "AWS_LAMBDA_MICROVM_IMAGE_VERSION"];

const NO_REPORT: &str = "no `ai-env: run-report` line with hook \"run\" in the log (runtime logs need [aws].execution_role_arn and an image built from S4 on)";

/// runtime-env from the newest `run` report: the verdict says whether AWS
/// credential variables were in PID 1's environment (names only ever), the
/// note lists every name and the allowlisted values. The shim writes
/// `env` and `aws_credential_env` as null when PID 1's environ was
/// unreadable: that is an error here, never `absent`.
pub fn verdict_runtime_env(reports: &[serde_json::Value]) -> std::result::Result<(String, String), String> {
    fn strs(v: &serde_json::Value) -> Vec<&str> {
        v.as_array().map(|a| a.iter().filter_map(|s| s.as_str()).collect()).unwrap_or_default()
    }
    let r = *reports_of(reports, "run").last().ok_or(NO_REPORT)?;
    if r.get("unsupported").is_some() {
        return Err("the run report says unsupported (not a Linux shim)".into());
    }
    let env = r.get("env").filter(|e| e.is_object());
    let cred = r.get("aws_credential_env").or_else(|| r.pointer("/env/aws_credential_env")).filter(|c| c.is_array());
    let (Some(env), Some(cred)) = (env, cred) else {
        return Err("the run report has no environment (PID 1's environ was unreadable)".into());
    };
    let cred = strs(cred);
    let names = env.get("names").map(strs).unwrap_or_default();
    // Only the shim's allowlisted values are ever repeated (defence in depth against a shim that sent more).
    let values = env
        .get("values")
        .and_then(|v| v.as_object())
        .map(|m| m.iter().filter(|(k, _)| RUNTIME_ENV_VALUES.contains(&k.as_str())).map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("?"))).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let verdict = if cred.is_empty() { "aws-credentials:absent".to_string() } else { format!("aws-credentials:{}", cred.join(",")) };
    Ok((verdict, format!("names: {}; values: {values}", names.join(","))))
}

/// disk-budget from the newest `run` report: `used=<MiB>MiB total=<MiB>MiB`
/// (a note warns above 512 MiB, the plan's budget for the bare image).
pub fn verdict_disk_budget(reports: &[serde_json::Value]) -> std::result::Result<(String, String), String> {
    let r = *reports_of(reports, "run").last().ok_or(NO_REPORT)?;
    let n = |k: &str| r.get(k).and_then(serde_json::Value::as_u64);
    let (Some(used), Some(total)) = (n("disk_used_bytes"), n("disk_total_bytes")) else {
        return Err("the run report has no disk_used_bytes/disk_total_bytes".into());
    };
    let mib = |b: u64| b / (1024 * 1024);
    let note = if mib(used) > 512 { "above the 0.5 GB budget".to_string() } else { "within the 0.5 GB budget".to_string() };
    Ok((format!("used={}MiB total={}MiB", mib(used), mib(total)), note))
}

/// snapshot-uniqueness, log pass: the `boot_id`s of the `run` reports of
/// `ids` (the VMs of the live pass). Returns `identical` / `differ` and the pairs.
pub fn boot_ids(reports: &[serde_json::Value], ids: &[&str]) -> std::result::Result<(String, String), String> {
    let mut pairs = Vec::new();
    for id in ids {
        let r = reports_of(reports, "run").into_iter().rev().find(|r| r.get("microvm_id").and_then(|m| m.as_str()) == Some(*id)).ok_or_else(|| format!("no run report of {id} in the log"))?;
        let boot = r.get("boot_id").and_then(|b| b.as_str()).ok_or_else(|| format!("the run report of {id} has no boot_id"))?;
        pairs.push((*id, boot.to_string()));
    }
    let same = pairs.windows(2).all(|w| w[0].1 == w[1].1);
    let listed = pairs.iter().map(|(id, b)| format!("{id}={b}")).collect::<Vec<_>>().join(" ");
    Ok((if same { "identical" } else { "differ" }.to_string(), listed))
}

// ---- CloudTrail ---------------------------------------------------------------------------

/// The CloudTrail resource type of Lambda MicroVMs data events. RunMicrovm,
/// TerminateMicrovm, SuspendMicrovm, ResumeMicrovm and the two token calls
/// are data events: CloudTrail logs them only for a trail or a service-linked
/// channel (CloudWatch's CloudTrail ingestion, Security Lake) that selects
/// this type, and event history (`lookup-events`) never has them (AWS Lambda
/// MicroVMs docs, "Monitoring"; S4 part B, 30 Sep 2026).
pub const MICROVM_DATA_RESOURCE: &str = "AWS::Lambda::MicrovmImage";

/// Whether one field selector of an advanced event selector lets `value`
/// through, as CloudTrail evaluates it ("How CloudTrail evaluates multiple
/// conditions for a field"): the SELECT operators (`Equals`, `StartsWith`,
/// `EndsWith`) are OR'd — any match selects, and a field without one selects
/// everything — and a match of any DESELECT operator (`NotEquals`,
/// `NotStartsWith`, `NotEndsWith`) excludes.
fn field_allows(field: &serde_json::Value, value: &str) -> bool {
    let list = |k: &str| field.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>());
    let any = |k: &str, f: &dyn Fn(&str) -> bool| list(k).is_some_and(|l| l.iter().any(|x| f(x)));
    let has_select = ["Equals", "StartsWith", "EndsWith"].iter().any(|k| list(k).is_some());
    let selected = !has_select || any("Equals", &|x| x == value) || any("StartsWith", &|x| value.starts_with(x)) || any("EndsWith", &|x| value.ends_with(x));
    let deselected = any("NotEquals", &|x| x == value) || any("NotStartsWith", &|x| value.starts_with(x)) || any("NotEndsWith", &|x| value.ends_with(x));
    selected && !deselected
}

/// Whether a trail's `get-event-selectors` document, or a channel's
/// `SourceConfig`, selects the RunMicrovm data event. Conservative: a field the
/// selector does not constrain lets the event through, and only the fields
/// that can exclude RunMicrovm are evaluated (`resources.ARN` is not), so a
/// "maybe" counts as logging — the probe then asks for the trail's record
/// instead of claiming nothing is kept.
#[must_use]
pub fn selectors_log_microvm_data(doc: &serde_json::Value) -> bool {
    let run_microvm = [("eventCategory", "Data"), ("resources.type", MICROVM_DATA_RESOURCE), ("eventName", "RunMicrovm"), ("eventSource", "lambda.amazonaws.com"), ("readOnly", "false")];
    let advanced = doc.get("AdvancedEventSelectors").and_then(|a| a.as_array()).is_some_and(|sels| {
        sels.iter().any(|sel| {
            let fields = sel.get("FieldSelectors").and_then(|f| f.as_array()).map(Vec::as_slice).unwrap_or_default();
            run_microvm.iter().all(|(name, value)| fields.iter().filter(|f| f.get("Field").and_then(|v| v.as_str()) == Some(*name)).all(|f| field_allows(f, value)))
        })
    });
    let basic = doc.get("EventSelectors").and_then(|a| a.as_array()).is_some_and(|sels| {
        sels.iter().any(|sel| {
            let rw_ok = sel.get("ReadWriteType").and_then(|v| v.as_str()) != Some("ReadOnly");
            rw_ok && sel.get("DataResources").and_then(|d| d.as_array()).is_some_and(|d| d.iter().any(|r| r.get("Type").and_then(|t| t.as_str()) == Some(MICROVM_DATA_RESOURCE)))
        })
    });
    advanced || basic
}

/// What a CloudTrail channel (`get-channel`) may do with RunMicrovm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelCover {
    /// Its selectors take RunMicrovm: the destination keeps the record.
    Logs,
    /// A service-linked channel whose selectors cannot be read: counted as keeping it.
    Maybe,
    /// Its selectors exclude RunMicrovm, or it serves only another Region.
    No,
    /// A CloudTrail Lake integration channel (external events into event data stores): not AWS API calls.
    External,
}

/// One channel as the probe sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelView {
    pub name: String,
    pub arn: String,
    pub cover: ChannelCover,
    /// The creating service for a service-linked channel (`cloudwatch`, `security-lake`, …), else `integration`.
    pub kind: String,
    /// `(Type, Location)` of each destination.
    pub destinations: Vec<(String, String)>,
}

/// Classify a `get-channel` document. Service-linked channels are named
/// `aws-service-channel/<service>/…` and deliver to `AWS_SERVICE`; CloudWatch
/// ingests CloudTrail events only through one (`aws-service-channel/cloudwatch/…`).
/// The selectors sit under `SourceConfig`, in a trail's shape. Conservative:
/// a service-linked channel without readable selectors is [`ChannelCover::Maybe`].
#[must_use]
pub fn channel_cover(doc: &serde_json::Value) -> ChannelView {
    let s = |p: &str| doc.pointer(p).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let (name, arn) = (s("/Name"), s("/ChannelArn"));
    let destinations: Vec<(String, String)> = doc
        .get("Destinations")
        .and_then(|d| d.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|d| (d.get("Type").and_then(|v| v.as_str()).unwrap_or_default().to_string(), d.get("Location").and_then(|v| v.as_str()).unwrap_or_default().to_string()))
        .collect();
    let service_linked = name.starts_with("aws-service-channel/") || destinations.iter().any(|(t, _)| t == "AWS_SERVICE");
    let kind = if let Some(rest) = name.strip_prefix("aws-service-channel/") {
        rest.split('/').next().unwrap_or(rest).to_string()
    } else if let Some((_, loc)) = destinations.iter().find(|(t, _)| t == "AWS_SERVICE") {
        loc.clone()
    } else {
        "integration".to_string()
    };
    let view = |cover| ChannelView { name: name.clone(), arn: arn.clone(), cover, kind: kind.clone(), destinations: destinations.clone() };
    if !service_linked && !destinations.is_empty() && destinations.iter().all(|(t, _)| t == "EVENT_DATA_STORE") {
        return view(ChannelCover::External);
    }
    let region = arn.split(':').nth(3).unwrap_or_default();
    if doc.pointer("/SourceConfig/ApplyToAllRegions").and_then(serde_json::Value::as_bool) == Some(false) && !region.is_empty() && region != crate::bridge::config::REGION {
        return view(ChannelCover::No);
    }
    let source = doc.get("SourceConfig");
    let readable = source.and_then(|c| c.get("AdvancedEventSelectors")).and_then(|a| a.as_array()).is_some_and(|a| !a.is_empty());
    if !readable {
        return view(ChannelCover::Maybe);
    }
    view(if source.is_some_and(selectors_log_microvm_data) { ChannelCover::Logs } else { ChannelCover::No })
}

/// `(Region, name)` of a CloudWatch Logs log group ARN
/// (`arn:aws:logs:REGION:ACCT:log-group:NAME:*`, the form `describe-trails`
/// gives as `CloudWatchLogsLogGroupArn`); `None` for anything else or a name
/// outside `[A-Za-z0-9._/#-]` (the name is printed inside a shell command).
#[must_use]
pub fn log_group_from_arn(arn: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = arn.splitn(7, ':').collect();
    if parts.len() != 7 || parts[0] != "arn" || parts[2] != "logs" || parts[3].is_empty() || parts[5] != "log-group" {
        return None;
    }
    let name = parts[6].strip_suffix(":*").unwrap_or(parts[6]);
    is_safe_log_group_name(name).then(|| (parts[3].to_string(), name.to_string()))
}

/// A log group name the probe may print inside a single-quoted shell word:
/// non-empty, `[A-Za-z0-9._/#-]` only (a subset of what CloudWatch allows).
#[must_use]
pub fn is_safe_log_group_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || "._/#-".contains(c))
}

/// A redaction marker is the whole value, never a substring (a logged
/// payload's owner may say "hidden").
fn is_redaction_marker(s: &str) -> bool {
    let s = s.trim();
    s.eq_ignore_ascii_case("HIDDEN_DUE_TO_SECURITY_REASONS") || s.eq_ignore_ascii_case("REDACTED") || s.eq_ignore_ascii_case("HIDDEN") || (!s.is_empty() && s.chars().all(|c| c == '*'))
}

/// Where a record was read from (the row note names it: a CloudWatch copy may
/// have been transformed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    Trail,
    LogsRaw,
    LogsOcsf,
}

impl Provenance {
    fn label(self) -> &'static str {
        match self {
            Provenance::Trail => "CloudTrail record",
            Provenance::LogsRaw => "CloudWatch Logs, raw",
            Provenance::LogsOcsf => "CloudWatch Logs, OCSF",
        }
    }
}

/// One record: the CloudTrail shape, its raw text (searched for the session
/// token), and where it came from.
struct CtRecord {
    rec: serde_json::Value,
    raw: String,
    from: Provenance,
}

/// An OCSF `api.request.data` / `api.response.data` value as a CloudTrail
/// `requestParameters` / `responseElements`: an object, a JSON string of an
/// object, or a whole-value redaction marker; anything else is refused.
fn ocsf_data(v: Option<&serde_json::Value>, required: bool, eid: &str, what: &str) -> std::result::Result<serde_json::Value, String> {
    match v {
        None | Some(serde_json::Value::Null) if !required => Ok(serde_json::Value::Null),
        None | Some(serde_json::Value::Null) => Err(format!("CloudWatch Logs event {eid}: an OCSF record without {what}")),
        Some(o @ serde_json::Value::Object(_)) => Ok(o.clone()),
        Some(serde_json::Value::String(s)) if is_redaction_marker(s) => Ok(serde_json::Value::String(s.clone())),
        Some(serde_json::Value::String(s)) => match serde_json::from_str::<serde_json::Value>(s) {
            Ok(o @ serde_json::Value::Object(_)) => Ok(o),
            _ => Err(format!("CloudWatch Logs event {eid}: {what} is neither an object nor a JSON object string")),
        },
        Some(_) => Err(format!("CloudWatch Logs event {eid}: {what} is neither an object nor a JSON object string")),
    }
}

/// The CloudTrail records in `doc`: a trail's log file (`{"Records": [...]}`,
/// gunzipped), `aws logs filter-log-events` output (`{"events": [{"message":
/// "...", "eventId": "..."}]}` — each message a raw CloudTrail record or an
/// OCSF one mapped back: `api.operation` → eventName, `metadata.uid` →
/// eventID, `api.request.data` / `api.response.data` → requestParameters /
/// responseElements), a `lookup-events` answer (`{"Events":
/// [{"CloudTrailEvent": "..."}]}`), a JSON array of records, or one record. A
/// CloudWatch message that cannot be read is an error, never skipped: the
/// filter output holds only matches.
fn cloudtrail_records(doc: &serde_json::Value) -> std::result::Result<Vec<CtRecord>, String> {
    let own = |r: &serde_json::Value| CtRecord { rec: r.clone(), raw: r.to_string(), from: Provenance::Trail };
    if let Some(records) = doc.get("Records").and_then(|r| r.as_array()) {
        return Ok(records.iter().map(own).collect());
    }
    if let Some(events) = doc.get("events").and_then(|e| e.as_array()) {
        let mut out = Vec::new();
        for ev in events {
            let eid = ev.get("eventId").and_then(|v| v.as_str()).unwrap_or("?");
            let msg = ev.get("message").and_then(|m| m.as_str()).ok_or_else(|| format!("CloudWatch Logs event {eid} has no message"))?;
            let v: serde_json::Value = serde_json::from_str(msg).map_err(|_| format!("CloudWatch Logs event {eid}: the message is not JSON"))?;
            if v.get("eventName").is_some() {
                out.push(CtRecord { rec: v, raw: msg.to_string(), from: Provenance::LogsRaw });
                continue;
            }
            let Some(op) = v.pointer("/api/operation").and_then(|o| o.as_str()) else {
                return Err(format!("CloudWatch Logs event {eid}: neither a CloudTrail record (eventName) nor OCSF (api.operation)"));
            };
            if v.pointer("/api/request").is_none() {
                return Err(format!("CloudWatch Logs event {eid}: an OCSF record without api.request"));
            }
            let rec = serde_json::json!({
                "eventName": op,
                "eventID": v.pointer("/metadata/uid").cloned().unwrap_or(serde_json::Value::Null),
                "requestParameters": ocsf_data(v.pointer("/api/request/data"), true, eid, "api.request.data")?,
                "responseElements": ocsf_data(v.pointer("/api/response/data"), false, eid, "api.response.data")?,
            });
            out.push(CtRecord { rec, raw: msg.to_string(), from: Provenance::LogsOcsf });
        }
        return Ok(out);
    }
    if let Some(events) = doc.get("Events").and_then(|e| e.as_array()) {
        return Ok(events
            .iter()
            .filter_map(|ev| ev.get("CloudTrailEvent").and_then(|c| c.as_str()))
            .filter_map(|raw| serde_json::from_str::<serde_json::Value>(raw).ok().map(|rec| CtRecord { rec, raw: raw.to_string(), from: Provenance::Trail }))
            .collect());
    }
    if let Some(records) = doc.as_array() {
        return Ok(records.iter().map(own).collect());
    }
    if doc.get("eventName").is_some() {
        return Ok(vec![own(doc)]);
    }
    Err("not a CloudTrail document: no Records, events (CloudWatch Logs), Events or eventName".into())
}

/// cloudtrail-payload from a CloudTrail document (see [`cloudtrail_records`]):
/// every `RunMicrovm` record of this VM (matched by
/// `responseElements.microvmId` or `requestParameters.clientToken`; records
/// without an event name or of other calls on the same VM are skipped), then
/// what each kept of `runHookPayload`: `absent`, `hidden` (a redaction
/// marker), `commitment-only` (the payload with the commitment and without
/// the session token), `present-other`, or `LEAKED` when the session token
/// appears anywhere in a record. LEAKED in any record wins; records that
/// disagree otherwise are refused, as is a CloudWatch copy with masked
/// (`****`) text (fetch it with `--unmask`). `Ok(None)` when no record matched.
pub fn verdict_cloudtrail(doc_json: &str, id: &str, client_token: &str, session_token: Option<&str>, commit: &str) -> std::result::Result<Option<(String, String)>, String> {
    let doc: serde_json::Value = serde_json::from_str(doc_json).map_err(|e| format!("CloudTrail document: {e}"))?;
    let mut found: Vec<(&'static str, String)> = Vec::new();
    for r in cloudtrail_records(&doc)? {
        let inner = &r.rec;
        if inner.get("eventName").and_then(|v| v.as_str()) != Some("RunMicrovm") {
            continue;
        }
        let by_id = inner.pointer("/responseElements/microvmId").and_then(|v| v.as_str()) == Some(id);
        let by_token = !client_token.is_empty() && inner.pointer("/requestParameters/clientToken").and_then(|v| v.as_str()) == Some(client_token);
        if !(by_id || by_token) {
            continue;
        }
        let event_id = inner.get("eventID").and_then(|v| v.as_str()).unwrap_or("?");
        let label = format!("event {event_id} (matched by {}; {})", if by_id { "microvmId" } else { "clientToken" }, r.from.label());
        if session_token.is_some_and(|t| !t.is_empty() && r.raw.contains(t)) {
            return Ok(Some(("LEAKED".to_string(), format!("{label}: the session token itself is in the event"))));
        }
        if r.from != Provenance::Trail && r.raw.contains("****") {
            return Err(format!("{label} has masked text: fetch it again with --unmask"));
        }
        let verdict = match inner.get("requestParameters") {
            None | Some(serde_json::Value::Null) => "absent",
            Some(serde_json::Value::String(s)) if is_redaction_marker(s) => "hidden",
            Some(serde_json::Value::Object(_)) => match inner.pointer("/requestParameters/runHookPayload") {
                None | Some(serde_json::Value::Null) => "absent",
                Some(serde_json::Value::String(s)) if is_redaction_marker(s) => "hidden",
                Some(serde_json::Value::String(s)) if s.contains(commit) => "commitment-only",
                Some(_) => "present-other",
            },
            Some(_) => return Err(format!("{label}: requestParameters is neither an object nor a redaction marker")),
        };
        found.push((verdict, label));
    }
    let Some((first, _)) = found.first() else { return Ok(None) };
    if found.iter().any(|(v, _)| v != first) {
        let all = found.iter().map(|(v, l)| format!("{l}={v}")).collect::<Vec<_>>().join(", ");
        return Err(format!("the matching records disagree: {all}"));
    }
    Ok(Some((first.to_string(), found.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join(", "))))
}

// ---- S5: dns-path and connector-pending -----------------------------------------------------

/// One `dig` of the dns-path probe (and of `ai-env egress check`'s DNS cases),
/// which asks a fresh name that exists nowhere (`d<nonce>.example.com A`)
/// and, of a server that replied, `example.com A`: which server, over which
/// transport, dig's exit code (`None`: not asked — `/etc/resolv.conf` named
/// no nameserver), whether either reply carried an address, and the fresh
/// name's reply as dig's header printed it — its status, the
/// recursion-available flag, and the ANSWER and AUTHORITY counts (`None`:
/// not printed). Only NOERROR with 0 and 0 is the reply the platform's stub
/// gives and the operator tested ([`is_empty_noerror`]): a validating
/// recursor answers the fresh name NOERROR with the zone's SOA in AUTHORITY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsReply {
    pub server: String,
    /// `udp` | `tcp`.
    pub transport: &'static str,
    pub rc: Option<i32>,
    pub resolves: bool,
    pub status: Option<String>,
    pub ra: Option<bool>,
    /// The header's `ANSWER:` count.
    pub answers: Option<u16>,
    /// The header's `AUTHORITY:` count.
    pub authority: Option<u16>,
}

/// The one reply of a platform resolver that may be accepted: status
/// NOERROR with no answer and no authority section. Anything else — another
/// status ([`DNS_NO_EXAMPLE`] included), a record, an SOA, a count dig did
/// not print — is "answered" (fail closed: a parsing slip can only fail a
/// check).
#[must_use]
pub fn is_empty_noerror(status: Option<&str>, answers: Option<u16>, authority: Option<u16>) -> bool {
    status == Some("NOERROR") && answers == Some(0) && authority == Some(0)
}

/// The status the check script reports in place of the fresh name's
/// (`st=NOEXAMPLE`) when the server replied to the fresh name but dig got no
/// reply asking it `example.com A`: the platform's stub answers both at once
/// (2 Oct 2026: 0 ms), so this is never the reply that was tested — a
/// forwarder whose upstream does not answer in time looks so
/// ([`is_empty_noerror`] refuses it: answered).
pub const DNS_NO_EXAMPLE: &str = "NOEXAMPLE";
/// How the reasons and the dns-path note say [`DNS_NO_EXAMPLE`].
pub const DNS_NO_EXAMPLE_SAID: &str = "example.com A unanswered";

/// The dns-path verdict when a resolver that is not the platform's replies
/// (`open-dns:<ip>[,<ip>…]`): a failing verdict, never accepted
/// (`egress::dns_verdict_ok` refuses it).
pub const DNS_OPEN_PREFIX: &str = "open-dns:";
/// The dns-path verdict when a platform resolver returned an address — for
/// the fresh name, which exists nowhere, or for example.com (a forwarder
/// that drops the authority section still hands out example.com's): its
/// lookups reach authoritative servers, a path out.
/// `platform-dns-resolves:<ip>[,<ip>…]`, never accepted.
pub const DNS_PLATFORM_RESOLVES_PREFIX: &str = "platform-dns-resolves:";
/// The dns-path verdict when a platform resolver replied with anything but
/// an empty NOERROR ([`is_empty_noerror`]): NXDOMAIN, SERVFAIL, REFUSED,
/// NOTIMP, an SOA in AUTHORITY, records without an address, no header dig
/// could print, a truncated UDP reply whose TCP retry got nothing, or no
/// reply to example.com ([`DNS_NO_EXAMPLE`]).
/// `platform-dns-answered:<ip>[,<ip>…]`, never accepted: the
/// operator accepted the reply they tested and nothing else (a different
/// reply from the same address means the platform changed, and the canary
/// tests must be repeated; a forwarder can pass on its upstream's REFUSED).
pub const DNS_PLATFORM_ANSWERED_PREFIX: &str = "platform-dns-answered:";

/// An address of the platform resolver's class (`config::is_platform_address`:
/// a private or link-local IPv4, or `fd00:ec2::/32`) — the address class
/// only, never the acceptance (`[egress].accept_platform_dns`). Anything
/// else that replies is open DNS.
#[must_use]
pub fn is_platform_resolver(ip: &str) -> bool {
    crate::bridge::config::is_platform_address(ip)
}

/// How bad one reply (or a server's worst reply) is, the worst last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DnsClass {
    /// dig exit 9: nothing came back.
    Silent,
    /// A platform resolver's empty NOERROR (`platform-dns:`).
    Empty,
    /// A platform resolver's other reply (`platform-dns-answered:`).
    Answered,
    /// A platform resolver's address (`platform-dns-resolves:`).
    Resolves,
    /// Any reply of another server (`open-dns:`).
    Open,
}

/// dns-path from the digs of one VM. Each server is ranked by its worst
/// reply: `open-dns` when it is not a platform resolver
/// ([`is_platform_resolver`]: a public one, a local stub) and replied;
/// `platform-dns-resolves` when a platform resolver returned an address;
/// `platform-dns-answered` when one replied otherwise than with an empty
/// NOERROR ([`is_empty_noerror`]); `platform-dns` for an empty NOERROR; no
/// reply (dig exit 9) ranks lowest. A truncated UDP reply whose TCP retry got
/// nothing (exit 9 with a status) is a reply: open for a server that is not
/// the platform's, answered for one that is (never the empty NOERROR tested,
/// and the check's judge fails it). The verdict is the worst class, followed
/// by every server of that class in case order, comma-separated (so
/// acceptance never depends on which server was asked first); `no-dns` when
/// no server replied. The note says `resolves=yes|no` (did any reply carry
/// an address), the resolv.conf nameserver, and each server's replies (their
/// status, ANSWER and AUTHORITY counts, and whether recursion was offered).
/// Any other dig exit code proves nothing about its server: an error (a
/// missing dig must never read as `no-dns`, nor hide behind `platform-dns`),
/// unless another server already gives a failing verdict (answered, resolves
/// or open: it stands, and the note names the exit code). A probe that asked
/// nothing is an error too.
pub fn verdict_dns_path(resolv_ns: Option<&str>, replies: &[DnsReply]) -> std::result::Result<(String, String), String> {
    if replies.iter().all(|r| r.rc.is_none()) {
        return Err("no DNS server was asked".into());
    }
    let mut servers: Vec<(String, Vec<String>, DnsClass)> = Vec::new();
    // The first dig that proved nothing (an exit code other than 0 and 9): the error, unless the verdict fails anyway.
    let mut unproven: Option<String> = None;
    for r in replies {
        let (class, said) = match r.rc {
            None => continue,
            Some(0) => {
                let class = if !is_platform_resolver(&r.server) {
                    DnsClass::Open
                } else if r.resolves {
                    DnsClass::Resolves
                } else if !is_empty_noerror(r.status.as_deref(), r.answers, r.authority) {
                    DnsClass::Answered
                } else {
                    DnsClass::Empty
                };
                let detail: Vec<String> = [
                    r.status.as_deref().map(|s| (if s == DNS_NO_EXAMPLE { DNS_NO_EXAMPLE_SAID } else { s }).to_string()),
                    r.answers.map(|n| format!("answer {n}")),
                    r.authority.map(|n| format!("authority {n}")),
                    r.ra.map(|a| (if a { "recursion available" } else { "no recursion" }).to_string()),
                ]
                .into_iter()
                .flatten()
                .collect();
                let what = if r.resolves { "resolved" } else { "replied" };
                (class, if detail.is_empty() { what.to_string() } else { format!("{what} ({})", detail.join(", ")) })
            }
            // A truncated UDP reply whose TCP retry failed (dig exit 9 with a status): the UDP path answered — open for
            // a server that is not the platform's; for a platform resolver a reply other than the empty NOERROR tested
            // (answered, as the check's judge fails it).
            Some(9) if r.status.is_some() => {
                let class = if is_platform_resolver(&r.server) { DnsClass::Answered } else { DnsClass::Open };
                (class, "replied (truncated; the TCP retry got nothing)".to_string())
            }
            Some(9) => (DnsClass::Silent, "no reply".to_string()),
            Some(rc) => {
                unproven.get_or_insert_with(|| format!("dig exited {rc} asking {} over {}: no verdict (is dig in the image?)", r.server, r.transport));
                (DnsClass::Silent, format!("dig exited {rc}"))
            }
        };
        let part = format!("{} {said}", r.transport);
        match servers.iter_mut().find(|(s, _, _)| *s == r.server) {
            Some((_, parts, worst)) => {
                parts.push(part);
                *worst = (*worst).max(class);
            }
            None => servers.push((r.server.clone(), vec![part], class)),
        }
    }
    let resolves = replies.iter().any(|r| r.rc == Some(0) && r.resolves);
    let worst = servers.iter().map(|(_, _, c)| *c).max().unwrap_or(DnsClass::Silent);
    // A dig that proved nothing may only stand beside a failing verdict: `no-dns` or `platform-dns` would claim what
    // that server was never shown to do.
    if let Some(e) = unproven.filter(|_| worst < DnsClass::Answered) {
        return Err(e);
    }
    let of = |class: DnsClass| servers.iter().filter(|(_, _, c)| *c == class).map(|(s, _, _)| s.as_str()).collect::<Vec<_>>().join(",");
    let verdict = match worst {
        DnsClass::Open => format!("{DNS_OPEN_PREFIX}{}", of(worst)),
        DnsClass::Resolves => format!("{DNS_PLATFORM_RESOLVES_PREFIX}{}", of(worst)),
        DnsClass::Answered => format!("{DNS_PLATFORM_ANSWERED_PREFIX}{}", of(worst)),
        DnsClass::Empty => format!("{}{}", crate::bridge::egress::DNS_PLATFORM_PREFIX, of(worst)),
        DnsClass::Silent => crate::bridge::egress::DNS_NONE.to_string(),
    };
    let asked = servers.iter().map(|(s, parts, _)| format!("{s} {}", parts.join(", "))).collect::<Vec<_>>().join("; ");
    Ok((verdict, format!("resolves={} resolv.conf nameserver {}; {asked}", if resolves { "yes" } else { "no" }, resolv_ns.unwrap_or("none"))))
}

/// An AWS error code: `Validation…Exception`-shaped (a capital first, then
/// letters and digits, ending in `Exception`, `Error` or `Fault`).
fn is_error_code(s: &str) -> bool {
    s.len() <= 64 && s.starts_with(|c: char| c.is_ascii_uppercase()) && s.bytes().all(|c| c.is_ascii_alphanumeric()) && ["Exception", "Error", "Fault"].iter().any(|t| s.ends_with(t))
}

/// connector-pending, refused: `rejected:<Code>` with the error code of
/// RunMicrovm's refusal — `ValidationException` or `ConflictException` for
/// those error classes, or the `Code:` an SDK error's message starts with —
/// else `rejected:unknown`; the note is the error text (at most 300
/// characters). `None` for a failure that is no verdict on the connector:
/// throttling, a quota, an access denial (the runtime policy), missing
/// credentials, an ambiguous call — the caller reports it and records
/// nothing.
#[must_use]
pub fn verdict_connector_rejected(e: &crate::bridge::errors::BridgeError) -> Option<(String, String)> {
    use crate::bridge::errors::BridgeError;
    let code = match e {
        BridgeError::Throttled(_) | BridgeError::Quota(_) | BridgeError::AccessDenied(_) | BridgeError::CredentialsUnavailable(_) | BridgeError::Ambiguous { .. } => return None,
        BridgeError::Validation(_) => Some("ValidationException".to_string()),
        BridgeError::Conflict(_) => Some("ConflictException".to_string()),
        BridgeError::Sdk { message, .. } => message.split_once(':').map(|(c, _)| c.trim()).filter(|c| is_error_code(c)).map(str::to_string),
        _ => None,
    };
    let text: String = e.to_string().chars().take(300).collect();
    Some((format!("rejected:{}", code.as_deref().unwrap_or("unknown")), format!("RunMicrovm refused the connector: {text}")))
}

// ---- S6: the agent-transport verdict renderers (pure; `vm/lab.rs` feeds them) --------------

/// e0's exact verdict `<header> <http version> <no-token> <other-port>
/// <proxy-port>` — `101 HTTP/1.1 403 403 403` when the header token upgraded
/// (`accepted`: a 101 the client took, so the WebSocket opened) and the three
/// mis-scoped tokens were each refused 403. A 101 the client refused (a
/// `Connection` other than `Upgrade`, a bad `Sec-WebSocket-Accept`, an
/// unrequested subprotocol) is `101-refused`, which never matches. The
/// version is the client's parse of the endpoint's answer, always `HTTP/1.1`
/// (tungstenite refuses HTTP/1.0); the shim's own view of it is the `http=`
/// field of its `agent upgrade` log line. The note (built in the probe)
/// carries the refusal, the subprotocol form, the bearer through the endpoint
/// and the 9th socket.
#[must_use]
pub fn verdict_e0(header_status: u16, accepted: bool, http_version: &str, no_token: u16, other_port: u16, proxy_port: u16) -> String {
    let header = if header_status == 101 && !accepted { "101-refused".to_string() } else { header_status.to_string() };
    format!("{header} {http_version} {no_token} {other_port} {proxy_port}")
}

/// e1: `survives` when the open socket outlived its endpoint token (the
/// shim's pongs kept arriving past the expiry), else `cut-at-expiry:<s>`
/// (the socket closed or failed) or `silent-at-expiry:<s>` (it stayed open,
/// but nothing came back from its last frame on), in whole seconds after
/// expiry; at or before expiry is `0`. A cut outranks a silence.
#[must_use]
pub fn verdict_e1(cut_after_expiry_s: Option<i64>, silent_after_expiry_s: Option<i64>) -> String {
    match (cut_after_expiry_s, silent_after_expiry_s) {
        (Some(s), _) => format!("cut-at-expiry:{}", s.max(0)),
        (None, Some(s)) => format!("silent-at-expiry:{}", s.max(0)),
        (None, None) => "survives".to_string(),
    }
}

/// `kept` (the VM was RUNNING after the phase) or `suspended` (the service
/// suspended it), for one e5 phase.
#[must_use]
pub fn phase_outcome(kept: bool) -> &'static str {
    if kept {
        "kept"
    } else {
        "suspended"
    }
}

/// e5's recorded verdict: whether a VM with max idle 60 s stayed RUNNING under
/// a silent socket, app pings only, VM→Mac output only, and a bearer-less
/// `GET /health` every 30 s.
#[must_use]
pub fn verdict_e5(silent: bool, pings: bool, outbound: bool, http: bool) -> String {
    format!("silent:{} pings:{} outbound:{} http:{}", phase_outcome(silent), phase_outcome(pings), phase_outcome(outbound), phase_outcome(http))
}

/// frames: `byte-identical` when stdout equalled stdin, else
/// `differs:<first offset>` (the first byte that differs, or the shorter
/// length when one is a prefix of the other). MB/s goes in the note.
#[must_use]
pub fn verdict_frames(input: &[u8], output: &[u8]) -> String {
    if input == output {
        return "byte-identical".to_string();
    }
    let offset = input.iter().zip(output).position(|(a, b)| a != b).unwrap_or_else(|| input.len().min(output.len()));
    format!("differs:{offset}")
}

/// reattach: `no-loss-same-pid` when a client-side cut mid-stream lost and
/// doubled no line, the pid was unchanged and the producer ran to its end
/// (exit code 0, no signal: a cut that killed it — the D22 ladder applied to
/// a lost socket, critic H1 — never passes); else every problem joined
/// (`lost:<n>`, `doubled:<n>`, `pid-changed`, `signal:<n>` or `exit:<code>`,
/// `exit:?` when the shim reported neither). The stale-from_seq gap, the
/// full-window kill replay and the reattach ms go in the note.
#[must_use]
pub fn verdict_reattach(missing: u64, doubled: u64, same_pid: bool, exit_code: Option<i32>, signal: Option<i32>) -> String {
    let mut problems = Vec::new();
    if missing > 0 {
        problems.push(format!("lost:{missing}"));
    }
    if doubled > 0 {
        problems.push(format!("doubled:{doubled}"));
    }
    if !same_pid {
        problems.push("pid-changed".to_string());
    }
    match (exit_code, signal) {
        (Some(0), None) => {}
        (_, Some(s)) => problems.push(format!("signal:{s}")),
        (Some(c), None) => problems.push(format!("exit:{c}")),
        (None, None) => problems.push("exit:?".to_string()),
    }
    if problems.is_empty() {
        "no-loss-same-pid".to_string()
    } else {
        problems.join(" ")
    }
}

/// The guest-vs-Mac clock offset within which `clock-after-resume` passes.
pub const CLOCK_TOLERANCE_S: f64 = 2.0;

/// clock-after-resume: `within-2s` when the guest clock after a long suspend
/// is within [`CLOCK_TOLERANCE_S`] of the Mac's (round-trip corrected), else
/// `offset:<s>` (signed seconds, the guest minus the Mac). The monotonic and
/// boottime deltas and the time to the first proxied success go in the note.
#[must_use]
pub fn verdict_clock(offset_s: f64) -> String {
    if offset_s.abs() <= CLOCK_TOLERANCE_S {
        "within-2s".to_string()
    } else {
        format!("offset:{offset_s:.3}")
    }
}

/// in-vm-firewall: `guarded` when nothing on the DEFAULT VM let the agent uid
/// through and every required check ran, else `exposed:<port>` for the lowest
/// exposed port, else `gap:<names>` when a required check could not run.
/// `exposures` holds the port of every default-VM check that did not hold: a
/// forged hook that was not refused (or drained the VM: the firewall spawn
/// ended with `hook_terminate` while the VM is RUNNING) → 9000; uid 1000's
/// `GET /health` or `GET /health/detail` on 8080, or its request on 9418,
/// that the guard did not refuse — or, under tree B's fallback (`agent_guard`
/// `log` or `off`, where only the bearer holds), that the bearer did not
/// refuse, `GET /health` answering the public summary being no exposure
/// there — → that port; an RST-aborted `GET /health` through the VM's own
/// address that the guard did not refuse (its 8080 refusal count rose by
/// less than two per connection; not judged under the fallback, which
/// counts nothing) → 8080; and every foreign listener a uid-1000 connect
/// reached where it listens → its port. `gaps` names a required measurement
/// that was skipped — `vm-address` when the VM's own IPv4 was not found, so
/// the via-own-address checks (critic M6a: a guard that caches locality at
/// start) never ran; `listeners` when the inventory could not be read whole
/// or a foreign listener was not dialed where it listens (a wildcard without
/// the VM's own address, an IPv6 link-local one); `rst-abort` when the RST
/// abort did not run, made no connection, or the guard's refusal count could
/// not be read: that must not read as a clean pass. An exposure outranks a gap (it is the worse
/// finding). The `--shell` VM's own listeners (8022) are recorded in the
/// note, never an exposure of the default VM.
#[must_use]
pub fn verdict_in_vm_firewall(exposures: &[u16], gaps: &[&str]) -> String {
    if let Some(port) = exposures.iter().copied().min() {
        return format!("exposed:{port}");
    }
    if !gaps.is_empty() {
        return format!("gap:{}", gaps.join(","));
    }
    "guarded".to_string()
}

// ---- S7: the credential probes' verdict renderers (pure; `vm/lab.rs` and `vm/lab_mac.rs` feed them) ----

/// What fd-delivery's second spawn read while claude ran with the token on
/// fd 3 (v6 T7.3: "a second exec scans every claude environ").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeEnviron {
    /// Claude's own environment was among those read (or one read held the
    /// token anyway); this many entries, over all of them, held the token's
    /// name or a value of its kind.
    Read(u64),
    /// Claude's own environment was not read (the scan failed, or claude had
    /// already exited): a gap, never a pass.
    Unread,
    /// Not judged: there is no `/proc` where the shim runs, which only a
    /// test's emulated platform has (its shim runs on a Mac), never a VM.
    NotJudged,
}

/// fd-delivery's verdict (T7.3), from the scan spawn (`in_environ`: its
/// environ entries with the token's name or a value of its kind, `None` when
/// its output held no such count; `fd_bytes`: what fd 3 held), whether
/// claude answered with the fd alone (`via_fd`) and, only when it did not,
/// with the token in its environment (`via_env`), what was read of the
/// environments while claude ran with the fd, and `has_credentials` after a
/// suspend and a resume. A
/// custody failure outranks how claude took the token: `kept-after-resume`
/// (D3: the VM still held it), then the scan's own `fd-unread:<why>` (the
/// shim's side), then `claude-environ:<n>` (fd delivery, yet n entries held
/// it while claude ran). A scan whose environ count could not be read
/// leaves the shim's side unknown, whatever fd 3 held, so claude's answers
/// cannot be judged against it: then `gap:fd-scan` (with any other check
/// that could not be read) — run it again, never a shim bug's
/// `fd-unread:fd-3-was-empty`. Then `env-only` or
/// `fd-unread:claude-answered-neither-way`; and `fd-honoured` only with
/// every custody check read, else `gap:<checks>` (`fd-scan`,
/// `claude-environ`, `has-credentials`): a check that could not be read is
/// no pass.
#[must_use]
pub fn verdict_fd_delivery(in_environ: Option<u64>, fd_bytes: Option<u64>, via_fd: bool, via_env: Option<bool>, environ: ClaudeEnviron, after_resume: Option<bool>) -> String {
    if after_resume == Some(true) {
        return "kept-after-resume".to_string();
    }
    match in_environ {
        Some(n) if n > 0 => return "fd-unread:the-token-was-in-the-environ".to_string(),
        Some(_) if !fd_bytes.is_some_and(|b| b > 0) => return "fd-unread:fd-3-was-empty".to_string(),
        _ => {}
    }
    if let ClaudeEnviron::Read(n) = environ {
        if n > 0 {
            return format!("claude-environ:{n}");
        }
    }
    let gaps: Vec<&str> = [(in_environ.is_none(), "fd-scan"), (environ == ClaudeEnviron::Unread, "claude-environ"), (after_resume.is_none(), "has-credentials")].into_iter().filter(|(gap, _)| *gap).map(|(_, name)| name).collect();
    if in_environ.is_none() {
        return format!("gap:{}", gaps.join(","));
    }
    match (via_fd, via_env) {
        (false, Some(true)) => return "env-only".to_string(),
        (false, _) => return "fd-unread:claude-answered-neither-way".to_string(),
        (true, _) => {}
    }
    if gaps.is_empty() {
        "fd-honoured".to_string()
    } else {
        format!("gap:{}", gaps.join(","))
    }
}

/// touchid-gui's verdict once the terminal unseal answered: `prompted` when
/// the detached one (S8's prewarm shape) answered too, else `terminal-only`,
/// which never passes (tree B).
#[must_use]
pub fn verdict_touchid_gui(detached_ok: bool) -> &'static str {
    if detached_ok {
        "prompted"
    } else {
        "terminal-only"
    }
}

/// A credentialed claude's init budgets (plan S7): cold, the token's unseal
/// then RunMicrovm to the answer to `initialize`; warm, on a VM that holds the token.
pub const INIT_COLD_BUDGET_MS: u128 = 30_000;
pub const INIT_WARM_BUDGET_MS: u128 = 5_000;
/// S10 F9: init-wrapper's budget for a session whose VM was resumed
/// (`vm_how:resumed`): the warm path plus the VM's resume, which S8 and S9
/// measured at 5.5 to 6.5 s in all (their Touch ID 2.3 to 2.9 s of it).
pub const INIT_RESUMED_BUDGET_MS: u128 = 8_000;

/// The budget init-wrapper judges a warm row by (S10 F9): on a resumed VM
/// [`INIT_RESUMED_BUDGET_MS`], on a reused one [`INIT_WARM_BUDGET_MS`].
#[must_use]
pub fn warm_budget_ms(vm_how: &str) -> u128 {
    if vm_how == "resumed" {
        INIT_RESUMED_BUDGET_MS
    } else {
        INIT_WARM_BUDGET_MS
    }
}

/// init-budget's verdict on the times to claude's `initialize` answer:
/// `over:<cold|warm|cold,warm>` past [`INIT_COLD_BUDGET_MS`] or
/// [`INIT_WARM_BUDGET_MS`] (a budget met exactly passes), else `gap:unseal`
/// when the cold figure is unknown (`None`: the combined unseal's time could
/// not be read, so the cold path's Touch ID could not be counted), else
/// `within-budget`.
#[must_use]
pub fn verdict_init_budget(cold_ms: Option<u128>, warm_ms: u128) -> String {
    let over: Vec<&str> = [(cold_ms.is_some_and(|c| c > INIT_COLD_BUDGET_MS), "cold"), (warm_ms > INIT_WARM_BUDGET_MS, "warm")].into_iter().filter(|(o, _)| *o).map(|(_, n)| n).collect();
    if !over.is_empty() {
        return format!("over:{}", over.join(","));
    }
    if cold_ms.is_none() {
        return "gap:unseal".to_string();
    }
    "within-budget".to_string()
}

// ---- `ai-env lab list|show` ---------------------------------------------------------------

/// `ai-env lab list [--json]`: every probe with its last recorded verdict.
pub fn cmd_list(json: bool) -> Result<()> {
    let paths = crate::bridge::config::Paths::resolve()?;
    let mut rows = Vec::new();
    for p in &CATALOG {
        let last = last_row(&paths.probes(), p.name)?;
        let field = |k: &str| last.as_ref().and_then(|r| r.get(k)).and_then(|v| v.as_str()).map(str::to_string);
        rows.push(serde_json::json!({
            "probe": p.name, "stage": p.stage, "source": p.source.name(), "expected": p.expect.expectation().render(),
            "last_verdict": field("verdict"), "last_ts": field("ts"), "recorded_by": p.recorded_by, "what": p.what,
        }));
    }
    if json {
        outln!("{}", serde_json::to_string_pretty(&rows).map_err(|e| CliError::Msg(e.to_string()))?);
        return Ok(());
    }
    for r in &rows {
        let s = |k: &str| r[k].as_str().unwrap_or("-").to_string();
        outln!("{:<22} {:<3} {:<9} {:<28} last {:<28} {}", s("probe"), s("stage"), s("source"), s("expected"), s("last_verdict"), s("recorded_by"));
    }
    Ok(())
}

/// `ai-env lab show PROBE [--json]`: the recorded rows of one probe, oldest first.
pub fn cmd_show(probe: &str, json: bool) -> Result<()> {
    if spec(probe).is_none() {
        return Err(CliError::Usage(format!("unknown probe {probe:?} (ai-env lab list)")));
    }
    let paths = crate::bridge::config::Paths::resolve()?;
    let rows: Vec<serde_json::Value> = read_rows(&paths.probes(), None)?.into_iter().filter(|r| r.get("probe").and_then(|p| p.as_str()) == Some(probe)).collect();
    if json {
        outln!("{}", serde_json::to_string_pretty(&rows).map_err(|e| CliError::Msg(e.to_string()))?);
    } else if rows.is_empty() {
        outln!("no rows recorded for {probe}");
    } else {
        for r in &rows {
            let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("-").to_string();
            outln!("{}  {}={}  (expected {})  {}", s("ts"), probe, s("verdict"), s("expected"), s("note"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expectations_render_and_hold() {
        let exact = Expectation::Exact("9000".into());
        let any = Expectation::AnyOf(vec!["hidden".into(), "absent".into()]);
        assert_eq!(exact.render(), "9000");
        assert_eq!(any.render(), "any-of:hidden|absent");
        assert_eq!(Expectation::Recorded.render(), "recorded");
        assert!(expectation_holds("9000", "9000"));
        assert!(!expectation_holds("9000", "8080"));
        assert!(expectation_holds("any-of:hidden|absent", "absent"));
        assert!(!expectation_holds("any-of:hidden|absent", "present"));
        assert!(expectation_holds("recorded", "anything at all"));
    }

    #[test]
    fn s1_rows_keep_their_shape_and_old_rows_parse() {
        let row = ProbeRow::new("entrypoint", "S1", "claude-vscode", &Expectation::Exact("claude-vscode".into()));
        let text = serde_json::to_string(&row).unwrap();
        for absent in ["image_version", "shim", "claude", "note"] {
            assert!(!text.contains(&format!("\"{absent}\":")), "{absent} must be omitted when unset: {text}");
        }
        let old = r#"{"probe":"entrypoint","stage":"S1","ext":"2.1.282","sdk":null,"verdict":"claude-vscode","expected":"claude-vscode","ts":"2026-09-23T10:00:00Z"}"#;
        let back: ProbeRow = serde_json::from_str(old).unwrap();
        assert_eq!(back.note, None);
        assert_eq!(back.ext.as_deref(), Some("2.1.282"));
    }

    /// The catalog's names are unique, its S4–S6 probes are the planned ones,
    /// and each S7 probe has its planned source and exact expectation: a
    /// loosened one (fd-delivery taking env-only, touchid-gui taking
    /// terminal-only, init-budget taking an over) fails here.
    #[test]
    fn catalog_names_are_unique_and_cover_the_nine_s4_two_s5_seven_s6_and_five_s7_probes() {
        let names: std::collections::BTreeSet<&str> = CATALOG.iter().map(|p| p.name).collect();
        assert_eq!(names.len(), CATALOG.len());
        assert_eq!(CATALOG.iter().filter(|p| p.stage == "S4").count(), 9);
        assert_eq!(CATALOG.iter().filter(|p| p.stage == "S5").map(|p| p.name).collect::<Vec<_>>(), ["connector-pending", "dns-path"]);
        assert_eq!(CATALOG.iter().filter(|p| p.stage == "S6").map(|p| p.name).collect::<Vec<_>>(), ["e0", "e1", "e5", "frames", "reattach", "clock-after-resume", "in-vm-firewall"]);
        assert_eq!(spec("dns-path").unwrap().expect.expectation().render(), crate::bridge::egress::DNS_NONE);
        assert_eq!(spec("cloudtrail-payload").unwrap().expect.expectation().render(), "any-of:not-logged|hidden|absent|commitment-only");
        let s7: Vec<(&str, Source, String)> = CATALOG.iter().filter(|p| p.stage == "S7").map(|p| (p.name, p.source, p.expect.expectation().render())).collect();
        assert_eq!(
            s7,
            [
                ("fd-delivery", Source::Live, "fd-honoured".to_string()),
                ("oauth-t1", Source::Mac, "recorded".to_string()),
                ("setup-token-prefix", Source::Mac, "recorded".to_string()),
                ("touchid-gui", Source::Mac, "prompted".to_string()),
                ("init-budget", Source::Live, "within-budget".to_string()),
            ]
        );
    }

    /// The four S8 probes (plan L8): their source, recorder and exact
    /// expectation. The dup probes are what Cursor showed (by hand, `--manual`
    /// only), init-wrapper comes from the census, fresh-claude-json is live.
    #[test]
    fn the_four_s8_probes_have_their_source_recorder_and_expectation() {
        let s8: Vec<(&str, Source, String, &str)> = CATALOG.iter().filter(|p| p.stage == "S8").map(|p| (p.name, p.source, p.expect.expectation().render(), p.recorded_by)).collect();
        assert_eq!(
            s8,
            [
                ("dup-init", Source::Cursor, "no-duplicate".to_string(), "ai-env lab run dup-init --manual VERDICT (after a resume in Cursor)"),
                ("dup-user-replay", Source::Cursor, "no-duplicate".to_string(), "ai-env lab run dup-user-replay --manual VERDICT (after a resume in Cursor)"),
                ("fresh-claude-json", Source::Live, "no-stall".to_string(), "ai-env lab run fresh-claude-json"),
                ("init-wrapper", Source::Census, "within-budget".to_string(), "ai-env wrapper census --record-probes"),
            ]
        );
        assert_eq!(CATALOG.len(), 33, "S1/S3 3, S4 9, S5 2, S6 7, S7 5, S8 4, S9 2, S10 1");
        assert_eq!(Source::Cursor.name(), "cursor");
    }

    /// S9's two probes (plan L6): live, `lab run`'s own, measured by
    /// ai-env's clients; `protocol-v2` expects exactly `v2`, `chunked-put`
    /// records what it saw.
    #[test]
    fn the_two_s9_probes_have_their_source_recorder_and_expectation() {
        let s9: Vec<(&str, Source, String, &str)> = CATALOG.iter().filter(|p| p.stage == "S9").map(|p| (p.name, p.source, p.expect.expectation().render(), p.recorded_by)).collect();
        assert_eq!(s9, [("protocol-v2", Source::Live, "v2".to_string(), "ai-env lab run protocol-v2"), ("chunked-put", Source::Live, "recorded".to_string(), "ai-env lab run chunked-put")]);
    }

    /// S10's one probe (L3): what Cursor showed of the move's note, by hand
    /// only (`--manual`), expecting exactly `shown`.
    #[test]
    fn the_s10_probe_is_the_move_note_cursor_shows() {
        let s10: Vec<(&str, Source, String, &str)> = CATALOG.iter().filter(|p| p.stage == "S10").map(|p| (p.name, p.source, p.expect.expectation().render(), p.recorded_by)).collect();
        assert_eq!(s10, [("move-note", Source::Cursor, "shown".to_string(), "ai-env lab run move-note --manual VERDICT (after a move in Cursor)")]);
    }

    /// S12 (V3, plans/s12-contracts.md §V3.1): both OAuth texts say what 2.1.310's extension does: its Agent SDK
    /// sets CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH only for a host that passes a getOAuthToken callback, which its own
    /// chats never do (the phrase, not the word: stock-ext-oauth's note already names the callback); oauth-t1's no
    /// longer says the extension never sets it or that Tier B is S12's, and names 2.1.310's reviewed timers
    /// (LD-V13). Text only: the expectations stay `recorded` and `absent`.
    #[test]
    fn the_oauth_texts_say_the_sdk_sets_the_refresh_only_for_a_get_oauth_token_host() {
        let phrase = "only for a host that passes a getOAuthToken callback";
        let (t1, stock) = (spec("oauth-t1").unwrap(), spec("stock-ext-oauth").unwrap());
        for s in [t1, stock] {
            assert!(s.what.contains(phrase), "{}: {}", s.name, s.what);
        }
        assert!(t1.what.contains("2.1.310's own chats never do") && t1.what.contains("Tier B would"), "{}", t1.what);
        assert!(!t1.what.contains("never sets") && !t1.what.contains("Tier B (S12)"), "{}", t1.what);
        assert!(t1.what.contains("AUTH_TIMERS_REVIEWED 2.1.310's too (S11 part B)"), "{}", t1.what);
        assert_eq!((t1.expect.expectation().render(), stock.expect.expectation().render()), ("recorded".to_string(), "absent".to_string()));
    }

    /// A session id of the picker's shape, built at run time.
    fn sid(n: u32) -> String {
        format!("{n:08x}-0000-4000-8000-{:012x}", u64::from(n) << 20)
    }

    /// The census rows of one piped session: its start row (the wrapper and
    /// the bundled claude, then `args`; `mode` its mode note), and its end
    /// row (the pump's clone with `end`, `exit` and `tail` after the note)
    /// unless `tail` is `None`.
    fn session(pid: u32, start: u64, mode: &str, args: &[&str], tail: Option<&str>, exit: i32) -> Vec<serde_json::Value> {
        let mut argv = vec!["/Users/mike/.cargo/bin/ai-env-claude", "/Users/mike/.cursor/extensions/anthropic.claude-code-2.1.296-darwin-arm64/resources/native-binary/claude"];
        argv.extend_from_slice(args);
        let row = serde_json::json!({
            "v": 1, "ts": format!("2026-10-13T10:{:02}:00Z", start % 60), "start": start, "pid": pid, "ppid": 700, "ext": "2.1.296", "route": "remote", "reason": "session",
            "argv": argv, "cwd": "/Users/mike/Documents/DeFi/ai-env", "env_names": ["CLAUDE_CODE_ENTRYPOINT", "HOME"],
            "env_selected": {"CLAUDE_CODE_ENTRYPOINT": "claude-vscode", "CLAUDE_AGENT_SDK_VERSION": "0.3.296"}, "note": mode,
        });
        let mut out = vec![row.clone()];
        if let Some(tail) = tail {
            let mut end = row;
            end["end"] = serde_json::json!(start + 9_000);
            end["exit"] = serde_json::json!(exit);
            end["note"] = serde_json::json!(format!("{mode}; {tail}"));
            out.push(end);
        }
        out
    }

    /// A remote end row's tail: answered `init_ms` (when given) on a VM had `how`, with a Touch ID leg of `touchid` ms.
    fn remote_tail(init_ms: Option<u64>, how: &str, touchid: u64) -> String {
        let init = init_ms.map_or_else(String::new, |ms| format!("; init_ms:{ms}"));
        format!(
            "end:eof; child_pid:-; respawns:0; mirror:2/0; dropped:0; oauth_refresh_answered:0{init}; credential:combined; vm:microvm-{how}; vm_how:{how}; spawn:s1; vm_pid:41; claude:2.1.296; legs:touchid={touchid},select=900,workspace=700,gate=200,spawn=600; seed:seeded; fetch:0/0; close_ms:540; link_drops:0; auth_timers:match; pid_rewrite:ok"
        )
    }

    /// init-wrapper (plan L8): nothing until a remote end row exists; then
    /// the newest cold row (vm_how:started) against 30 s and the newest warm
    /// one against its VM's budget (reused 5 s, resumed 8 s since S10 F9),
    /// each named with its Touch ID leg
    /// in the note; local sessions, start rows, pinned VMs and starts that
    /// never answered are not judged (the unanswered are counted); a
    /// missing kind is a gap, an over wins over a gap, a budget met exactly
    /// passes; `ext`, `sdk` and `claude` are the newest judged row's.
    #[test]
    fn init_wrapper_is_derived_from_the_newest_cold_and_warm_rows() {
        let mut rows = session(10, 1, "mode:local-child", &[], Some("end:eof; child_pid:12; respawns:0; init_ms:900"), 0);
        rows.extend(session(11, 2, "mode:remote", &[], None, 0));
        assert_eq!(init_wrapper_verdict(&rows), None, "a local session and a remote start row are no remote end row");
        rows.extend(session(12, 3, "mode:remote", &[], Some(&remote_tail(None, "started", 1800)), 8));
        let only_failed = init_wrapper_verdict(&rows).expect("a remote end row exists");
        assert_eq!(only_failed.verdict, "gap:cold,warm");
        assert!(only_failed.note.as_deref().unwrap().ends_with("; 1 remote end row(s) never answered initialize (not judged)"), "{only_failed:?}");
        rows.extend(session(13, 4, "mode:remote(config)", &[], Some(&remote_tail(Some(21_000), "started", 2600)), 0));
        let cold_only = init_wrapper_verdict(&rows).unwrap();
        assert_eq!(cold_only.verdict, "gap:warm");
        assert!(cold_only.note.as_deref().unwrap().starts_with("cold 21000 ms (touchid 2600 ms; vm_how:started; legs touchid=2600,select=900,workspace=700,gate=200,spawn=600; microvm-started at 2026-10-13T10:04:00Z); no warm row yet"), "{cold_only:?}");
        rows.extend(session(14, 5, "mode:remote", &[], Some(&remote_tail(Some(4_100), "reused", 1500)), 0));
        rows.extend(session(15, 6, "mode:remote", &[], Some(&remote_tail(Some(60_000), "pinned", 1500)), 0));
        let row = init_wrapper_verdict(&rows).unwrap();
        assert_eq!((row.probe.as_str(), row.stage.as_str(), row.verdict.as_str(), row.expected.as_str()), ("init-wrapper", "S8", "within-budget", "within-budget"));
        let note = row.note.clone().unwrap();
        assert!(note.contains("; warm 4100 ms (touchid 1500 ms; vm_how:reused; legs touchid=1500,"), "{note}");
        assert!(note.contains("; budgets 30000 ms cold, 5000 ms reused and 8000 ms resumed, from the census start to the forwarded answer; 1 remote end row(s) never answered"), "{note}");
        assert!(!note.contains("pinned"), "a pinned VM's row is not judged: {note}");
        assert_eq!((row.ext.as_deref(), row.sdk.as_deref(), row.claude.as_deref()), (Some("2.1.296"), Some("0.3.296"), Some("2.1.296")));
        // The newest of each kind is judged: a newer warm row on a resumed VM over its own budget (S10 F9: 8 s).
        rows.extend(session(16, 7, "mode:remote", &[], Some(&remote_tail(Some(8_001), "resumed", 1500)), 0));
        assert_eq!(init_wrapper_verdict(&rows).unwrap().verdict, "over:warm");
        rows.extend(session(17, 8, "mode:remote", &[], Some(&remote_tail(Some(30_001), "started", 1500)), 0));
        assert_eq!(init_wrapper_verdict(&rows).unwrap().verdict, "over:cold,warm");
        rows.extend(session(18, 9, "mode:remote", &[], Some(&remote_tail(Some(30_000), "started", 1500)), 0));
        rows.extend(session(19, 10, "mode:remote", &[], Some(&remote_tail(Some(5_000), "reused", 1500)), 0));
        assert_eq!(init_wrapper_verdict(&rows).unwrap().verdict, "within-budget", "budgets met exactly pass");
    }

    #[test]
    fn the_init_wrapper_verdict_names_what_is_over_or_missing() {
        assert_eq!(verdict_init_wrapper(Some(29_000), Some((4_000, "reused"))), "within-budget");
        assert_eq!(verdict_init_wrapper(Some(31_000), None), "over:cold", "an over wins over a gap");
        assert_eq!(verdict_init_wrapper(None, Some((6_000, "reused"))), "over:warm");
        assert_eq!(verdict_init_wrapper(None, Some((4_000, "resumed"))), "gap:cold");
        assert_eq!(verdict_init_wrapper(Some(1), None), "gap:warm");
        assert_eq!(verdict_init_wrapper(None, None), "gap:cold,warm");
        for v in ["within-budget", "over:cold", "gap:warm"] {
            assert_eq!(expectation_holds(&spec("init-wrapper").unwrap().expect.expectation().render(), v), v == "within-budget", "{v}");
        }
    }

    /// The dup probes' census evidence (T8.5): the newest end row of a
    /// remote session that resumed (`--resume`), answered initialize and
    /// found its VM without the transcript (uploaded; S9's restored or
    /// staged; or the resume miss's seed retry); without one the refusal
    /// names what the newest remote resume lacks, or that there is none. An
    /// end row is its start row's by pid and start, never by pid alone.
    #[test]
    fn a_dup_probe_needs_the_census_evidence_of_a_remote_resume_into_a_vm_without_its_transcript() {
        let (a, b) = (sid(0x8a01), sid(0x8a02));
        let resume_a = format!("--resume={a}");
        let none = resume_evidence(&[]).unwrap_err();
        assert!(none.starts_with("no remote resume in the census; the dup probes need a census end row of a remote session (mode:remote) that resumed a conversation (--resume)"), "{none}");
        // A local resume and a remote chat without --resume are no remote resume.
        let mut rows = session(20, 1, "mode:local-child", &["--resume", &a], Some("end:eof; child_pid:3; respawns:0; init_ms:400"), 0);
        rows.extend(session(21, 2, "mode:remote", &["--output-format", "stream-json"], Some(&remote_tail(Some(4_000), "reused", 900)), 0));
        assert!(resume_evidence(&rows).unwrap_err().starts_with("no remote resume in the census"));
        // Still open: no end row.
        rows.extend(session(22, 3, "mode:remote", &[resume_a.as_str()], None, 0));
        let open = resume_evidence(&rows).unwrap_err();
        assert!(open.starts_with(&format!("the newest remote resume (session {a}, started 2026-10-13T10:03:00Z) has no census end row yet: close the chat")), "{open}");
        // Ended without an answer, though its transcript went up before the spawn failed: Cursor never showed it.
        rows.extend(session(23, 4, "mode:remote", &["--resume", &a], Some(&format!("{}; transcript:uploaded", remote_tail(None, "started", 900).replace("end:eof", "end:spawn_failed"))), 8));
        let failed = resume_evidence(&rows).unwrap_err();
        assert!(failed.contains("never answered initialize (end:spawn_failed, exit 8)"), "{failed}");
        // Answered on the VM that held the transcript (T8.4's same-VM resume).
        rows.extend(session(24, 5, "mode:remote", &["--resume", &a], Some(&format!("{}; transcript:already_there", remote_tail(Some(3_000), "reused", 900))), 0));
        let held = resume_evidence(&rows).unwrap_err();
        assert!(held.contains("found its VM holding the transcript (transcript:already_there, respawns:0): the dup probes judge a resume into a VM without it"), "{held}");
        // T8.5: the upload before the spawn into a new VM.
        rows.extend(session(25, 6, "mode:remote(config)", &[resume_a.as_str()], Some(&format!("{}; transcript:uploaded", remote_tail(Some(9_000), "started", 900))), 0));
        let evidence = resume_evidence(&rows).unwrap();
        assert_eq!(evidence, format!("census: session {a} resumed in remote mode at 2026-10-13T10:06:00Z (wrapper pid 25) on microvm-started (vm_how:started): transcript:uploaded, respawns:0, init_ms:9000, end:eof, exit 0"));
        // A newer resume that held its transcript does not hide it; the forced replay (the miss's retry) is newer still.
        rows.extend(session(26, 7, "mode:remote", &["--resume", &b], Some(&format!("{}; transcript:already_there", remote_tail(Some(3_000), "reused", 900))), 0));
        assert_eq!(resume_evidence(&rows).unwrap(), evidence);
        let mut forced = session(27, 8, "mode:remote", &["--resume", &b], Some(&format!("{}; transcript:uploaded", remote_tail(Some(7_000), "reused", 900).replace("respawns:0", "respawns:1"))), 0);
        for r in &mut forced {
            r["env_names"] = serde_json::json!(["AI_ENV_BRIDGE_LAB_TRANSCRIPT", "HOME"]);
            r["env_selected"]["AI_ENV_BRIDGE_LAB_TRANSCRIPT"] = serde_json::json!("skip");
        }
        rows.extend(forced);
        let replay = resume_evidence(&rows).unwrap();
        assert!(replay.starts_with(&format!("census: session {b} resumed in remote mode")) && replay.contains("respawns:1") && replay.ends_with("exit 0 (AI_ENV_BRIDGE_LAB_TRANSCRIPT was set: the forced replay)"), "{replay}");
        // Only the miss's retry, the transcript word missing: still a resume into a VM without it.
        let retry = session(28, 9, "mode:remote", &["--resume", &b], Some(&remote_tail(Some(7_000), "reused", 900).replace("respawns:0", "respawns:2")), 0);
        assert!(resume_evidence(&retry).unwrap().contains("respawns:2"));
        // S9: a restore from S3 into the new VM is the same evidence; a VM that kept the committed prefix is not.
        let restored = session(31, 12, "mode:remote", &["--resume", &b], Some(&format!("{}; transcript:restored", remote_tail(Some(8_000), "started", 900))), 0);
        assert_eq!(resume_evidence(&restored).unwrap(), format!("census: session {b} resumed in remote mode at 2026-10-13T10:12:00Z (wrapper pid 31) on microvm-started (vm_how:started): transcript:restored, respawns:0, init_ms:8000, end:eof, exit 0"));
        let kept = session(32, 13, "mode:remote", &["--resume", &b], Some(&format!("{}; transcript:kept", remote_tail(Some(3_000), "reused", 900))), 0);
        assert!(resume_evidence(&kept).unwrap_err().contains("found its VM holding the transcript (transcript:kept, respawns:0)"));
        // A chat S3 did not hold yet (begun on this Mac, an S8 mirror), sent up at the reopen and pulled into the new VM.
        let staged = session(33, 14, "mode:remote", &["--resume", &b], Some(&format!("{}; transcript:staged", remote_tail(Some(8_500), "started", 900))), 0);
        assert_eq!(resume_evidence(&staged).unwrap(), format!("census: session {b} resumed in remote mode at 2026-10-13T10:14:00Z (wrapper pid 33) on microvm-started (vm_how:started): transcript:staged, respawns:0, init_ms:8500, end:eof, exit 0"));
        // A --resume that is no uuid is no resume of a conversation.
        let odd = session(29, 10, "mode:remote", &["--resume", "../x"], Some(&format!("{}; transcript:uploaded", remote_tail(Some(7_000), "started", 900))), 0);
        assert!(resume_evidence(&odd).unwrap_err().starts_with("no remote resume in the census"));
        // Pids recycle: a later session of the open resume's pid (no resume, an end row that would qualify) is not its end.
        let mut recycled = session(50, 1, "mode:remote", &["--resume", &a], None, 0);
        recycled.extend(session(50, 2, "mode:remote", &["--output-format", "stream-json"], Some(&format!("{}; transcript:uploaded", remote_tail(Some(4_000), "started", 900))), 0));
        let open = resume_evidence(&recycled).unwrap_err();
        assert!(open.starts_with(&format!("the newest remote resume (session {a}, started 2026-10-13T10:01:00Z) has no census end row yet")), "{open}");
    }

    /// S8 phase 4 (RESUME-5): the evidence names the forced replay only when
    /// it happened: the census recorded `AI_ENV_BRIDGE_LAB_TRANSCRIPT=skip`
    /// (only `skip` forces the miss, in a debug wrapper) and the end row
    /// shows the retry. The knob with another value, or `skip` with no
    /// retry (a release wrapper ignores it), forces nothing.
    #[test]
    fn the_dup_evidence_names_the_forced_replay_only_for_skip_with_a_retry() {
        let id = sid(0x8b01);
        for (value, respawns, named) in [("0", 0, false), ("", 0, false), ("skip", 0, false), ("1", 1, false), ("skip", 1, true)] {
            let tail = format!("{}; transcript:uploaded", remote_tail(Some(9_000), "started", 900).replace("respawns:0", &format!("respawns:{respawns}")));
            let mut rows = session(30, 1, "mode:remote", &["--resume", &id], Some(&tail), 0);
            for r in &mut rows {
                r["env_names"] = serde_json::json!(["AI_ENV_BRIDGE_LAB_TRANSCRIPT", "HOME"]);
                r["env_selected"]["AI_ENV_BRIDGE_LAB_TRANSCRIPT"] = serde_json::json!(value);
            }
            let evidence = resume_evidence(&rows).unwrap();
            assert_eq!(evidence.ends_with("exit 0 (AI_ENV_BRIDGE_LAB_TRANSCRIPT was set: the forced replay)"), named, "{value:?} with respawns:{respawns}: {evidence}");
            assert!(evidence.contains(&format!("respawns:{respawns}")), "{evidence}");
        }
    }

    #[test]
    fn a_dup_verdict_is_no_duplicate_or_names_what_was_shown_twice() {
        assert_eq!(check_dup_verdict("dup-init", "no-duplicate"), Ok(()));
        assert_eq!(check_dup_verdict("dup-init", "duplicate:two init bubbles"), Ok(()));
        for bad in ["duplicate:", "duplicate: ", "ok", "no-duplicates", "Duplicate:x"] {
            let e = check_dup_verdict("dup-user-replay", bad).unwrap_err();
            assert!(e.starts_with("dup-user-replay: the verdict is no-duplicate, or duplicate:<what Cursor showed twice>"), "{bad}: {e}");
        }
    }

    #[test]
    fn the_fresh_claude_json_verdict_names_the_step_that_stalled() {
        assert_eq!(verdict_fresh_claude_json(true, Some(true)), "no-stall");
        assert_eq!(verdict_fresh_claude_json(false, None), "stall:initialize");
        assert_eq!(verdict_fresh_claude_json(true, None), "stall:turn");
        assert_eq!(verdict_fresh_claude_json(true, Some(false)), "stall:turn-error");
        let expected = spec("fresh-claude-json").unwrap().expect.expectation().render();
        assert!(expectation_holds(&expected, "no-stall") && !expectation_holds(&expected, "stall:turn"));
    }

    #[test]
    fn hook_lines_parse_the_shim_format_behind_a_timestamp() {
        let log = "2026-09-29T10:21:08 ai-env: hook ready peer=127.0.0.1:1 local=127.0.0.1:9000 origin=loopback len=- status=200 ms=1\n\
                   2026-09-29T10:21:09 ai-env: hook run peer=127.0.0.1:34567 local=127.0.0.1:9000 origin=loopback len=238 status=200 ms=190\n\
                   noise\n\
                   2026-09-29T10:22:00 ai-env: hook terminate peer=127.0.0.1:40000 local=127.0.0.1:9000 origin=loopback len=- status=200 ms=3\n";
        let lines = parse_hook_lines(log);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], HookLine { hook: "run".into(), peer: Some("127.0.0.1:34567".into()), local: Some("127.0.0.1:9000".into()), origin: Some("loopback".into()), status: Some(200) });
        assert_eq!(lines[2].peer.as_deref(), Some("127.0.0.1:40000"));
        let (port, note) = verdict_hooks_port(&lines).unwrap();
        assert_eq!(port, "9000");
        assert!(note.contains("run×1") && note.contains("terminate×1") && !note.contains("ready"), "{note}");
        assert_eq!(verdict_hooks_source(&lines).unwrap().0, "loopback");
        let mixed = parse_hook_lines("ai-env: hook run peer=10.0.0.9:1 local=10.0.0.5:8080 origin=remote\nai-env: hook resume peer=127.0.0.1:2 local=127.0.0.1:9000 origin=loopback");
        assert_eq!(verdict_hooks_port(&mixed).unwrap().0, "8080,9000");
        assert_eq!(verdict_hooks_source(&mixed).unwrap().0, "loopback,remote");
        assert!(verdict_hooks_port(&parse_hook_lines("ai-env: hook ready local=127.0.0.1:9000")).is_err(), "image hooks do not count");
        assert_eq!(local_port("[::1]:9000"), Some(9000));
    }

    #[test]
    fn run_reports_give_env_disk_and_boot_ids() {
        let secret_value = format!("{}{}", "AKIA", "Q".repeat(16));
        // The shim's shape: `aws_credential_env` at the top level, beside `env`.
        let r1 = serde_json::json!({"hook":"run","microvm_id":"microvm-a","boot_id":"b-1","disk_total_bytes": 8u64<<30, "disk_used_bytes": 300u64<<20,
            "env":{"names":["HOME","PATH"],"values":{"HOME":"/root"}},"aws_credential_env":[],"zombies":0});
        // A buggy shim that leaked a credential VALUE into `values` must not get it into the verdict or the note.
        let r2 = serde_json::json!({"hook":"run","microvm_id":"microvm-b","boot_id":"b-1","disk_total_bytes": 1, "disk_used_bytes": 1,
            "env":{"names":["AWS_ACCESS_KEY_ID"],"values":{"AWS_ACCESS_KEY_ID":secret_value,"HOME":"/root"}},"aws_credential_env":["AWS_ACCESS_KEY_ID"],"zombies":0});
        let unreadable = serde_json::json!({"hook":"run","microvm_id":"microvm-c","boot_id":"b-1","env":null,"aws_credential_env":null});
        assert!(verdict_runtime_env(&[unreadable]).unwrap_err().contains("unreadable"), "null env is never `absent`");
        let log = format!("t ai-env: run-report {r1}\nx\nt ai-env: run-report {{broken\nt ai-env: run-report {r2}\n");
        let reports = parse_run_reports(&log);
        assert_eq!(reports.len(), 2);
        let (v, note) = verdict_runtime_env(&reports).unwrap();
        assert_eq!(v, "aws-credentials:AWS_ACCESS_KEY_ID", "the newest run report");
        assert!(!note.contains(&secret_value) && !v.contains(&secret_value), "{note}");
        assert!(note.contains("HOME=/root"), "{note}");
        assert_eq!(verdict_runtime_env(&reports[..1]).unwrap().0, "aws-credentials:absent");
        assert_eq!(verdict_disk_budget(&reports[..1]).unwrap().0, "used=300MiB total=8192MiB");
        assert_eq!(boot_ids(&reports, &["microvm-a", "microvm-b"]).unwrap().0, "identical");
        assert!(boot_ids(&reports, &["microvm-c"]).is_err());
        assert!(verdict_disk_budget(&[]).unwrap_err().contains("execution_role_arn"));
    }

    #[test]
    fn cloudtrail_verdicts() {
        let token = "s".repeat(64);
        let commit = "c".repeat(64);
        let event = |params: serde_json::Value| {
            let inner = serde_json::json!({"eventName":"RunMicrovm","eventID":"e1","requestParameters":params,"responseElements":{"microvmId":"microvm-a"}});
            serde_json::json!({"Events":[{"CloudTrailEvent": inner.to_string()}]}).to_string()
        };
        let v = |params: serde_json::Value| verdict_cloudtrail(&event(params), "microvm-a", "", Some(&token), &commit).unwrap().unwrap().0;
        assert_eq!(v(serde_json::json!({"imageIdentifier":"x"})), "absent");
        assert_eq!(v(serde_json::json!({"runHookPayload":"HIDDEN_DUE_TO_SECURITY_REASONS"})), "hidden");
        assert_eq!(v(serde_json::json!({"runHookPayload": format!("{{\"commit\":\"{commit}\"}}")})), "commitment-only");
        assert_eq!(v(serde_json::json!({"runHookPayload":"something else"})), "present-other");
        assert_eq!(v(serde_json::json!({"runHookPayload": format!("x{token}")})), "LEAKED");
        assert_eq!(verdict_cloudtrail(&event(serde_json::json!({})), "microvm-other", "", None, &commit).unwrap(), None, "not yet visible");
        assert!(verdict_cloudtrail("{}", "microvm-a", "", None, &commit).is_err());
        let nameless = serde_json::json!({"Records": [{"eventID": "e9", "requestParameters": {}, "responseElements": {"microvmId": "microvm-a"}}]}).to_string();
        assert_eq!(verdict_cloudtrail(&nameless, "microvm-a", "", None, &commit).unwrap(), None, "a record without an event name never stands in for RunMicrovm");
        // A trail's log file: the Records of other calls on the same VM (TerminateMicrovm answers with its
        // microvmId too) must not stand in for RunMicrovm, whose record shape is the AWS docs example.
        let terminate = serde_json::json!({"eventName":"TerminateMicrovm","eventID":"e0","responseElements":{"microvmId":"microvm-a"}});
        let run = serde_json::json!({"eventName":"RunMicrovm","eventID":"e2","requestParameters":{"microvmImageArn":"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent"},
            "responseElements":{"microvmId":"microvm-a","microvmState":"PENDING"},"eventCategory":"Data","managementEvent":false});
        let file = |records: Vec<&serde_json::Value>| serde_json::json!({"Records": records}).to_string();
        assert_eq!(verdict_cloudtrail(&file(vec![&terminate]), "microvm-a", "", None, &commit).unwrap(), None, "only RunMicrovm counts");
        let (v, note) = verdict_cloudtrail(&file(vec![&terminate, &run]), "microvm-a", "", Some(&token), &commit).unwrap().unwrap();
        assert_eq!((v.as_str(), note.as_str()), ("absent", "event e2 (matched by microvmId; CloudTrail record)"));
        assert_eq!(verdict_cloudtrail(&run.to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "absent", "one record");
        assert_eq!(verdict_cloudtrail(&serde_json::json!([run]).to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "absent", "an array");
        let leaked = serde_json::json!({"eventName":"RunMicrovm","responseElements":{"microvmId":"microvm-a"},"requestParameters":{"note":token}});
        assert_eq!(verdict_cloudtrail(&file(vec![&leaked]), "microvm-a", "", Some(&token), &commit).unwrap().unwrap().0, "LEAKED", "anywhere in the record");
    }

    #[test]
    fn microvm_data_event_selectors() {
        let field = |name: &str, op: &str, values: &[&str]| serde_json::json!({"Field": name, op: values});
        let adv = |fields: Vec<serde_json::Value>| serde_json::json!({"AdvancedEventSelectors": [{"Name": "s", "FieldSelectors": fields}]});
        // The AWS docs' selector for MicroVM data events.
        assert!(selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"]), field("resources.type", "Equals", &[MICROVM_DATA_RESOURCE])])));
        assert!(selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"]), field("resources.type", "StartsWith", &["AWS::Lambda::"])])));
        assert!(selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"])])), "an unconstrained type is a maybe: counts as logging");
        assert!(!selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Management"])])), "the default management selector");
        assert!(!selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"]), field("resources.type", "Equals", &["AWS::S3::Object"])])));
        assert!(!selectors_log_microvm_data(&adv(vec![
            field("eventCategory", "Equals", &["Data"]),
            field("resources.type", "Equals", &[MICROVM_DATA_RESOURCE]),
            field("eventName", "NotEquals", &["RunMicrovm"]),
        ])), "RunMicrovm filtered out");
        assert!(!selectors_log_microvm_data(&adv(vec![field("eventCategory", "Equals", &["Data"]), field("resources.type", "Equals", &[MICROVM_DATA_RESOURCE]), field("readOnly", "Equals", &["true"])])));
        let basic = |ty: &str, rw: &str| serde_json::json!({"EventSelectors": [{"ReadWriteType": rw, "IncludeManagementEvents": true, "DataResources": [{"Type": ty, "Values": ["arn:aws:lambda"]}]}]});
        assert!(selectors_log_microvm_data(&basic(MICROVM_DATA_RESOURCE, "All")));
        assert!(!selectors_log_microvm_data(&basic(MICROVM_DATA_RESOURCE, "ReadOnly")));
        assert!(!selectors_log_microvm_data(&basic("AWS::S3::Object", "All")));
        assert!(!selectors_log_microvm_data(&serde_json::json!({"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": true, "DataResources": []}]})), "management events only");
        assert!(!selectors_log_microvm_data(&serde_json::json!({})));
    }

    #[test]
    fn field_selector_operators_follow_cloudtrail() {
        // CloudTrail: SELECT operators (Equals, StartsWith, EndsWith) are OR'd; any DESELECT match excludes.
        let data = |name: serde_json::Value| {
            let mut name = name;
            name["Field"] = serde_json::json!("eventName");
            serde_json::json!({"AdvancedEventSelectors": [{"FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": [MICROVM_DATA_RESOURCE]}, name]}]})
        };
        let on = |name: serde_json::Value| selectors_log_microvm_data(&data(name));
        assert!(on(serde_json::json!({"Equals": ["RunMicrovm"], "StartsWith": ["CreateMicrovm"]})), "OR: Equals matches");
        assert!(on(serde_json::json!({"EndsWith": ["Microvm"], "StartsWith": ["Create"]})), "OR: EndsWith matches");
        assert!(on(serde_json::json!({"Equals": ["TerminateMicrovm"], "StartsWith": ["Run"]})), "OR: StartsWith matches");
        assert!(on(serde_json::json!({"EndsWith": ["Microvm"]})));
        assert!(!on(serde_json::json!({"EndsWith": ["Image"]})));
        assert!(!on(serde_json::json!({"StartsWith": ["Run"], "NotEquals": ["RunMicrovm"]})), "a DESELECT match wins");
        assert!(!on(serde_json::json!({"NotStartsWith": ["Run"]})));
        assert!(on(serde_json::json!({"NotStartsWith": ["Terminate"]})));
        assert!(!on(serde_json::json!({"NotEndsWith": ["Microvm"]})));
        assert!(on(serde_json::json!({"NotEndsWith": ["Image"]})));
        // eventSource: the service RunMicrovm is recorded under.
        let source = |v: &str| {
            selectors_log_microvm_data(&serde_json::json!({"AdvancedEventSelectors": [{"FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": [MICROVM_DATA_RESOURCE]}, {"Field": "eventSource", "Equals": [v]}]}]}))
        };
        assert!(source("lambda.amazonaws.com"));
        assert!(!source("s3.amazonaws.com"));
        // The console's usual pair: a management selector, then the data selector — any selector may log it.
        let pair = serde_json::json!({"AdvancedEventSelectors": [
            {"Name": "Management events", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]},
            {"Name": "MicroVM", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": [MICROVM_DATA_RESOURCE]}]}]});
        assert!(selectors_log_microvm_data(&pair));
    }

    #[test]
    fn cloudtrail_matches_by_client_token_and_exact_markers() {
        let commit = "c".repeat(64);
        // No microvmId in the record: matched by clientToken.
        let by_token = serde_json::json!({"Records": [{"eventName": "RunMicrovm", "eventID": "e3", "requestParameters": {"clientToken": "ct-1", "runHookPayload": format!("{{\"commit\":\"{commit}\"}}")}}]});
        let (v, note) = verdict_cloudtrail(&by_token.to_string(), "microvm-a", "ct-1", None, &commit).unwrap().unwrap();
        assert_eq!((v.as_str(), note.as_str()), ("commitment-only", "event e3 (matched by clientToken; CloudTrail record)"));
        assert_eq!(verdict_cloudtrail(&by_token.to_string(), "microvm-a", "", None, &commit).unwrap(), None, "an empty client token matches nothing");
        // A payload whose owner says "hidden" is logged, not redacted.
        let owner = serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": {"runHookPayload": "{\"owner\":\"hidden@host\"}"}});
        assert_eq!(verdict_cloudtrail(&owner.to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "present-other");
        for marker in ["HIDDEN_DUE_TO_SECURITY_REASONS", "redacted", "****"] {
            let m = serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": {"runHookPayload": marker}});
            assert_eq!(verdict_cloudtrail(&m.to_string(), "microvm-a", "", None, &commit).unwrap().unwrap().0, "hidden", "{marker}");
        }
        // requestParameters itself a marker (CloudTrail's form for sensitive parameters): hidden; any other scalar: refused.
        let whole = |p: serde_json::Value| serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": p}).to_string();
        assert_eq!(verdict_cloudtrail(&whole(serde_json::json!("HIDDEN_DUE_TO_SECURITY_REASONS")), "microvm-a", "", None, &commit).unwrap().unwrap().0, "hidden");
        assert!(verdict_cloudtrail(&whole(serde_json::json!("some text")), "microvm-a", "", None, &commit).is_err());
        assert!(verdict_cloudtrail(&whole(serde_json::json!(42)), "microvm-a", "", None, &commit).is_err());
    }

    #[test]
    fn cloudtrail_reads_cloudwatch_events() {
        let token = "s".repeat(64);
        let commit = "c".repeat(64);
        let payload = format!("{{\"commit\":\"{commit}\"}}");
        // `aws logs filter-log-events --output json`: one message per matching log event.
        let logs = |messages: Vec<String>| {
            let events: Vec<serde_json::Value> = messages.iter().enumerate().map(|(i, m)| serde_json::json!({"logStreamName": "s", "timestamp": 1, "message": m, "eventId": format!("ev{i}")})).collect();
            serde_json::json!({"events": events, "searchedLogStreams": []}).to_string()
        };
        let v = |messages: Vec<String>| verdict_cloudtrail(&logs(messages), "microvm-a", "", Some(&token), &commit);
        let raw = |p: &str| serde_json::json!({"eventName": "RunMicrovm", "eventID": "r1", "requestParameters": {"runHookPayload": p}, "responseElements": {"microvmId": "microvm-a"}}).to_string();
        let ocsf = |op: &str, request: serde_json::Value| serde_json::json!({"class_uid": 6003, "metadata": {"uid": "o1"}, "api": {"operation": op, "request": request, "response": {"data": {"microvmId": "microvm-a"}}}}).to_string();
        let (verdict, note) = v(vec![raw("HIDDEN_DUE_TO_SECURITY_REASONS")]).unwrap().unwrap();
        assert_eq!((verdict.as_str(), note.as_str()), ("hidden", "event r1 (matched by microvmId; CloudWatch Logs, raw)"));
        assert_eq!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": {"microvmImageArn": "x"}}))]).unwrap().unwrap().0, "absent", "OCSF, object data");
        assert_eq!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": {"runHookPayload": "other"}}))]).unwrap().unwrap().0, "present-other");
        let (verdict, note) = v(vec![ocsf("RunMicrovm", serde_json::json!({"data": serde_json::json!({"runHookPayload": payload}).to_string()}))]).unwrap().unwrap();
        assert_eq!((verdict.as_str(), note.as_str()), ("commitment-only", "event o1 (matched by microvmId; CloudWatch Logs, OCSF)"), "OCSF data as a JSON string");
        assert_eq!(v(vec![ocsf("TerminateMicrovm", serde_json::json!({"data": {}}))]).unwrap(), None, "other operations are skipped");
        let leaked = serde_json::json!({"eventName": "RunMicrovm", "responseElements": {"microvmId": "microvm-a"}, "requestParameters": {}, "userAgent": token}).to_string();
        assert_eq!(v(vec![leaked.clone()]).unwrap().unwrap().0, "LEAKED", "anywhere in the message");
        assert_eq!(v(vec![raw(&payload), leaked]).unwrap().unwrap().0, "LEAKED", "a later LEAKED record wins");
        assert!(v(vec![raw(&payload), raw("other")]).unwrap_err().contains("disagree"), "records that disagree are refused");
        assert!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": "{not json"}))]).unwrap_err().contains("api.request.data"));
        assert!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": 7}))]).is_err());
        assert!(v(vec![serde_json::json!({"api": {"operation": "RunMicrovm"}}).to_string()]).unwrap_err().contains("without api.request"));
        assert!(v(vec![ocsf("RunMicrovm", serde_json::json!({"uid": "q"}))]).unwrap_err().contains("without api.request.data"));
        assert!(v(vec!["plain text line".to_string()]).unwrap_err().contains("ev0: the message is not JSON"), "never skipped: the filter output holds only matches");
        assert!(v(vec![serde_json::json!({"hello": 1}).to_string()]).unwrap_err().contains("neither a CloudTrail record"));
        assert!(v(vec![raw("{\"commit\":\"********\"}")]).unwrap_err().contains("--unmask"), "masked text is refused, not called hidden");
        assert!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": {"runHookPayload": "{\"owner\":\"****\"}"}}))]).unwrap_err().contains("--unmask"), "an OCSF record with a 4-star mask too");
        // The token anywhere in the OCSF message, outside what is mapped back: LEAKED.
        let actor = serde_json::json!({"metadata": {"uid": "o2"}, "actor": {"session": token}, "api": {"operation": "RunMicrovm", "request": {"data": {}}, "response": {"data": {"microvmId": "microvm-a"}}}}).to_string();
        assert_eq!(v(vec![actor]).unwrap().unwrap().0, "LEAKED");
        // Optional OCSF shapes: request data that is a redaction marker, and no response (matched by clientToken).
        assert_eq!(v(vec![ocsf("RunMicrovm", serde_json::json!({"data": "HIDDEN_DUE_TO_SECURITY_REASONS"}))]).unwrap().unwrap().0, "hidden");
        let no_response = serde_json::json!({"metadata": {"uid": "o3"}, "api": {"operation": "RunMicrovm", "request": {"data": {"clientToken": "ct-5"}}}}).to_string();
        let (verdict, note) = verdict_cloudtrail(&logs(vec![no_response]), "microvm-a", "ct-5", Some(&token), &commit).unwrap().unwrap();
        assert_eq!((verdict.as_str(), note.as_str()), ("absent", "event o3 (matched by clientToken; CloudWatch Logs, OCSF)"));
        assert_eq!(v(vec![]).unwrap(), None);
    }

    #[test]
    fn channel_cover_cases() {
        let arn = |region: &str, name: &str| format!("arn:aws:cloudtrail:{region}:123456789012:channel/{name}");
        let data_sel = serde_json::json!([{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": [MICROVM_DATA_RESOURCE]}]}]);
        // The live Resource Explorer channel (shape seen 30 Sep 2026): management events only.
        let rex = serde_json::json!({"ChannelArn": arn("eu-central-1", "aws-service-channel/resource-explorer-2"), "Name": "aws-service-channel/resource-explorer-2/AwsResourceExplorerDefault", "Source": "CloudTrail",
            "SourceConfig": {"ApplyToAllRegions": true, "AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}]},
            "Destinations": [{"Type": "AWS_SERVICE", "Location": "resource-explorer-2"}]});
        let c = channel_cover(&rex);
        assert_eq!((c.cover, c.kind.as_str()), (ChannelCover::No, "resource-explorer-2"));
        let cw = serde_json::json!({"ChannelArn": arn("eu-central-1", "cw-1"), "Name": "aws-service-channel/cloudwatch/rule-1", "SourceConfig": {"ApplyToAllRegions": true, "AdvancedEventSelectors": data_sel},
            "Destinations": [{"Type": "AWS_SERVICE", "Location": "cloudwatch"}]});
        let c = channel_cover(&cw);
        assert_eq!((c.cover, c.kind.as_str()), (ChannelCover::Logs, "cloudwatch"));
        assert!(!selectors_log_microvm_data(&cw), "the selectors sit under SourceConfig: the whole document never matches");
        let mut no_source = cw.clone();
        no_source.as_object_mut().unwrap().remove("SourceConfig");
        assert_eq!(channel_cover(&no_source).cover, ChannelCover::Maybe, "unreadable selectors: may log");
        let mut empty = cw.clone();
        empty["SourceConfig"]["AdvancedEventSelectors"] = serde_json::json!([]);
        assert_eq!(channel_cover(&empty).cover, ChannelCover::Maybe);
        let lake = serde_json::json!({"ChannelArn": arn("eu-central-1", "int-1"), "Name": "partner-integration", "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "arn:aws:cloudtrail:eu-central-1:123456789012:eventdatastore/eds-1"}]});
        let c = channel_cover(&lake);
        assert_eq!((c.cover, c.kind.as_str()), (ChannelCover::External, "integration"));
        let mut elsewhere = cw.clone();
        elsewhere["ChannelArn"] = serde_json::json!(arn("us-east-1", "cw-2"));
        elsewhere["SourceConfig"]["ApplyToAllRegions"] = serde_json::json!(false);
        assert_eq!(channel_cover(&elsewhere).cover, ChannelCover::No, "a single-Region channel of another Region");
        elsewhere["SourceConfig"]["ApplyToAllRegions"] = serde_json::json!(true);
        assert_eq!(channel_cover(&elsewhere).cover, ChannelCover::Logs, "an all-Region channel homed elsewhere covers this Region");
        let mut here_only = cw.clone();
        here_only["SourceConfig"]["ApplyToAllRegions"] = serde_json::json!(false);
        assert_eq!(channel_cover(&here_only).cover, ChannelCover::Logs, "a single-Region channel of eu-central-1 covers it");
        // External only for a non-service channel whose destinations are all event data stores.
        let nowhere = serde_json::json!({"ChannelArn": arn("eu-central-1", "n"), "Name": "partner", "Destinations": []});
        assert_eq!(channel_cover(&nowhere).cover, ChannelCover::Maybe, "no destinations: unknown, not External");
        let service_to_store = serde_json::json!({"ChannelArn": arn("eu-central-1", "s"), "Name": "aws-service-channel/cloudwatch/y", "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "arn:aws:cloudtrail:eu-central-1:123456789012:eventdatastore/eds-2"}]});
        assert_ne!(channel_cover(&service_to_store).cover, ChannelCover::External, "a service-linked name is never an integration channel");
        let unnamed_service = serde_json::json!({"ChannelArn": arn("eu-central-1", "x"), "Name": "x", "Destinations": [{"Type": "AWS_SERVICE", "Location": "security-lake"}]});
        let c = channel_cover(&unnamed_service);
        assert_eq!((c.cover, c.kind.as_str()), (ChannelCover::Maybe, "security-lake"));
    }

    #[test]
    fn log_group_arn_cases() {
        let g = |a: &str| log_group_from_arn(a);
        assert_eq!(g("arn:aws:logs:eu-central-1:123456789012:log-group:aws-cloudtrail-logs-1:*"), Some(("eu-central-1".into(), "aws-cloudtrail-logs-1".into())));
        assert_eq!(g("arn:aws:logs:eu-central-1:123456789012:log-group:aws/cloudtrail/data"), Some(("eu-central-1".into(), "aws/cloudtrail/data".into())));
        assert_eq!(g("arn:aws:logs:us-east-1:123456789012:log-group:/aws/ct:*"), Some(("us-east-1".into(), "/aws/ct".into())));
        assert_eq!(g("arn:aws:logs:eu-central-1:123456789012:log-group:bad name'x:*"), None, "a name this probe will not print");
        assert_eq!(g("arn:aws:s3:::bucket"), None);
        assert_eq!(g("garbage"), None);
        assert!(is_safe_log_group_name("aws/cloudtrail/data-events") && !is_safe_log_group_name("") && !is_safe_log_group_name("a'b"));
    }

    fn reply(server: &str, transport: &'static str, rc: Option<i32>, resolves: bool) -> DnsReply {
        DnsReply { server: server.into(), transport, rc, resolves, status: None, ra: None, answers: None, authority: None }
    }

    /// What the platform's stub gave on 2 Oct 2026: NOERROR, no answer, no authority, recursion offered.
    fn empty(server: &str, transport: &'static str) -> DnsReply {
        DnsReply { status: Some("NOERROR".into()), ra: Some(true), answers: Some(0), authority: Some(0), ..reply(server, transport, Some(0), false) }
    }

    #[test]
    fn dns_path_verdicts() {
        let pin = |s: &str| [s.parse::<std::net::IpAddr>().unwrap()];
        let closed = [
            reply("10.42.0.2", "udp", Some(9), false),
            reply("10.42.0.2", "tcp", Some(9), false),
            reply("169.254.169.253", "udp", Some(9), false),
            reply("169.254.169.253", "tcp", Some(9), false),
        ];
        let (v, note) = verdict_dns_path(Some("10.42.0.2"), &closed).unwrap();
        assert_eq!(v, crate::bridge::egress::DNS_NONE);
        assert_eq!(note, "resolves=no resolv.conf nameserver 10.42.0.2; 10.42.0.2 udp no reply, tcp no reply; 169.254.169.253 udp no reply, tcp no reply");
        assert_eq!(spec("dns-path").unwrap().expect.expectation().render(), v, "the expectation");
        // The platform's empty NOERROR: platform-dns, accepted only for a pinned resolver; the counts reach the note.
        let stub = [reply("", "udp", None, false), empty("169.254.169.253", "udp"), reply("10.42.1.2", "udp", Some(9), false)];
        let (v, note) = verdict_dns_path(None, &stub).unwrap();
        assert_eq!(v, "platform-dns:169.254.169.253");
        assert!(note.starts_with("resolves=no resolv.conf nameserver none;") && note.contains("169.254.169.253 udp replied (NOERROR, answer 0, authority 0, recursion available)"), "{note}");
        assert!(crate::bridge::egress::dns_verdict_ok(&v, &pin("169.254.169.253")) && !crate::bridge::egress::dns_verdict_ok(&v, &[]) && !crate::bridge::egress::dns_verdict_ok(&v, &pin("fd00:ec2::253")));
        // Every server of the worst class, in case order: acceptance never depends on which was asked first.
        let three = [empty("169.254.169.253", "udp"), reply("10.42.0.2", "udp", Some(9), false), empty("fd00:ec2::253", "udp"), empty("fd00:ec2::253", "tcp"), empty("10.42.1.2", "tcp")];
        assert_eq!(verdict_dns_path(None, &three).unwrap().0, "platform-dns:169.254.169.253,fd00:ec2::253,10.42.1.2");
        let (v, _) = verdict_dns_path(None, &[empty("fd00:ec2::253", "udp"), empty("10.42.1.2", "udp")]).unwrap();
        assert!(!crate::bridge::egress::dns_verdict_ok(&v, &pin("fd00:ec2::253")), "an unpinned empty reply asked after the pinned one is not hidden: {v}");
        // Anything but an empty NOERROR from a platform resolver is answered, never accepted: an SOA (the black lie of a
        // validating recursor), a record, another status, no status at all, no counts.
        let answered = |r: DnsReply| verdict_dns_path(None, &[r]).unwrap().0;
        let fd = || empty("fd00:ec2::253", "udp");
        for (what, r) in [
            ("authority 1", DnsReply { authority: Some(1), ..fd() }),
            ("answer 1", DnsReply { answers: Some(1), ..fd() }),
            ("NXDOMAIN", DnsReply { status: Some("NXDOMAIN".into()), authority: Some(1), ..fd() }),
            ("SERVFAIL", DnsReply { status: Some("SERVFAIL".into()), ..fd() }),
            ("REFUSED", DnsReply { status: Some("REFUSED".into()), ra: Some(false), ..fd() }),
            ("no status", DnsReply { status: None, ..fd() }),
            ("no counts", DnsReply { answers: None, authority: None, ..fd() }),
            ("no answer count", DnsReply { answers: None, ..fd() }),
            ("no authority count", DnsReply { authority: None, ..fd() }),
            ("nothing printed", reply("fd00:ec2::253", "udp", Some(0), false)),
        ] {
            let v = answered(r);
            assert_eq!(v, "platform-dns-answered:fd00:ec2::253", "{what}");
            assert!(!crate::bridge::egress::dns_verdict_ok(&v, &pin("fd00:ec2::253")), "{what}: never accepted");
        }
        // A server takes its worst reply: empty over UDP, NXDOMAIN over TCP.
        let (v, note) = verdict_dns_path(None, &[empty("fd00:ec2::253", "udp"), DnsReply { status: Some("NXDOMAIN".into()), authority: Some(1), ..empty("fd00:ec2::253", "tcp") }]).unwrap();
        assert_eq!(v, "platform-dns-answered:fd00:ec2::253");
        assert!(note.ends_with("fd00:ec2::253 udp replied (NOERROR, answer 0, authority 0, recursion available), tcp replied (NXDOMAIN, answer 0, authority 1, recursion available)"), "{note}");
        assert_eq!(verdict_dns_path(None, &[DnsReply { status: Some("REFUSED".into()), ..reply("fd00:ec2::253", "tcp", Some(0), false) }]).unwrap().1, "resolves=no resolv.conf nameserver none; fd00:ec2::253 tcp replied (REFUSED)", "counts omitted when absent");
        // A platform resolver that resolves names (its lookups leave): its own verdict, never accepted; resolves=yes when any
        // reply carried an address.
        let leaving = [reply("10.42.0.2", "udp", Some(9), false), empty("169.254.169.253", "udp"), DnsReply { resolves: true, answers: Some(1), ..empty("10.42.1.2", "tcp") }];
        let (v, note) = verdict_dns_path(Some("10.42.0.2"), &leaving).unwrap();
        assert_eq!(v, "platform-dns-resolves:10.42.1.2");
        assert!(note.starts_with("resolves=yes") && note.contains("10.42.1.2 tcp resolved (NOERROR, answer 1, authority 0, recursion available)") && note.contains("169.254.169.253 udp replied"), "{note}");
        assert!(!crate::bridge::egress::dns_verdict_ok(&v, &pin("10.42.1.2")), "never accepted");
        assert!(!expectation_holds("no-dns", &v));
        // Precedence: empty < answered < resolves < open, whatever the case order.
        let answered_r = DnsReply { status: Some("SERVFAIL".into()), ..empty("10.42.0.2", "udp") };
        let resolves_r = DnsReply { resolves: true, ..empty("10.42.1.2", "udp") };
        let open_r = reply("9.9.9.9", "udp", Some(0), false);
        assert_eq!(verdict_dns_path(None, &[answered_r.clone(), empty("fd00:ec2::253", "udp")]).unwrap().0, "platform-dns-answered:10.42.0.2");
        assert_eq!(verdict_dns_path(None, &[empty("fd00:ec2::253", "udp"), answered_r.clone()]).unwrap().0, "platform-dns-answered:10.42.0.2");
        assert_eq!(verdict_dns_path(None, &[resolves_r.clone(), answered_r.clone(), empty("fd00:ec2::253", "udp")]).unwrap().0, "platform-dns-resolves:10.42.1.2");
        assert_eq!(verdict_dns_path(None, &[answered_r.clone(), resolves_r.clone()]).unwrap().0, "platform-dns-resolves:10.42.1.2");
        assert_eq!(verdict_dns_path(None, &[resolves_r.clone(), open_r.clone(), answered_r.clone()]).unwrap().0, "open-dns:9.9.9.9", "open DNS is worse");
        assert_eq!(verdict_dns_path(None, &[open_r, resolves_r]).unwrap().0, "open-dns:9.9.9.9");
        // A resolver that is not the platform's (public, a local stub) replying is open DNS, whatever else replied.
        for (ns, server) in [("1.1.1.1", "1.1.1.1"), ("10.42.0.2", "9.9.9.9"), ("127.0.0.53", "127.0.0.53")] {
            let open = [empty("169.254.169.253", "udp"), empty(server, "udp"), reply("10.42.1.2", "tcp", Some(9), false)];
            let (v, note) = verdict_dns_path(Some(ns), &open).unwrap();
            assert_eq!(v, format!("open-dns:{server}"), "{note}");
            assert!(!crate::bridge::egress::dns_verdict_ok(&v, &pin(server)), "never accepted");
            assert!(expectation_holds(&spec("dns-path").unwrap().expect.expectation().render(), "no-dns") && !expectation_holds("no-dns", &v));
        }
        assert_eq!(verdict_dns_path(None, &[empty("fd00:ec2::253", "udp")]).unwrap().0, "platform-dns:fd00:ec2::253");
        assert_eq!(verdict_dns_path(None, &[DnsReply { resolves: true, ..empty("fd00:ec2::253", "udp") }]).unwrap().0, "platform-dns-resolves:fd00:ec2::253");
        assert_eq!(verdict_dns_path(None, &[reply("2606:4700:4700::1111", "tcp", Some(0), false)]).unwrap().0, "open-dns:2606:4700:4700::1111");
        assert_eq!(verdict_dns_path(None, &[empty("1.1.1.1", "udp"), empty("9.9.9.9", "tcp")]).unwrap().0, "open-dns:1.1.1.1,9.9.9.9");
        // The address class only, never the acceptance: no pin is consulted.
        for platform in ["10.42.0.2", "10.42.1.2", "169.254.169.253", "fd00:ec2::253", "172.16.0.2", "192.168.0.2"] {
            assert!(is_platform_resolver(platform), "{platform}");
        }
        for public in ["1.1.1.1", "9.9.9.9", "208.67.222.222", "127.0.0.53", "2606:4700:4700::1111", "::1", "100.64.0.2", "resolver", ""] {
            assert!(!is_platform_resolver(public), "{public}");
        }
        // Nothing proven: a dig that did not run (127: not in the image) or failed, or nothing asked.
        assert!(verdict_dns_path(None, &[reply("169.254.169.253", "udp", Some(127), false)]).unwrap_err().contains("exited 127"));
        assert!(verdict_dns_path(None, &[reply("169.254.169.253", "udp", Some(10), false)]).is_err());
        assert!(verdict_dns_path(None, &[reply("", "udp", None, false)]).is_err());
        // A dig that proved nothing never lets a verdict that could pass stand (no-dns, or an empty reply elsewhere)…
        let silent = |server: &str, transport: &'static str| reply(server, transport, Some(9), false);
        assert!(verdict_dns_path(None, &[silent("10.42.0.2", "udp"), silent("fd00:ec2::253", "udp"), reply("10.42.1.2", "tcp", Some(10), false)]).unwrap_err().contains("dig exited 10 asking 10.42.1.2 over tcp"));
        assert!(verdict_dns_path(None, &[empty("fd00:ec2::253", "udp"), reply("10.42.1.2", "udp", Some(10), false)]).unwrap_err().contains("dig exited 10"), "never platform-dns beside an unproven server");
        // …but cannot hide a failing one: an answered, resolving or open server is a definite verdict, and the note says
        // what the other dig did.
        let (v, note) = verdict_dns_path(None, &[reply("10.42.0.2", "udp", Some(127), false), DnsReply { status: Some("SERVFAIL".into()), ..empty("fd00:ec2::253", "udp") }]).unwrap();
        assert!(v == "platform-dns-answered:fd00:ec2::253" && note.contains("10.42.0.2 udp dig exited 127"), "{v}: {note}");
        assert_eq!(verdict_dns_path(None, &[empty("1.1.1.1", "udp"), reply("10.42.0.2", "udp", Some(10), false)]).unwrap().0, "open-dns:1.1.1.1");
        assert_eq!(verdict_dns_path(None, &[reply("10.42.0.2", "udp", Some(10), false), DnsReply { resolves: true, ..empty("10.42.1.2", "udp") }]).unwrap().0, "platform-dns-resolves:10.42.1.2");
        // A truncated UDP reply whose TCP retry got nothing (dig exit 9 with a status): never "no reply" — open for a
        // public resolver, answered for a platform one (the reply tested is the empty NOERROR, never a truncated one).
        let truncated = |server: &str| DnsReply { status: Some("TRUNCATED".into()), ..reply(server, "udp", Some(9), false) };
        let (v, note) = verdict_dns_path(None, &[truncated("1.1.1.1")]).unwrap();
        assert!(v == "open-dns:1.1.1.1" && note.contains("1.1.1.1 udp replied (truncated; the TCP retry got nothing)"), "{v}: {note}");
        let (v, note) = verdict_dns_path(None, &[truncated("fd00:ec2::253")]).unwrap();
        assert!(v == "platform-dns-answered:fd00:ec2::253" && note.contains("fd00:ec2::253 udp replied (truncated; the TCP retry got nothing)"), "{v}: {note}");
        assert!(!crate::bridge::egress::dns_verdict_ok(&v, &pin("fd00:ec2::253")), "never accepted");
        assert_eq!(verdict_dns_path(None, &[empty("1.1.1.1", "udp"), truncated("fd00:ec2::253")]).unwrap().0, "open-dns:1.1.1.1", "open DNS is still worse");
        assert_eq!(verdict_dns_path(None, &[empty("fd00:ec2::253", "tcp"), truncated("fd00:ec2::253")]).unwrap().0, "platform-dns-answered:fd00:ec2::253", "its worst reply");
        // The fresh name answered, example.com not at all (`st=NOEXAMPLE`): answered, and the note says so in words.
        let (v, note) = verdict_dns_path(None, &[DnsReply { status: Some(DNS_NO_EXAMPLE.into()), ..empty("fd00:ec2::253", "udp") }]).unwrap();
        assert!(v == "platform-dns-answered:fd00:ec2::253" && note.ends_with("fd00:ec2::253 udp replied (example.com A unanswered, answer 0, authority 0, recursion available)"), "{v}: {note}");
        assert!(verdict_dns_path(None, &[]).is_err());
        // Only NOERROR, 0, 0.
        assert!(is_empty_noerror(Some("NOERROR"), Some(0), Some(0)));
        for (st, an, au) in [(Some("NOERROR"), Some(0), Some(1)), (Some("NOERROR"), Some(1), Some(0)), (Some("NXDOMAIN"), Some(0), Some(0)), (None, Some(0), Some(0)), (Some("NOERROR"), None, Some(0)), (Some("NOERROR"), Some(0), None), (Some("noerror"), Some(0), Some(0)), (Some(DNS_NO_EXAMPLE), Some(0), Some(0))] {
            assert!(!is_empty_noerror(st, an, au), "{st:?} {an:?} {au:?}");
        }
    }

    #[test]
    fn connector_pending_rejections_name_the_code() {
        use crate::bridge::errors::BridgeError;
        let msg = "Network connector arn:aws:lambda:eu-central-1:123456789012:network-connector:probe is not ACTIVE";
        let (v, note) = verdict_connector_rejected(&BridgeError::Validation(msg.into())).unwrap();
        assert_eq!(v, "rejected:ValidationException");
        assert!(note.starts_with("RunMicrovm refused the connector: aws validation: Network connector") && note.contains("is not ACTIVE"), "{note}");
        for (e, code) in [
            (BridgeError::Conflict("x".into()), "ConflictException"),
            (BridgeError::Sdk { op: "run_microvm", message: "ResourceNotFoundException: Network connector x not found".into() }, "ResourceNotFoundException"),
            (BridgeError::Sdk { op: "run_microvm", message: "InvalidParameterValueError: x".into() }, "InvalidParameterValueError"),
        ] {
            assert_eq!(verdict_connector_rejected(&e).unwrap().0, format!("rejected:{code}"), "{e}");
        }
        // No code in the text: unknown, the message kept in the note.
        for message in ["the connector is pending", "timeout: no answer", "lowercaseException: x", ""] {
            let (v, note) = verdict_connector_rejected(&BridgeError::Sdk { op: "run_microvm", message: message.into() }).unwrap();
            assert_eq!(v, "rejected:unknown", "{message:?}");
            assert!(note.contains(message), "{note}");
        }
        assert_eq!(verdict_connector_rejected(&BridgeError::Endpoint("x".into())).unwrap().0, "rejected:unknown");
        let long = verdict_connector_rejected(&BridgeError::Validation("y".repeat(1000))).unwrap().1;
        assert!(long.chars().count() <= 300 + "RunMicrovm refused the connector: ".len(), "{}", long.len());
        // Throttling, a quota, the runtime policy, credentials, an ambiguous call: no verdict on the connector.
        for e in [
            BridgeError::Throttled("Rate exceeded".into()),
            BridgeError::Quota("Max allocated ARM_64 MicroVM memory".into()),
            BridgeError::AccessDenied("run_microvm: not authorized to perform lambda:PassNetworkConnector".into()),
            BridgeError::CredentialsUnavailable("expired".into()),
            BridgeError::Ambiguous { op: "run_microvm", message: "timeout".into() },
        ] {
            assert!(verdict_connector_rejected(&e).is_none(), "{e}");
        }
    }

    #[test]
    fn s6_verdict_renderers() {
        // e0: the exact string the catalog pins, and the failing shapes.
        assert_eq!(verdict_e0(101, true, "HTTP/1.1", 403, 403, 403), "101 HTTP/1.1 403 403 403");
        assert_eq!(spec("e0").unwrap().expect.expectation().render(), verdict_e0(101, true, "HTTP/1.1", 403, 403, 403));
        assert_eq!(verdict_e0(101, true, "HTTP/2.0", 403, 403, 403), "101 HTTP/2.0 403 403 403", "the version the client parsed is built in");
        assert_ne!(verdict_e0(403, false, "HTTP/1.1", 403, 403, 403), "101 HTTP/1.1 403 403 403", "a refused header token fails");
        // A 101 the client refused opened no WebSocket: never the catalog's pass.
        let refused = verdict_e0(101, false, "HTTP/1.1", 403, 403, 403);
        assert_eq!(refused, "101-refused HTTP/1.1 403 403 403");
        assert!(!expectation_holds(&spec("e0").unwrap().expect.expectation().render(), &refused), "{refused}");
        // e1: survives only with pongs past the expiry; a cut outranks a silence.
        assert_eq!(verdict_e1(None, None), "survives");
        assert_eq!(verdict_e1(Some(12), None), "cut-at-expiry:12");
        assert_eq!(verdict_e1(Some(-3), None), "cut-at-expiry:0", "a cut at or before expiry is 0");
        assert_eq!(verdict_e1(None, Some(4)), "silent-at-expiry:4");
        assert_eq!(verdict_e1(None, Some(-20)), "silent-at-expiry:0", "silent from before the expiry on is 0");
        assert_eq!(verdict_e1(Some(30), Some(0)), "cut-at-expiry:30");
        // e5: recorded, four phases.
        assert_eq!(verdict_e5(true, true, true, true), "silent:kept pings:kept outbound:kept http:kept");
        assert_eq!(verdict_e5(false, true, false, true), "silent:suspended pings:kept outbound:suspended http:kept");
        assert!(expectation_holds(&spec("e5").unwrap().expect.expectation().render(), &verdict_e5(false, false, false, true)), "e5 records any phase mix");
        // frames.
        assert_eq!(verdict_frames(b"abc", b"abc"), "byte-identical");
        assert_eq!(verdict_frames(&[0u8, 0xff, 0x01], &[0u8, 0xff, 0x02]), "differs:2");
        assert_eq!(verdict_frames(b"abcd", b"abc"), "differs:3", "a prefix differs at the shorter length");
        assert_eq!(verdict_frames(b"", b""), "byte-identical");
        assert_eq!(spec("frames").unwrap().expect.expectation().render(), "byte-identical");
        // reattach: the pass needs the producer to have run to its end.
        assert_eq!(verdict_reattach(0, 0, true, Some(0), None), "no-loss-same-pid");
        assert_eq!(verdict_reattach(2, 0, true, Some(0), None), "lost:2");
        assert_eq!(verdict_reattach(0, 1, false, Some(0), None), "doubled:1 pid-changed");
        assert_eq!(verdict_reattach(3, 4, false, Some(0), None), "lost:3 doubled:4 pid-changed");
        // A cut that killed it (critic H1: the D22 ladder on a lost socket) never passes, whatever the lines say.
        assert_eq!(verdict_reattach(0, 0, true, None, Some(15)), "signal:15");
        assert_eq!(verdict_reattach(5, 0, true, None, Some(9)), "lost:5 signal:9");
        assert_eq!(verdict_reattach(0, 0, true, Some(143), None), "exit:143");
        assert_eq!(verdict_reattach(0, 0, true, None, None), "exit:?");
        assert_eq!(spec("reattach").unwrap().expect.expectation().render(), "no-loss-same-pid");
        // clock: AnyOf within-2s, ±2 s inclusive.
        assert_eq!(verdict_clock(0.0), "within-2s");
        assert_eq!(verdict_clock(-2.0), "within-2s");
        assert_eq!(verdict_clock(1.999), "within-2s");
        assert_eq!(verdict_clock(2.5), "offset:2.500");
        assert_eq!(verdict_clock(-9.25), "offset:-9.250");
        assert!(expectation_holds(&spec("clock-after-resume").unwrap().expect.expectation().render(), &verdict_clock(0.5)));
        assert!(!expectation_holds(&spec("clock-after-resume").unwrap().expect.expectation().render(), &verdict_clock(3.0)));
        // in-vm-firewall: guarded with nothing exposed, else the lowest port.
        assert_eq!(verdict_in_vm_firewall(&[], &[]), "guarded");
        assert_eq!(verdict_in_vm_firewall(&[9418, 9000, 8080], &[]), "exposed:8080", "the lowest exposed port");
        assert_eq!(verdict_in_vm_firewall(&[8022], &[]), "exposed:8022");
        // A skipped required check (the VM's own IPv4 was not found) is a gap, not a clean pass.
        assert_eq!(verdict_in_vm_firewall(&[], &["vm-address"]), "gap:vm-address");
        assert_eq!(verdict_in_vm_firewall(&[8080], &["vm-address"]), "exposed:8080", "an exposure outranks a gap");
        assert!(!expectation_holds(&spec("in-vm-firewall").unwrap().expect.expectation().render(), &verdict_in_vm_firewall(&[], &["vm-address"])), "a gap does not satisfy the guarded expectation");
        assert_eq!(spec("in-vm-firewall").unwrap().expect.expectation().render(), "guarded");
        assert_eq!(phase_outcome(true), "kept");
        assert_eq!(phase_outcome(false), "suspended");
    }

    /// The S7 verdicts against the catalog: fd-delivery passes only when fd 3
    /// carried the token alone, claude answered with it, and every custody
    /// check was read clean (a cache kept across a suspend and a resume, a
    /// token in an environment while claude ran, or a check that could not be
    /// read never passes, and neither does env-only; a scan whose environ
    /// count could not be read is `gap:fd-scan`, to run again, not a shim
    /// bug's `fd-unread:fd-3-was-empty`, whatever fd 3 held); touchid-gui's
    /// terminal-only never passes; init-budget's thresholds are 30 s and 5 s,
    /// met exactly passes, and an unread cold figure is a gap.
    #[test]
    fn s7_verdict_renderers() {
        let holds = |probe: &str, verdict: &str| expectation_holds(&spec(probe).unwrap().expect.expectation().render(), verdict);
        let fd = |in_environ, fd_bytes, via_fd, via_env, environ, after| verdict_fd_delivery(in_environ, fd_bytes, via_fd, via_env, environ, after);
        let (clean, unread, here) = (ClaudeEnviron::Read(0), ClaudeEnviron::Unread, ClaudeEnviron::NotJudged);
        assert_eq!(fd(Some(0), Some(108), true, None, clean, Some(false)), "fd-honoured");
        assert!(holds("fd-delivery", "fd-honoured"));
        assert_eq!(fd(Some(0), Some(108), true, None, here, Some(false)), "fd-honoured", "not judged where there is no /proc (the emulated platform only)");
        let env_only = fd(Some(0), Some(108), false, Some(true), clean, Some(false));
        assert_eq!(env_only, "env-only");
        assert!(!holds("fd-delivery", &env_only), "env-only is never a pass");
        assert_eq!(fd(Some(0), Some(108), false, Some(false), clean, Some(false)), "fd-unread:claude-answered-neither-way");
        assert_eq!(fd(Some(0), Some(108), false, None, clean, Some(false)), "fd-unread:claude-answered-neither-way", "env not tried");
        assert_eq!(fd(Some(1), None, true, None, clean, Some(false)), "fd-unread:the-token-was-in-the-environ");
        assert_eq!(fd(Some(0), Some(0), true, None, clean, Some(false)), "fd-unread:fd-3-was-empty");
        assert_eq!(fd(Some(0), None, true, None, clean, Some(false)), "fd-unread:fd-3-was-empty", "the environ read, no byte count: fd 3 was not open");
        // The scan's environ count unread: the shim's side unknown, a gap to run again (never a shim bug's fd-3-was-empty).
        assert_eq!(fd(None, None, true, None, clean, Some(false)), "gap:fd-scan", "a scan that printed nothing");
        assert_eq!(fd(None, Some(108), true, None, clean, Some(false)), "gap:fd-scan", "though fd 3 held bytes");
        assert!(!holds("fd-delivery", "gap:fd-scan"));
        assert_eq!(fd(None, Some(108), false, Some(true), clean, Some(false)), "gap:fd-scan", "claude's answers are not judged against an unknown shim side: never env-only");
        assert_eq!(fd(None, Some(108), false, Some(false), clean, Some(false)), "gap:fd-scan", "nor neither-way");
        assert_eq!(fd(None, Some(108), true, None, unread, None), "gap:fd-scan,claude-environ,has-credentials");
        assert_eq!(fd(None, Some(108), true, None, ClaudeEnviron::Read(1), Some(false)), "claude-environ:1", "a custody failure outranks the gap");
        assert_eq!(fd(None, None, true, None, clean, Some(true)), "kept-after-resume");
        // D3 and the environments: custody failures outrank how claude took the token.
        let kept = fd(Some(0), Some(108), true, None, clean, Some(true));
        assert_eq!(kept, "kept-after-resume");
        assert!(!holds("fd-delivery", &kept), "a cache kept across a suspend and a resume is no pass");
        assert_eq!(fd(Some(1), None, false, Some(true), ClaudeEnviron::Read(2), Some(true)), "kept-after-resume", "it outranks everything");
        let held = fd(Some(0), Some(108), true, None, ClaudeEnviron::Read(2), Some(false));
        assert_eq!(held, "claude-environ:2");
        assert!(!holds("fd-delivery", &held), "a token in an environment while claude ran on the fd is no pass");
        assert_eq!(fd(Some(0), Some(108), false, Some(true), ClaudeEnviron::Read(1), Some(false)), "claude-environ:1", "it outranks env-only");
        assert_eq!(fd(Some(1), None, true, None, ClaudeEnviron::Read(1), Some(false)), "fd-unread:the-token-was-in-the-environ", "the shim's own side is named first");
        // A custody check that could not be read: a gap, never fd-honoured.
        assert_eq!(fd(Some(0), Some(108), true, None, clean, None), "gap:has-credentials");
        assert_eq!(fd(Some(0), Some(108), true, None, unread, Some(false)), "gap:claude-environ");
        let gaps = fd(Some(0), Some(108), true, None, unread, None);
        assert_eq!(gaps, "gap:claude-environ,has-credentials");
        assert!(!holds("fd-delivery", &gaps));
        assert_eq!(fd(Some(0), Some(108), false, Some(true), unread, None), "env-only", "a gap matters only to a pass");
        // touchid-gui.
        assert_eq!(verdict_touchid_gui(true), "prompted");
        assert!(holds("touchid-gui", verdict_touchid_gui(true)));
        assert_eq!(verdict_touchid_gui(false), "terminal-only");
        assert!(!holds("touchid-gui", verdict_touchid_gui(false)), "terminal-only is never prompted");
        // init-budget.
        assert_eq!((INIT_COLD_BUDGET_MS, INIT_WARM_BUDGET_MS), (30_000, 5_000));
        assert_eq!(verdict_init_budget(Some(30_000), 5_000), "within-budget", "a budget met exactly passes");
        assert!(holds("init-budget", &verdict_init_budget(Some(30_000), 5_000)));
        assert_eq!(verdict_init_budget(Some(30_001), 5_000), "over:cold");
        assert_eq!(verdict_init_budget(Some(30_000), 5_001), "over:warm");
        assert_eq!(verdict_init_budget(Some(30_001), 5_001), "over:cold,warm");
        assert!(!holds("init-budget", &verdict_init_budget(Some(1_000), 5_001)));
        assert_eq!(verdict_init_budget(None, 4_000), "gap:unseal");
        assert!(!holds("init-budget", "gap:unseal"));
        assert_eq!(verdict_init_budget(None, 5_001), "over:warm", "a known over outranks the gap");
    }

    /// A Mac probe's row (S7) carries nothing of the image, which it never
    /// measured; a live probe's row still starts from the recorded image.
    #[test]
    fn a_mac_probes_row_carries_nothing_of_the_image() {
        let d = tempfile::tempdir().unwrap();
        let paths = crate::bridge::config::Paths::from_root_and_env(d.path().to_path_buf(), None);
        std::fs::create_dir_all(paths.infra_state().parent().unwrap()).unwrap();
        std::fs::write(paths.infra_state(), "latest_active_image_version = \"6.0\"\nclaude_version = \"2.1.288\"\n").unwrap();
        for probe in ["oauth-t1", "touchid-gui", "setup-token-prefix"] {
            let row = stamped(&paths, spec(probe).unwrap(), "v", Some("n".into()));
            assert_eq!((row.claude, row.ext, row.image_version, row.note.as_deref()), (None, None, None, Some("n")), "{probe}");
        }
        let live = stamped(&paths, spec("fd-delivery").unwrap(), "v", None);
        assert_eq!((live.claude.as_deref(), live.image_version.as_deref()), (Some("2.1.288"), Some("6.0")));
    }

    #[test]
    fn append_writes_one_line_per_row_and_reports_the_expectation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lab").join("probes.jsonl");
        let mut row = ProbeRow::new("hooks-port", "S4", "9000", &Expectation::Exact("9000".into()));
        row.note = Some("from logs".into());
        assert!(append_row(&path, &row).unwrap());
        row.verdict = "8080".into();
        assert!(!append_row(&path, &row).unwrap(), "a verdict that misses the expectation is reported, still written");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert_eq!(last_row(&path, "hooks-port").unwrap().unwrap()["verdict"], "8080");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod n_tests {
    use super::*;

    /// A session id of the picker's shape, built at run time.
    fn sid(n: u32) -> String {
        format!("{n:08x}-0000-4000-8000-{:012x}", u64::from(n) << 24)
    }

    /// The census rows of one piped session: its start row (the wrapper and
    /// the bundled claude, then `args`; `mode` its mode note), and its end
    /// row (the pump's clone with `end`, `exit` and `tail` after the note)
    /// unless `tail` is `None`.
    fn session(pid: u32, start: u64, mode: &str, args: &[&str], tail: Option<&str>, exit: i32) -> Vec<serde_json::Value> {
        let mut argv = vec!["/Users/mike/.cargo/bin/ai-env-claude", "/Users/mike/.cursor/extensions/anthropic.claude-code-2.1.303-darwin-arm64/resources/native-binary/claude"];
        argv.extend_from_slice(args);
        let row = serde_json::json!({
            "v": 1, "ts": format!("2026-10-20T10:{:02}:00Z", start % 60), "start": start, "pid": pid, "ppid": 700, "ext": "2.1.303", "route": "remote", "reason": "session",
            "argv": argv, "cwd": "/Users/mike/Documents/DeFi/ai-env/target/s8/x", "env_names": ["CLAUDE_CODE_ENTRYPOINT", "HOME"],
            "env_selected": {"CLAUDE_CODE_ENTRYPOINT": "claude-vscode"}, "note": mode,
        });
        let mut out = vec![row.clone()];
        if let Some(tail) = tail {
            let mut end = row;
            end["end"] = serde_json::json!(start + 9_000);
            end["exit"] = serde_json::json!(exit);
            end["note"] = serde_json::json!(format!("{mode}; {tail}"));
            out.push(end);
        }
        out
    }

    /// An S10 remote end row's tail (§4.1's order): `init_ms` when given;
    /// the moves (readdress, respawn, migrate), the last one's time and cut,
    /// when any is above 0; the swallow rules' counts; the link's parts on
    /// `vm`, had as `how`, with the `transcript` word.
    fn s10_tail(init_ms: Option<u64>, moves: [u32; 3], transcript: &str, vm: &str, how: &str) -> String {
        let init = init_ms.map_or_else(String::new, |ms| format!("; init_ms:{ms}"));
        let [readdress, respawn, migrate] = moves;
        let moved = if moves.iter().any(|n| *n > 0) { format!("; moves:readdress={readdress},respawn={respawn},migrate={migrate}; move_ms:4200; cut:at") } else { String::new() };
        format!(
            "end:eof; child_pid:-; respawns:0; mirror:0/0; dropped:0; oauth_refresh_answered:0{init}; credential:combined{moved}; inits:2/1; echoes:1/1; vm:{vm}; vm_how:{how}; spawn:s2; vm_pid:41; claude:2.1.303; legs:touchid=2100,select=900,workspace=700,gate=200,spawn=600; seed:seeded; transcript:{transcript}; fetch:1/1; close_ms:540; link_drops:0; auth_timers:match; park:0; pid_rewrite:ok"
        )
    }

    /// S10 F9: init-wrapper judges the newest warm row against its own VM's
    /// budget: a reused one against 5 s, a resumed one (the VM's resume on
    /// top: S8 and S9 measured 5.5 to 6.5 s) against 8 s; a budget met exactly
    /// passes, and the note names the three budgets.
    #[test]
    fn init_wrapper_judges_reused_against_5_s_and_resumed_against_8_s() {
        assert_eq!((INIT_COLD_BUDGET_MS, INIT_WARM_BUDGET_MS, INIT_RESUMED_BUDGET_MS), (30_000, 5_000, 8_000));
        assert_eq!((warm_budget_ms("reused"), warm_budget_ms("resumed")), (5_000, 8_000));
        for (warm, want) in [((5_000, "reused"), "within-budget"), ((5_001, "reused"), "over:warm"), ((5_985, "resumed"), "within-budget"), ((8_000, "resumed"), "within-budget"), ((8_001, "resumed"), "over:warm")] {
            assert_eq!(verdict_init_wrapper(Some(20_000), Some(warm)), want, "{warm:?}");
        }
        assert_eq!(verdict_init_wrapper(None, Some((6_450, "resumed"))), "gap:cold", "within its budget: only the cold row is missing");
        // From the census: the newest warm row decides, by its own vm_how.
        let mut rows = session(40, 1, "mode:remote", &[], Some(&s10_tail(Some(21_000), [0; 3], "none", "microvm-a", "started")), 0);
        rows.extend(session(41, 2, "mode:remote", &[], Some(&s10_tail(Some(6_450), [0; 3], "kept", "microvm-a", "resumed")), 0));
        let row = init_wrapper_verdict(&rows).expect("remote end rows exist");
        assert_eq!(row.verdict, "within-budget", "{row:?}");
        let note = row.note.unwrap_or_default();
        assert!(note.contains("; warm 6450 ms (touchid 2100 ms; vm_how:resumed;") && note.contains("; budgets 30000 ms cold, 5000 ms reused and 8000 ms resumed, from the census start"), "{note}");
        rows.extend(session(42, 3, "mode:remote", &[], Some(&s10_tail(Some(6_450), [0; 3], "kept", "microvm-a", "reused")), 0));
        assert_eq!(init_wrapper_verdict(&rows).unwrap().verdict, "over:warm", "the same time on a reused VM is over");
    }

    /// S10: init-wrapper judges a session that moved the chat only past the
    /// cold budget. Its end row's `vm` and `vm_how` are its last VM's (every
    /// generation rewrites them, a move's too), while its `init_ms` is the
    /// first answer the host got and its legs generation 1's (a move adds
    /// none), and a reopen's carry (generation 1, counted in `moves` too) is
    /// not told apart: no budget of its `vm_how` fits it. So a moved row is
    /// no warm row and, within 30 s, no cold row: it never hides an older
    /// row's over, nor makes one of its own. Past 30 s, the largest budget,
    /// it is over whatever its first VM was and stands as the cold row while
    /// it is the newest (a slow reopen's carry never reads within-budget),
    /// but never a pinned chat's (a pinned VM has no budget: `vm_how:pinned`,
    /// or the pin knob among `env_names` once it moved off the pinned VM);
    /// the note counts the moved rows that answered.
    #[test]
    fn init_wrapper_judges_a_moved_session_only_past_the_cold_budget() {
        let moved = |pid: u32, start: u64, init_ms: u64, moves: [u32; 3], how: &str| session(pid, start, "mode:remote", &[], Some(&s10_tail(Some(init_ms), moves, "restored", "microvm-m", how)), 0);
        let counted = |n: usize| format!("; {n} remote end row(s) moved the chat, a reopen's carry included (judged only past the 30000 ms cold budget: a move rewrites the row's vm_how while its init_ms stays the first answer's)");
        // A cold start of 21 s, then re-addressed onto a suspended VM of the workspace: alone, nothing is judged (never over:warm).
        let row = init_wrapper_verdict(&moved(50, 1, 21_000, [1, 0, 0], "resumed")).expect("a remote end row exists");
        assert_eq!(row.verdict, "gap:cold,warm", "{row:?}");
        let note = row.note.unwrap_or_default();
        assert!(note.starts_with("no cold row yet") && note.ends_with(&counted(1)), "{note}");
        // An older cold row over its 30 s stays the cold row beside a newer warm start migrated onto a started VM.
        let mut rows = session(51, 2, "mode:remote", &[], Some(&s10_tail(Some(31_000), [0; 3], "none", "microvm-a", "started")), 0);
        rows.extend(moved(52, 3, 4_100, [0, 0, 1], "started"));
        assert_eq!(init_wrapper_verdict(&rows).unwrap().verdict, "over:cold");
        // A 7 s answer on a reused VM, moved onto a resumed one, is not judged against 8 s; nor a cold 20 s, respawned on its VM, against 5 s.
        let mut rows = session(53, 4, "mode:remote", &[], Some(&s10_tail(Some(21_000), [0; 3], "none", "microvm-a", "started")), 0);
        rows.extend(moved(54, 5, 7_000, [1, 0, 0], "resumed"));
        rows.extend(moved(55, 6, 20_000, [0, 1, 0], "reused"));
        let row = init_wrapper_verdict(&rows).unwrap();
        assert_eq!(row.verdict, "gap:warm", "{row:?}");
        assert!(row.note.unwrap_or_default().contains("; no warm row yet (a session on a reused or resumed VM); budgets "), "the moved rows are no warm rows");
        // A warm row that never moved is judged as before, the moved rows counted beside it.
        rows.extend(session(56, 7, "mode:remote", &[], Some(&s10_tail(Some(4_000), [0; 3], "kept", "microvm-a", "reused")), 0));
        let row = init_wrapper_verdict(&rows).unwrap();
        assert_eq!(row.verdict, "within-budget", "{row:?}");
        assert!(row.note.unwrap_or_default().ends_with(&counted(2)));
        // A reopen carried off its gone VM onto a started one in 41 s, newer than the cold 21 s: over:cold, named as moved.
        rows.extend(moved(57, 8, 41_000, [1, 0, 0], "started"));
        let row = init_wrapper_verdict(&rows).unwrap();
        assert_eq!(row.verdict, "over:cold", "{row:?}");
        let note = row.note.unwrap_or_default();
        assert!(note.starts_with("cold 41000 ms, a session that moved the chat, past every budget (touchid 2100 ms; vm_how:started; legs touchid=2100,") && note.ends_with(&counted(3)), "{note}");
        // Alone as well, whatever its last VM; at 30 s exactly it is within every budget, so not judged.
        assert_eq!(init_wrapper_verdict(&moved(58, 9, 30_001, [0, 0, 1], "reused")).unwrap().verdict, "over:cold");
        assert_eq!(init_wrapper_verdict(&moved(59, 10, 30_000, [1, 0, 0], "started")).unwrap().verdict, "gap:cold,warm");
        // Never a pinned chat's: respawned on its pinned VM (a respawn keeps vm_how:pinned), or moved off it onto a started
        // one, its env_names (the start row's) naming the pin.
        assert_eq!(init_wrapper_verdict(&moved(61, 12, 35_000, [0, 1, 0], "pinned")).unwrap().verdict, "gap:cold,warm");
        let mut pinned = moved(62, 13, 35_000, [0, 0, 1], "started");
        for r in &mut pinned {
            r["env_names"] = serde_json::json!(["AI_ENV_BRIDGE_VM", "CLAUDE_CODE_ENTRYPOINT", "HOME"]);
        }
        assert_eq!(init_wrapper_verdict(&pinned).unwrap().verdict, "gap:cold,warm", "{pinned:?}");
        let mut beside = rows.clone();
        beside.extend(pinned);
        let row = init_wrapper_verdict(&beside).unwrap();
        assert!(row.verdict == "over:cold" && row.note.as_deref().unwrap_or_default().starts_with("cold 41000 ms, "), "the older unpinned 41 s row stays the cold row: {row:?}");
        // A newer cold start that never moved decides again.
        rows.extend(session(60, 11, "mode:remote", &[], Some(&s10_tail(Some(22_000), [0; 3], "none", "microvm-b", "started")), 0));
        assert_eq!(init_wrapper_verdict(&rows).unwrap().verdict, "within-budget");
        assert!(spec("init-wrapper").unwrap().what.contains("nor (S10) sessions that moved the chat, a reopen's carry included (a move rewrites the row's vm_how while its init_ms stays the first answer's), but one past 30 s stands as the cold row, over whatever its first VM was (a pinned chat's never);"));
    }

    /// S10 (T10.3): a move is dup evidence too: the newest end row of a
    /// remote session that answered initialize and whose moves add up to 1
    /// or more, a new chat's (its row names no session) as a reopened one's,
    /// whatever its transcript word; the evidence then prints the moves and
    /// the swallow rules' inits and echoes (an S9 row, without them, reads as
    /// before). Moves adding up to 0, or a local session's, are no move, nor
    /// is the move an `end:move_failed` row failed at the start of (no moved
    /// claude ran), though an earlier move of that row is; a move that never
    /// answered initialize is named, not taken, and hides no older evidence.
    /// The dup probes' texts name the moves.
    #[test]
    fn a_move_is_dup_evidence_and_the_note_prints_moves_inits_and_echoes() {
        let a = sid(0x10a1);
        let moved = session(60, 1, "mode:remote(config)", &["--output-format", "stream-json"], Some(&s10_tail(Some(9_000), [1, 0, 0], "none", "microvm-new", "started")), 0);
        assert_eq!(
            resume_evidence(&moved).unwrap(),
            "census: a new chat (no --resume) started in remote mode at 2026-10-20T10:01:00Z (wrapper pid 60) on microvm-new (vm_how:started): transcript:none, respawns:0, moves:readdress=1,respawn=0,migrate=0, inits:2/1, echoes:1/1, init_ms:9000, end:eof, exit 0"
        );
        // A reopened chat that moved on its own VM (a respawn), its transcript kept there: still a move.
        let resume_a = format!("--resume={a}");
        let respawned = session(61, 2, "mode:remote", &[resume_a.as_str()], Some(&s10_tail(Some(4_000), [0, 1, 0], "kept", "microvm-a", "reused")), 0);
        assert_eq!(
            resume_evidence(&respawned).unwrap(),
            format!("census: session {a} resumed in remote mode at 2026-10-20T10:02:00Z (wrapper pid 61) on microvm-a (vm_how:reused): transcript:kept, respawns:0, moves:readdress=0,respawn=1,migrate=0, inits:2/1, echoes:1/1, init_ms:4000, end:eof, exit 0")
        );
        // An S10 resume into a new VM, no move: its counts as well.
        let restored = session(62, 3, "mode:remote", &["--resume", &a], Some(&s10_tail(Some(8_000), [0; 3], "restored", "microvm-b", "started")), 0);
        let evidence = resume_evidence(&restored).unwrap();
        assert!(evidence.ends_with("(vm_how:started): transcript:restored, respawns:0, inits:2/1, echoes:1/1, init_ms:8000, end:eof, exit 0"), "{evidence}");
        // Moves adding up to 0, a local session's moves, a new chat whose one move failed at its start (end:move_failed:
        // no moved claude ran, nothing was sent again): neither a move nor a resume.
        let zero = session(63, 4, "mode:remote", &[], Some(&s10_tail(Some(9_000), [0; 3], "none", "microvm-c", "started").replace("; inits:", "; moves:readdress=0,respawn=0,migrate=0; inits:")), 0);
        let local = session(64, 5, "mode:local-child", &[], Some("end:eof; child_pid:9; respawns:0; init_ms:900; moves:readdress=1,respawn=0,migrate=0"), 0);
        let failed = session(66, 7, "mode:remote", &[], Some(&s10_tail(Some(9_000), [1, 0, 0], "none", "microvm-a", "started").replace("end:eof", "end:move_failed")), 8);
        for rows in [&zero, &local, &failed] {
            let why = resume_evidence(rows).unwrap_err();
            assert!(why.starts_with("no remote resume in the census; the dup probes need a census end row of a remote session (mode:remote) that resumed a conversation (--resume), answered initialize (init_ms) and found its VM without the transcript (transcript:uploaded, restored or staged, or respawns:1 or more), or (S10) one that answered initialize and moved the chat (its moves adding up to 1 or more, not counting the failed last move of an end:move_failed row): "), "{why}");
            assert!(why.contains("(T10.3: ai-env vm terminate during a turn)"), "{why}");
        }
        // A move whose chat never answered initialize (the host closed first): no evidence, named as the newest.
        let unanswered = session(65, 6, "mode:remote", &[], Some(&s10_tail(None, [1, 0, 0], "none", "microvm-d", "started")), 0);
        let why = resume_evidence(&unanswered).unwrap_err();
        assert!(why.starts_with("the newest remote move (a new chat, wrapper pid 65, started 2026-10-20T10:06:00Z) never answered initialize (end:eof, exit 0): move a chat that answered (T10.3), close it, then record; the dup probes need "), "{why}");
        // The newest row that qualifies wins, of either kind; a newer unanswered move, or a failed one, hides nothing.
        let mut all = moved.clone();
        all.extend(respawned.clone());
        all.extend(unanswered);
        all.extend(failed);
        assert!(resume_evidence(&all).unwrap().starts_with(&format!("census: session {a} resumed in remote mode at 2026-10-20T10:02:00Z (wrapper pid 61)")));
        // Two moves, the second failed at its start: the first one's claude ran, so the row is evidence.
        all.extend(session(67, 8, "mode:remote", &[], Some(&s10_tail(Some(9_000), [1, 1, 0], "restored", "microvm-e", "started").replace("end:eof", "end:move_failed")), 8));
        assert_eq!(
            resume_evidence(&all).unwrap(),
            "census: a new chat (no --resume) started in remote mode at 2026-10-20T10:08:00Z (wrapper pid 67) on microvm-e (vm_how:started): transcript:restored, respawns:0, moves:readdress=1,respawn=1,migrate=0, inits:2/1, echoes:1/1, init_ms:9000, end:move_failed, exit 8"
        );
        for probe in ["dup-init", "dup-user-replay"] {
            assert!(spec(probe).unwrap().what.contains(" move"), "{probe} names the moves");
        }
        assert!(spec("dup-init").unwrap().what.contains("or moved (its moves adding up to 1 or more, not counting the failed last move of an end:move_failed row), with its session (a new chat's row names none), VM, transcript word, respawns, moves, inits and echoes"));
    }

    /// resume_evidence pairs a start row with its end row by the wrapper's
    /// pid and the census start, both numbers as the wrapper writes them: a
    /// row without them, or with values of another type, pairs with none, so
    /// another run's end row is never a resume's evidence (the start is named
    /// as having no end row yet); numbers pair as before.
    #[test]
    fn resume_evidence_pairs_rows_by_a_numeric_pid_and_start() {
        let (a, b) = (sid(0x10c1), sid(0x10c2));
        let row = |id: &str, note: &str, ids: Option<(serde_json::Value, serde_json::Value)>, end: bool| {
            let mut r = serde_json::json!({"route": "remote", "note": note, "argv": ["w", "c", format!("--resume={id}")], "ts": "2026-10-20T10:07:00Z"});
            if let Some((pid, start)) = ids {
                r["pid"] = pid;
                r["start"] = start;
            }
            if end {
                r["end"] = serde_json::json!(5);
                r["exit"] = serde_json::json!(0);
            }
            r
        };
        let ended = "mode:remote; init_ms:900; transcript:restored; vm:microvm-b; vm_how:started";
        let alone = format!("the newest remote resume (session {a}, started 2026-10-20T10:07:00Z) has no census end row yet: close the chat (or reload Cursor), then record; the dup probes need ");
        // Session A's start beside another run's end row (session B's): a pid and a start of another type, or none at all.
        let typed = [row(&a, "mode:remote", Some((serde_json::json!("4100"), serde_json::json!("x"))), false), row(&b, ended, Some((serde_json::json!(-1), serde_json::json!(1.5))), true)];
        let bare = [row(&a, "mode:remote", None, false), row(&b, ended, None, true)];
        for rows in [&typed, &bare] {
            let why = resume_evidence(rows).unwrap_err();
            assert!(why.starts_with(&alone), "{why}");
        }
        let ids = Some((serde_json::json!(4100), serde_json::json!(1_791_000_000_000u64)));
        let paired = [row(&a, "mode:remote", ids.clone(), false), row(&a, ended, ids, true)];
        assert_eq!(
            resume_evidence(&paired).unwrap(),
            format!("census: session {a} resumed in remote mode at 2026-10-20T10:07:00Z (wrapper pid 4100) on microvm-b (vm_how:started): transcript:restored, respawns:-, init_ms:900, end:-, exit 0")
        );
    }

    /// S10 (L3, T10.3): move-note records what Cursor showed of the move's
    /// note, by hand, only with the census evidence of a move: its verdict is
    /// `shown`, or `not-shown:<what>` (else exit 2, before the census is
    /// read); the evidence is the newest remote end row whose moves add up to
    /// 1 or more, whatever else it shows (a failed move's too); without one
    /// nothing is recorded (exit 1, naming how to get one).
    #[test]
    fn move_note_needs_shown_or_not_shown_and_a_moves_census_evidence() {
        assert_eq!(check_move_note_verdict("shown"), Ok(()));
        assert_eq!(check_move_note_verdict("not-shown:no line in the chat"), Ok(()));
        for bad in ["not-shown:", "not-shown: ", "Shown", "no-duplicate", "shown:yes", ""] {
            let e = check_move_note_verdict(bad).unwrap_err();
            assert!(e.starts_with("move-note: the verdict is shown, or not-shown:<what Cursor showed instead>"), "{bad:?}: {e}");
        }
        let expected = spec("move-note").unwrap().expect.expectation().render();
        assert!(expectation_holds(&expected, "shown") && !expectation_holds(&expected, "not-shown:nothing"));
        let none = move_evidence(&[]).unwrap_err();
        assert!(none.starts_with("no remote end row in the census shows a move (moves adding up to 1 or more, a reopen's carry not counted)") && none.contains("(T10.3: ai-env vm terminate during a turn), close it (or reload Cursor), then record"), "{none}");
        let a = sid(0x10b1);
        // A resume with no move, a local session's moves, a session still open: no evidence.
        let mut rows = session(70, 1, "mode:remote", &["--resume", &a], Some(&s10_tail(Some(8_000), [0; 3], "restored", "microvm-b", "started")), 0);
        rows.extend(session(71, 2, "mode:local-child", &[], Some("end:eof; child_pid:9; respawns:0; init_ms:900; moves:readdress=1,respawn=0,migrate=0"), 0));
        rows.extend(session(72, 3, "mode:remote", &[], None, 0));
        assert!(move_evidence(&rows).unwrap_err().starts_with("no remote end row in the census shows a move"));
        // A reopened chat's re-address, then a new chat's migration that failed: the newest move, failed or not.
        let resume_a = format!("--resume={a}");
        rows.extend(session(73, 4, "mode:remote", &[resume_a.as_str()], Some(&s10_tail(Some(4_000), [1, 0, 0], "restored", "microvm-c", "started")), 0));
        let readdress = format!("census: session {a} moved in remote mode (started 2026-10-20T10:04:00Z, wrapper pid 73), last on microvm-c (vm_how:started): moves:readdress=1,respawn=0,migrate=0, move_ms:4200, cut:at, inits:2/1, echoes:1/1, init_ms:4000, end:eof, exit 0");
        assert_eq!(move_evidence(&rows).unwrap(), readdress);
        rows.extend(session(74, 5, "mode:remote", &[], Some(&s10_tail(Some(3_000), [0, 0, 1], "none", "microvm-c", "reused").replace("end:eof", "end:move_failed")), 8));
        assert_eq!(
            move_evidence(&rows).unwrap(),
            "census: a new chat (no --resume) moved in remote mode (started 2026-10-20T10:05:00Z, wrapper pid 74), last on microvm-c (vm_how:reused): moves:readdress=0,respawn=0,migrate=1, move_ms:4200, cut:at, inits:2/1, echoes:1/1, init_ms:3000, end:move_failed, exit 8"
        );
        // `lab run move-note --manual VERDICT`'s path: the verdict's form first, then the census.
        let d = tempfile::tempdir().unwrap();
        let paths = crate::bridge::config::Paths::from_root_and_env(d.path().to_path_buf(), None);
        let usage = cursor_evidence(&paths, "move-note", "maybe").unwrap_err();
        assert!(matches!(&usage, CliError::Usage(m) if m.starts_with("move-note: the verdict is shown")), "{usage:?}");
        let empty = cursor_evidence(&paths, "move-note", "shown").unwrap_err();
        assert!(matches!(&empty, CliError::Msg(m) if m.starts_with("move-note: no remote end row in the census shows a move") && m.ends_with("; nothing recorded")), "{empty:?}");
        std::fs::create_dir_all(paths.census().parent().unwrap()).unwrap();
        std::fs::write(paths.census(), rows[..rows.len() - 2].iter().map(|r| format!("{r}\n")).collect::<String>()).unwrap();
        assert_eq!(cursor_evidence(&paths, "move-note", "not-shown:a blank line").unwrap(), readdress);
        // The dup probes take the same move.
        let dup = cursor_evidence(&paths, "dup-init", "no-duplicate").unwrap();
        assert!(dup.starts_with(&format!("census: session {a} resumed in remote mode at 2026-10-20T10:04:00Z (wrapper pid 73) on microvm-c (vm_how:started): transcript:restored, respawns:0, moves:readdress=1,")), "{dup}");
    }

    /// S10 §2.7: a reopen's carry (`carried:`) counts in `moves`, but it is no
    /// move `move-note` takes (it shows no note) and none the dup probes'
    /// `moves_done` counts (it sends nothing again); a move after the carry is.
    #[test]
    fn a_reopens_carry_is_no_move_for_move_note_or_the_dup_probes() {
        let a = sid(0x10c1);
        let resume_a = format!("--resume={a}");
        let carried = |moves: [u32; 3]| format!("{}; carried:readdress", s10_tail(Some(9_000), moves, "restored", "microvm-d", "started"));
        let mut rows = session(80, 1, "mode:remote", &[resume_a.as_str()], Some(&carried([1, 0, 0])), 0);
        let end_parts = |rows: &[serde_json::Value]| note_parts(rows.iter().rev().find(|r| is_end_row(r)).unwrap()).iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect::<Vec<_>>();
        let done = |parts: &[(String, String)]| moves_done(&parts.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>());
        assert_eq!(done(&end_parts(&rows)), 0, "the carry alone sends nothing again");
        assert!(move_evidence(&rows).unwrap_err().starts_with("no remote end row in the census shows a move (moves adding up to 1 or more, a reopen's carry not counted)"));
        rows = session(81, 2, "mode:remote", &[resume_a.as_str()], Some(&carried([2, 0, 0])), 0);
        assert_eq!(done(&end_parts(&rows)), 1, "the move after the carry");
        assert!(move_evidence(&rows).unwrap().starts_with(&format!("census: session {a} moved in remote mode")));
    }
}
