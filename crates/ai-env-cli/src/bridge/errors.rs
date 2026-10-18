//! Bridge errors, mapped onto the CLI exit taxonomy: 7 AWS/infra, 8 VM lost,
//! 9 policy, 5 credentials unavailable, 3 cancelled, 1 everything else.
use crate::errors::CliError;
use crate::wire::frame::RunHookPayload;
use crate::wire::redact::scrub;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum BridgeError {
    // exit 7
    Sdk { op: &'static str, message: String },
    Quota(String),
    Validation(String),
    Http { status: u16, body: String },
    /// A wrong-state operation (suspend of a SUSPENDED VM, …); the message names the state.
    Conflict(String),
    /// Throttled after the SDK's own retries.
    Throttled(String),
    /// The runtime principal may not do this (the image-scoped runtime policy, or the sealed key is not the runtime user's).
    AccessDenied(String),
    /// The endpoint proxy refused the token (401/403): wrong port, expired, or not this VM's.
    TokenRejected { port: u16, status: u16, proxy_error: Option<String> },
    /// The MicroVM endpoint could not be reached (connect, reset, timeout): transient, retried.
    Endpoint(String),
    /// The call failed after it may have reached the service (timeout, dispatch or
    /// response failure, a 5xx): retry only with the same `client_token` (plan S4 D16).
    Ambiguous { op: &'static str, message: String },
    /// The endpoint kept answering 429 past the reconnect budget (S6); the last `Retry-After`, if any.
    EndpointThrottled { retry_after_s: Option<u64> },
    /// The VM answers no `/agent` (404): an image older than S6.
    NoAgent(String),
    /// S8: the VM lacks a capability a step needs (`cap`, e.g. `workspace_v1`:
    /// the seed, code-out, transcript and settings routes; S9's
    /// `git_http_v1`, `transcript_s3_v1`): an image older than the stage
    /// that added it (`wire::frame::cap_stage`). Never retried; nothing was sent.
    NoCapability { cap: &'static str, message: String },
    /// S9: S3 answered an error the transcript store does not act on itself
    /// (`op`: what was asked, `code`: S3's `<Code>` when known).
    S3 { op: &'static str, status: u16, code: Option<String> },
    // exit 5
    /// S7: the VM's credential cache no longer holds the seal a delivery
    /// expected it to hold (it went after it was checked), and no unsealed
    /// value is in hand: nothing was started. No caller retries (a retry
    /// inside `vm exec` could lose piped stdin already read); the message
    /// tells the operator to run the command again, which unseals the token.
    CredentialMissing(String),
    CredentialsUnavailable(String),
    // exit 3
    /// The operator pressed Ctrl-C (`lab run`: after the terminate guard ended the probe's VMs).
    Cancelled,
    // exit 8
    Transport(String),
    Terminated(String),
    Gap { spawn_id: String, from_seq: u64 },
    Protocol(String),
    /// The shim refused the hello (`bad_token`, `no_commitment`, `version`, `busy`) (S6).
    HelloRefused { code: String, message: String },
    /// A newer client attached this spawn (S6).
    Superseded(String),
    /// The VM is RUNNING but its shim does not answer `/agent`, or `/run` never came (S6).
    ShimUnavailable(String),
    /// `ResourceNotFound` for a MicroVM id: it is gone (or never was).
    VmNotFound(String),
    // exit 9
    Tripwire(String),
    SettingsWidening(String),
    EgressRequired,
    /// A VM whose egress echo (RunMicrovm, else the first GetMicrovm) is not
    /// exactly the connectors its egress requires (S5 echo gate). Boxed: it
    /// would double the size of every `Result` that carries a `BridgeError`.
    EgressMismatch(Box<EgressMismatch>),
    OutsideRoots(PathBuf),
    PayloadTooLarge(usize),
    MaxConcurrent(u32),
    /// A request the policy refuses (a token port outside the allowlist, a VM of another image, …).
    Policy(String),
    /// S8: the workspace data plane refused (`code`: the shim's refusal code,
    /// `wire::workspace::refusal`, such as `symlink_component` or
    /// `other_workspace`, or the Mac's own, `bridge::workspace::code`, such as
    /// `not_a_git_repo` or `wip_too_large`); `message` names the path, ref or
    /// rule, never a value.
    WorkspaceRefused { code: &'static str, message: String },
    /// S9: a session's transcript over what a seed or a reopen carries
    /// inline (S2's text, unchanged): `remote::Failure::TranscriptTooLarge`
    /// names `ai-env session stage`.
    TranscriptTooLarge { session: String, bytes: u64 },
    /// S9 (R5-AWS-1): a reopen's restore under the init deadline would pull
    /// more of the chat's transcript from S3 than `wire::s3::INLINE_MAX` in
    /// all: refused before any pull. `remote::Failure::TranscriptPullTooLarge`
    /// names `ai-env session stage UUID --warm`.
    TranscriptPullTooLarge { session: String, bytes: u64 },
    // exit 1 (vm exec maps `not_found` to 127 and `exec` to 126, like a shell, and `limit` to 9)
    /// The VM could not start the command: `code` is the shim's `spawn_err`
    /// code (`not_found`, `exec`, `cwd`, `limit`), `message` its scrubbed text.
    SpawnRefused { code: &'static str, message: String },
    Config(String),
    Io(std::io::Error),
    /// A lock stayed held past its budget (`workspace busy (pid N)`).
    Busy(String),
    /// S8: a workspace step failed (`code`: the wire's `git_failed`,
    /// `bad_pack`, `timeout`, …, or the Mac's own, `bridge::workspace::code`,
    /// such as `unsupported_repo`): a git run, a pack the VM did not take, an
    /// unsupported repository (shallow, bare, …).
    WorkspaceFailed { code: &'static str, message: String },
    // its own exit code
    /// A failure the CLI side already classified (S7: a credential step inside
    /// a `lab run` probe): its own exit code and text, so a missing key stays 4
    /// and a stopped unseal 130 or 143, never 1 with a `config:` line.
    Cli(CliError),
}

/// What the S5 egress echo gate found: the VM `id` echoed `echoed` where its
/// egress requires exactly `expected`; it was terminated when `terminated`,
/// else it is still alive under `id` (the caller keeps it in its terminate guard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressMismatch {
    pub id: String,
    pub expected: Vec<String>,
    pub echoed: Vec<String>,
    pub terminated: bool,
}

impl BridgeError {
    /// [`BridgeError::EgressMismatch`] of these fields.
    #[must_use]
    pub fn egress_mismatch(id: &str, expected: Vec<String>, echoed: Vec<String>, terminated: bool) -> BridgeError {
        BridgeError::EgressMismatch(Box::new(EgressMismatch { id: id.to_string(), expected, echoed, terminated }))
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeError::Sdk { op: op @ "run_microvm", message } => write!(f, "aws {op}: {message}{}", connector_hint(message)),
            BridgeError::Sdk { op, message } => write!(f, "aws {op}: {message}"),
            BridgeError::Quota(m) => write!(f, "aws quota: {m}"),
            BridgeError::Validation(m) => write!(f, "aws validation: {m}{}", connector_hint(m)),
            BridgeError::Http { status, body } => write!(f, "endpoint HTTP {status}: {}", crate::wire::redact::scrub(body)),
            BridgeError::Conflict(m) => write!(f, "aws conflict: {m}"),
            BridgeError::Throttled(m) => write!(f, "aws throttled (after retries): {m}"),
            BridgeError::AccessDenied(m) if m.contains("PassNetworkConnector") => {
                write!(f, "aws access denied: {m} (the runtime policy must allow lambda:PassNetworkConnector for --egress vpc: make deploy)")
            }
            BridgeError::AccessDenied(m) if m.contains("iam:PassRole") => {
                write!(f, "aws access denied: {m} (the runtime policy must allow iam:PassRole on the execution role; or start the VM without one: vm run/vm smoke --no-execution-role)")
            }
            BridgeError::AccessDenied(m) => {
                write!(f, "aws access denied: {m} (the runtime policy allows only the ai-env image; is credentials/aws.env the ai-env-runtime key?)")
            }
            BridgeError::TokenRejected { port, status, proxy_error } => {
                write!(f, "token rejected: HTTP {status} for port {port}")?;
                if let Some(p) = proxy_error {
                    write!(f, " (x-aws-proxy-error: {p})")?;
                }
                Ok(())
            }
            BridgeError::Endpoint(m) => write!(f, "endpoint: {m}"),
            BridgeError::Ambiguous { op, message } => write!(f, "aws {op}: {message} (the request may have reached the service)"),
            BridgeError::EndpointThrottled { retry_after_s } => match retry_after_s {
                Some(s) => write!(f, "endpoint throttled (HTTP 429, Retry-After {s} s) past the reconnect budget"),
                None => f.write_str("endpoint throttled (HTTP 429) past the reconnect budget"),
            },
            BridgeError::NoAgent(m) => write!(f, "the VM's shim has no /agent ({m}): its image is older than S6; start a VM of the current image"),
            // The S8 texts are scrubbed here too: a message may quote what the VM or git said.
            BridgeError::NoCapability { cap, message } => {
                write!(f, "the VM's shim lacks {cap} ({}): its image is older than {}; run make deploy, then use a VM of the new image", scrub(message), crate::wire::frame::cap_stage(cap))
            }
            BridgeError::S3 { op, status, code } => {
                write!(f, "s3 {op}: HTTP {status}")?;
                if let Some(c) = code {
                    write!(f, " ({})", scrub(c))?;
                }
                Ok(())
            }
            BridgeError::CredentialsUnavailable(m) => write!(f, "credentials unavailable: {m}"),
            BridgeError::CredentialMissing(m) => write!(f, "credential not on the VM: {m}"),
            BridgeError::Cancelled => f.write_str("cancelled"),
            BridgeError::Transport(m) => write!(f, "transport: {m}"),
            BridgeError::Terminated(m) => write!(f, "microvm terminated: {m}"),
            BridgeError::Gap { spawn_id, from_seq } => write!(f, "replay gap for spawn {spawn_id} from seq {from_seq}"),
            BridgeError::Protocol(m) => write!(f, "shim protocol: {m}"),
            BridgeError::HelloRefused { code, message } => match code.as_str() {
                "bad_token" => write!(f, "the VM refused this Mac's session token (wrong VM or stale row): {message}"),
                "no_commitment" => write!(f, "the VM booted without a session commitment (fail-closed /run): terminate it: {message}"),
                _ => write!(f, "the VM refused the hello ({code}): {message}"),
            },
            BridgeError::Superseded(m) => write!(f, "superseded: another client attached {m}"),
            BridgeError::ShimUnavailable(m) => write!(f, "the shim does not answer: {m}"),
            BridgeError::VmNotFound(m) => write!(f, "microvm not found: {m}"),
            BridgeError::Tripwire(m) => write!(f, "tripwire: {m}"),
            BridgeError::SettingsWidening(m) => write!(f, "repo settings widen permissions: {m}"),
            // At most 160 characters, so the remote wrapper's P0 line (`remote::Failure::Refused`) keeps the fix whole.
            BridgeError::EgressRequired => f.write_str("egress connector required (vpc egress asked for, or [egress].require=true) and none configured: make infra-status WRITE=1 writes [aws].egress_connector_arn"),
            BridgeError::EgressMismatch(m) => {
                let EgressMismatch { id, expected, echoed, terminated } = m.as_ref();
                let list = |l: &[String]| if l.is_empty() { "nothing".to_string() } else { l.join(", ") };
                if expected.is_empty() {
                    write!(f, "egress mismatch: {id} echoed egress {}, but its row records no egress connector (written before S5, or a vpc run without one): fail closed", list(echoed))?;
                } else {
                    write!(f, "egress mismatch: {id} echoed egress {} but its egress requires exactly {}", list(echoed), list(expected))?;
                }
                if *terminated {
                    f.write_str("; terminated")?;
                } else {
                    write!(f, "; NOT confirmed terminated: run `ai-env vm terminate {id}`")?;
                }
                if let Some(seg) = id_form_echo(expected, echoed) {
                    write!(f, " (if {seg} is the connector's Id, run `make infra-status WRITE=1` so state/infra.toml records connector_id)")?;
                }
                Ok(())
            }
            BridgeError::OutsideRoots(p) => write!(f, "{} is outside [workspaces].roots", p.display()),
            BridgeError::PayloadTooLarge(n) => write!(f, "run-hook payload of {n} bytes exceeds {}", RunHookPayload::MAX_BYTES),
            BridgeError::MaxConcurrent(n) => write!(f, "[vm].max_concurrent={n} reached"),
            BridgeError::Policy(m) => write!(f, "refused: {m}"),
            BridgeError::WorkspaceRefused { code, message } => write!(f, "workspace refused ({code}): {}", scrub(message)),
            BridgeError::TranscriptTooLarge { bytes, .. } => write!(f, "transcript too large to seed: {bytes} bytes"),
            BridgeError::TranscriptPullTooLarge { bytes, .. } => write!(f, "the transcript in S3 is {bytes} bytes: a reopen pulls at most {} inline", crate::wire::s3::INLINE_MAX),
            BridgeError::SpawnRefused { code, message } => write!(f, "the VM could not start the command ({code}): {message}"),
            BridgeError::Config(m) => write!(f, "config: {m}"),
            BridgeError::Io(e) => write!(f, "{e}"),
            BridgeError::Busy(m) => write!(f, "busy: {m}"),
            BridgeError::WorkspaceFailed { code, message } => write!(f, "workspace failed ({code}): {}", scrub(message)),
            BridgeError::Cli(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<std::io::Error> for BridgeError {
    fn from(e: std::io::Error) -> Self {
        BridgeError::Io(e)
    }
}

impl From<BridgeError> for CliError {
    fn from(e: BridgeError) -> Self {
        let text = e.to_string();
        match e {
            BridgeError::Sdk { .. }
            | BridgeError::Quota(_)
            | BridgeError::Validation(_)
            | BridgeError::Http { .. }
            | BridgeError::Conflict(_)
            | BridgeError::Throttled(_)
            | BridgeError::AccessDenied(_)
            | BridgeError::TokenRejected { .. }
            | BridgeError::Endpoint(_)
            | BridgeError::Ambiguous { .. }
            | BridgeError::EndpointThrottled { .. }
            | BridgeError::NoAgent(_)
            | BridgeError::NoCapability { .. }
            | BridgeError::S3 { .. } => CliError::Aws(text),
            BridgeError::CredentialsUnavailable(_) | BridgeError::CredentialMissing(_) => CliError::AuthUnavailable(text),
            BridgeError::Cancelled => CliError::Cancelled,
            BridgeError::Transport(_)
            | BridgeError::Terminated(_)
            | BridgeError::Gap { .. }
            | BridgeError::Protocol(_)
            | BridgeError::VmNotFound(_)
            | BridgeError::HelloRefused { .. }
            | BridgeError::Superseded(_)
            | BridgeError::ShimUnavailable(_) => CliError::VmLost(text),
            BridgeError::Tripwire(_)
            | BridgeError::SettingsWidening(_)
            | BridgeError::EgressRequired
            | BridgeError::EgressMismatch(_)
            | BridgeError::OutsideRoots(_)
            | BridgeError::PayloadTooLarge(_)
            | BridgeError::MaxConcurrent(_)
            | BridgeError::Policy(_)
            | BridgeError::WorkspaceRefused { .. }
            | BridgeError::TranscriptTooLarge { .. }
            | BridgeError::TranscriptPullTooLarge { .. } => CliError::Policy(text),
            BridgeError::Config(_) | BridgeError::Busy(_) | BridgeError::SpawnRefused { .. } | BridgeError::WorkspaceFailed { .. } => CliError::Msg(text),
            BridgeError::Io(io) => CliError::from(io),
            BridgeError::Cli(e) => e,
        }
    }
}

/// S9's phase-0 stubs that return a [`BridgeError`] (the data plane's,
/// the presigner's): what an operation a later S9 wave builds answers until
/// then, `WorkspaceFailed { not_built }` with `<what>: not built yet
/// (<wave>)` (exit 1), `wave` as `S9 wave 1: G4`. A stub returns it and
/// never panics; the wave that builds the code removes the stub. A command's
/// stub uses `crate::errors::not_built` (the same text).
#[must_use]
pub fn not_built(what: &str, wave: &str) -> BridgeError {
    BridgeError::WorkspaceFailed { code: crate::bridge::workspace::code::NOT_BUILT, message: format!("{what}: not built yet ({wave})") }
}

/// The hint a RunMicrovm failure that names a network connector gets: a
/// connector must be ACTIVE before a VM may use it (S5). Empty otherwise.
fn connector_hint(message: &str) -> &'static str {
    if message.to_ascii_lowercase().contains("connector") && !message.contains("PassNetworkConnector") {
        " (is the egress connector ACTIVE? make connector-status)"
    } else {
        ""
    }
}

/// The last ARN segment of an echoed customer connector that differs from
/// every expected one in that segment only: possibly the connector's Id form.
/// Never when the expected ARN is itself in the Id form (`nc-…`, as measured
/// 1 Oct 2026: a connector Pulumi creates): no alias can apply, so the hint
/// to record the Id would only repeat.
fn id_form_echo<'a>(expected: &[String], echoed: &'a [String]) -> Option<&'a str> {
    let split = |a: &str| a.rsplit_once(":network-connector:").map(|(p, s)| (p.to_string(), s.split(':').next().unwrap_or(s).to_string()));
    echoed.iter().find_map(|e| {
        let (prefix, seg) = split(e)?;
        if prefix.ends_with(":aws") {
            return None;
        }
        let other = expected.iter().filter_map(|x| split(x)).any(|(p, s)| p == prefix && s != seg && !s.starts_with("nc-"));
        other.then(|| e.rsplit_once(":network-connector:").map_or(e.as_str(), |(_, s)| s.split(':').next().unwrap_or(s)))
    })
}

/// The MicroVM operations whose `ResourceNotFound` means "this VM is gone"
/// (exit 8). Everywhere else it is an infra error (exit 7) naming the
/// resource — for `RunMicrovm` the image version, a connector or the
/// execution role (it names no VM yet).
const VM_OPS: [&str; 6] = ["get_microvm", "suspend_microvm", "resume_microvm", "terminate_microvm", "create_microvm_auth_token", "create_microvm_shell_auth_token"];

/// Error codes that mean the request was not accepted as the runtime
/// principal at all (bad, expired or foreign credentials): exit 5.
const CREDENTIAL_CODES: [&str; 6] = [
    "UnrecognizedClientException",
    "InvalidSignatureException",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "MissingAuthenticationToken",
];

/// Map an SDK error onto the bridge taxonomy (plan S4 D18). Service errors
/// are classified by their modelled `code()` (the Display prefix is only a
/// fallback when no code was parsed); non-service errors render through
/// `DisplayErrorContext` and the scrubber, never through `{:?}` of a raw
/// response. A non-service error that mentions credentials is exit 5.
pub fn map_sdk_error<E, R>(op: &'static str, e: aws_sdk_lambdamicrovms::error::SdkError<E, R>) -> BridgeError
where
    E: aws_sdk_lambdamicrovms::error::ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    R: fmt::Debug,
{
    use aws_sdk_lambdamicrovms::error::{DisplayErrorContext, SdkError};
    let scrubbed = |text: String| crate::wire::redact::scrub(&text).into_owned();
    match &e {
        SdkError::ServiceError(se) => {
            let err = se.err();
            let message = scrubbed(err.message().map_or_else(|| err.to_string(), str::to_string));
            classify_service(op, err.code(), message)
        }
        _ => {
            let text = scrubbed(DisplayErrorContext(&e).to_string());
            if text.to_ascii_lowercase().contains("credential") {
                BridgeError::CredentialsUnavailable(format!("{op}: {text}"))
            } else {
                BridgeError::Sdk { op, message: text }
            }
        }
    }
}

/// The service-error half of [`map_sdk_error`], pure so every code is testable.
#[must_use]
pub fn classify_service(op: &'static str, code: Option<&str>, message: String) -> BridgeError {
    let with_code = |c: &str| format!("{c}: {message}");
    match code {
        // The service's text already says `MicroVM not found: <id>`; keep only the id part.
        Some("ResourceNotFoundException") if VM_OPS.contains(&op) => BridgeError::VmNotFound(message.strip_prefix("MicroVM not found: ").map_or_else(|| message.clone(), str::to_string)),
        Some("ServiceQuotaExceededException") => BridgeError::Quota(message),
        Some("ValidationException") => BridgeError::Validation(message),
        Some("ConflictException") => BridgeError::Conflict(message),
        Some("ThrottlingException") => BridgeError::Throttled(message),
        Some("AccessDeniedException") => BridgeError::AccessDenied(format!("{op}: {message}")),
        Some("InsufficientCapacityException") => BridgeError::Sdk { op, message: format!("InsufficientCapacityException: {message} (retry later)") },
        Some(c) if CREDENTIAL_CODES.contains(&c) => BridgeError::CredentialsUnavailable(format!("{op}: {}", with_code(c))),
        Some(c) => BridgeError::Sdk { op, message: with_code(c) },
        None => {
            let lower = message.to_ascii_lowercase();
            if lower.contains("quota") || lower.contains("limit exceeded") {
                BridgeError::Quota(message)
            } else if lower.contains("validation") {
                BridgeError::Validation(message)
            } else {
                BridgeError::Sdk { op, message }
            }
        }
    }
}

/// Could the request have reached the service although the call failed
/// (timeout, dispatch or response failure, a 5xx)? Then a retry must reuse
/// the same `client_token` (plan S4 D16).
#[must_use]
pub fn sdk_ambiguous<E, R>(e: &aws_sdk_lambdamicrovms::error::SdkError<E, R>) -> bool
where
    E: aws_sdk_lambdamicrovms::error::ProvideErrorMetadata,
{
    use aws_sdk_lambdamicrovms::error::SdkError;
    match e {
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) | SdkError::ResponseError(_) => true,
        SdkError::ServiceError(se) => matches!(se.err().code(), Some("InternalServerException" | "ServiceUnavailableException")),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_mapping() {
        let cases: Vec<(BridgeError, i32)> = vec![
            (BridgeError::Sdk { op: "run", message: "x".into() }, 7),
            (BridgeError::Quota("q".into()), 7),
            (BridgeError::Http { status: 502, body: String::new() }, 7),
            (BridgeError::Conflict("c".into()), 7),
            (BridgeError::Throttled("t".into()), 7),
            (BridgeError::AccessDenied("a".into()), 7),
            (BridgeError::TokenRejected { port: 8080, status: 403, proxy_error: None }, 7),
            (BridgeError::Endpoint("e".into()), 7),
            (BridgeError::Ambiguous { op: "run_microvm", message: "timeout".into() }, 7),
            (BridgeError::CredentialsUnavailable("c".into()), 5),
            (BridgeError::Cancelled, 3),
            (BridgeError::Transport("t".into()), 8),
            (BridgeError::Gap { spawn_id: "s".into(), from_seq: 1 }, 8),
            (BridgeError::VmNotFound("microvm-x".into()), 8),
            (BridgeError::Tripwire("AKIA".into()), 9),
            (BridgeError::EgressRequired, 9),
            (BridgeError::egress_mismatch("microvm-x", vec![], vec![], true), 9),
            (BridgeError::MaxConcurrent(3), 9),
            (BridgeError::Policy("port 9000".into()), 9),
            (BridgeError::Config("bad".into()), 1),
            (BridgeError::Busy("pid 1".into()), 1),
            (BridgeError::Io(std::io::Error::other("io")), 1),
            (BridgeError::Cli(CliError::NoKey("k".into())), 4),
            (BridgeError::Cli(CliError::Exit(143)), 143),
            // S8: an image without the capability, a workspace the data plane refuses, a workspace step that failed.
            (BridgeError::NoCapability { cap: "workspace_v1", message: "GET /seed answered 404".into() }, 7),
            (BridgeError::WorkspaceRefused { code: crate::wire::workspace::refusal::SYMLINK_COMPONENT, message: "/Users/mike/w".into() }, 9),
            (BridgeError::WorkspaceRefused { code: crate::bridge::workspace::code::NOT_A_GIT_REPO, message: "/Users/mike/w".into() }, 9),
            (BridgeError::WorkspaceRefused { code: crate::bridge::workspace::code::WIP_TOO_LARGE, message: "/Users/mike/w".into() }, 9),
            (BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: "git exited 128".into() }, 1),
            (BridgeError::WorkspaceFailed { code: crate::bridge::workspace::code::UNSUPPORTED_REPO, message: "a shallow repository".into() }, 1),
            // S9: an S3 error, a transcript over the inline cap, a phase-0 stub, an image without S9's caps.
            (BridgeError::S3 { op: "transcript push", status: 403, code: Some("AccessDenied".into()) }, 7),
            (BridgeError::TranscriptTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 1 << 30 }, 9),
            (BridgeError::TranscriptPullTooLarge { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), bytes: 1 << 30 }, 9),
            (not_built("box review", "S9 wave 1: G3"), 1),
            (BridgeError::NoCapability { cap: crate::wire::frame::CAP_GIT_HTTP_V1, message: "microvm-1 names no git_http_v1 in its caps".into() }, 7),
        ];
        for (e, code) in cases {
            let text = e.to_string();
            let c: CliError = e.into();
            assert_eq!(c.exit_code(), code, "{text}");
        }
    }

    #[test]
    fn service_errors_by_code() {
        let m = || "msg".to_string();
        assert!(matches!(classify_service("get_microvm", Some("ResourceNotFoundException"), m()), BridgeError::VmNotFound(_)));
        let e = classify_service("get_microvm", Some("ResourceNotFoundException"), "MicroVM not found: microvm-x".into());
        assert_eq!(e.to_string(), "microvm not found: microvm-x", "the service prefix is not doubled");
        assert!(matches!(classify_service("get_microvm_image", Some("ResourceNotFoundException"), m()), BridgeError::Sdk { .. }), "an image that is gone is infra, not a lost VM");
        let e = classify_service("run_microvm", Some("ResourceNotFoundException"), "Image version 9.0 not found".into());
        assert_eq!(e.to_string(), "aws run_microvm: ResourceNotFoundException: Image version 9.0 not found", "RunMicrovm names no VM yet: infra, exit 7");
        assert!(matches!(classify_service("run_microvm", Some("ServiceQuotaExceededException"), m()), BridgeError::Quota(_)));
        assert!(matches!(classify_service("run_microvm", Some("ValidationException"), m()), BridgeError::Validation(_)));
        assert!(matches!(classify_service("suspend_microvm", Some("ConflictException"), m()), BridgeError::Conflict(_)));
        assert!(matches!(classify_service("list_microvms", Some("ThrottlingException"), m()), BridgeError::Throttled(_)));
        assert!(matches!(classify_service("get_microvm", Some("AccessDeniedException"), m()), BridgeError::AccessDenied(_)));
        for c in CREDENTIAL_CODES {
            assert!(matches!(classify_service("list_microvms", Some(c), m()), BridgeError::CredentialsUnavailable(_)), "{c}");
        }
        let e = classify_service("run_microvm", Some("InsufficientCapacityException"), m());
        assert!(e.to_string().contains("retry later"), "{e}");
        let e = classify_service("run_microvm", Some("SomethingNewException"), m());
        assert_eq!(e.to_string(), "aws run_microvm: SomethingNewException: msg");
        assert!(matches!(classify_service("x", None, "Service quota exceeded".into()), BridgeError::Quota(_)), "Display fallback without a code");
    }

    /// Real SDK errors, as `send()` returns them, through the public mappers.
    mod sdk {
        use super::super::{map_sdk_error, sdk_ambiguous, BridgeError};
        use crate::errors::CliError;
        use aws_sdk_lambdamicrovms::config::http::HttpResponse;
        use aws_sdk_lambdamicrovms::error::{ErrorMetadata, SdkError};
        use aws_sdk_lambdamicrovms::operation::get_microvm::GetMicrovmError;
        use aws_sdk_lambdamicrovms::operation::run_microvm::RunMicrovmError;

        fn meta(code: &str, message: &str) -> ErrorMetadata {
            ErrorMetadata::builder().code(code).message(message).build()
        }

        /// The raw response a service error came with (status only; the body was already parsed).
        fn raw(status: u16) -> HttpResponse {
            HttpResponse::new(status.try_into().expect("a valid status"), "{}".into())
        }

        fn get_err(code: &str, message: &str, status: u16) -> SdkError<GetMicrovmError, HttpResponse> {
            SdkError::service_error(GetMicrovmError::generic(meta(code, message)), raw(status))
        }

        fn run_err(code: &str, message: &str, status: u16) -> SdkError<RunMicrovmError, HttpResponse> {
            SdkError::service_error(RunMicrovmError::generic(meta(code, message)), raw(status))
        }

        fn exit(e: BridgeError) -> i32 {
            CliError::from(e).exit_code()
        }

        #[test]
        fn resource_not_found_is_a_lost_vm_only_for_vm_operations() {
            let id = "microvm-00000000-0000-4000-8000-000000000001";
            let e = map_sdk_error("get_microvm", get_err("ResourceNotFoundException", &format!("MicroVM not found: {id}"), 404));
            assert!(matches!(&e, BridgeError::VmNotFound(m) if m == id), "{e}");
            assert_eq!(exit(e), 8);
            // The typed variant carries the same metadata.
            let typed = aws_sdk_lambdamicrovms::types::error::ResourceNotFoundException::builder()
                .message(format!("MicroVM not found: {id}"))
                .meta(meta("ResourceNotFoundException", &format!("MicroVM not found: {id}")))
                .build()
                .unwrap();
            let e = map_sdk_error("get_microvm", SdkError::service_error(GetMicrovmError::ResourceNotFoundException(typed), raw(404)));
            assert!(matches!(e, BridgeError::VmNotFound(_)), "{e}");
            let e = map_sdk_error("run_microvm", run_err("ResourceNotFoundException", "Network connector arn:aws:lambda:eu-central-1:123456789012:network-connector:x not found", 404));
            let text = e.to_string();
            assert!(matches!(e, BridgeError::Sdk { op: "run_microvm", .. }) && text.contains("network-connector:x not found"), "names the resource: {text}");
            assert_eq!(exit(e), 7);
        }

        #[test]
        fn throttling_and_credential_codes() {
            let e = map_sdk_error("get_microvm", get_err("ThrottlingException", "Rate exceeded", 429));
            assert!(matches!(e, BridgeError::Throttled(_)), "{e}");
            assert_eq!(exit(e), 7);
            let e = map_sdk_error("run_microvm", run_err("UnrecognizedClientException", "The security token included in the request is invalid.", 403));
            assert!(matches!(e, BridgeError::CredentialsUnavailable(_)), "{e}");
            assert_eq!(exit(e), 5);
            let e = map_sdk_error("run_microvm", run_err("ServiceQuotaExceededException", "Max allocated ARM_64 MicroVM memory", 402));
            assert!(matches!(e, BridgeError::Quota(_)), "{e}");
        }

        #[test]
        fn ambiguity_of_real_sdk_errors() {
            assert!(sdk_ambiguous(&run_err("InternalServerException", "internal", 500)));
            assert!(sdk_ambiguous(&get_err("ServiceUnavailableException", "later", 503)));
            assert!(!sdk_ambiguous(&run_err("ValidationException", "bad", 400)));
            assert!(!sdk_ambiguous(&run_err("InsufficientCapacityException", "full", 500)), "no capacity: nothing was placed");
            assert!(sdk_ambiguous(&SdkError::<RunMicrovmError, HttpResponse>::timeout_error("operation timeout (all attempts including retries) occurred after 40s")));
            assert!(sdk_ambiguous(&SdkError::<RunMicrovmError, HttpResponse>::response_error("the response body was cut short", raw(200))));
            assert!(!sdk_ambiguous(&SdkError::<RunMicrovmError, HttpResponse>::construction_failure("bad input")));
            // What the real client's GetMicrovm turns a timeout into (wait_for_state retries it).
            let e = map_sdk_error("get_microvm", SdkError::<GetMicrovmError, HttpResponse>::timeout_error("operation timeout"));
            assert!(matches!(e, BridgeError::Sdk { op: "get_microvm", .. }), "{e}");
        }
    }

    #[test]
    fn displays_name_the_useful_part() {
        let e = BridgeError::TokenRejected { port: 8080, status: 403, proxy_error: Some("UNAUTHORIZED".into()) };
        assert_eq!(e.to_string(), "token rejected: HTTP 403 for port 8080 (x-aws-proxy-error: UNAUTHORIZED)");
        assert_eq!(BridgeError::PayloadTooLarge(4097).to_string(), "run-hook payload of 4097 bytes exceeds 4096");
        assert!(BridgeError::AccessDenied("get_microvm: no".into()).to_string().contains("runtime policy"));
        let pass = BridgeError::AccessDenied("run_microvm: ... not authorized to perform: iam:PassRole on resource: ...".into()).to_string();
        assert!(pass.contains("iam:PassRole on the execution role") && pass.contains("--no-execution-role") && !pass.contains("aws.env"), "{pass}");
        let pnc = BridgeError::AccessDenied("run_microvm: ... not authorized to perform: lambda:PassNetworkConnector on resource: ...".into()).to_string();
        assert!(pnc.contains("must allow lambda:PassNetworkConnector") && !pnc.contains("aws.env") && !pnc.contains("make connector-status"), "{pnc}");
        // The missing connector names the command that writes it; `make acceptance` greps the start.
        let required = BridgeError::EgressRequired.to_string();
        assert!(required.starts_with("egress connector required (") && required.ends_with("and none configured: make infra-status WRITE=1 writes [aws].egress_connector_arn"), "{required}");
    }

    /// The S8 variants name the capability or the code and the fix, and
    /// never show a secret a message may quote (a git or shim text).
    #[test]
    fn the_s8_errors_name_their_code_and_never_a_secret() {
        let token = format!("{}-{}-{}-{}", "sk", "ant", "oat01", "b".repeat(40));
        let key_id = format!("{}{}", "AKIA", "Q".repeat(16));
        let cap = BridgeError::NoCapability { cap: "workspace_v1", message: format!("404 from a shim that printed {token}") }.to_string();
        assert!(cap.contains("lacks workspace_v1") && cap.contains("make deploy") && !cap.contains(&token), "{cap}");
        let refused = BridgeError::WorkspaceRefused { code: crate::bridge::workspace::code::FINDING, message: format!("refs/heads/dev:cfg/prod.yaml line 3 holds {key_id}") }.to_string();
        assert!(refused.starts_with("workspace refused (finding): refs/heads/dev:cfg/prod.yaml") && !refused.contains(&key_id), "{refused}");
        let failed = BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: format!("git exited 128: token={token}") }.to_string();
        assert!(failed.starts_with("workspace failed (git_failed): git exited 128") && !failed.contains(&token), "{failed}");
    }

    #[test]
    fn connector_failures_of_run_microvm_ask_whether_it_is_active() {
        let v = BridgeError::Validation("Network connector arn:aws:lambda:eu-central-1:123456789012:network-connector:x is not ACTIVE".into()).to_string();
        assert!(v.ends_with("(is the egress connector ACTIVE? make connector-status)"), "{v}");
        let s = classify_service("run_microvm", Some("ResourceNotFoundException"), "Network connector arn:aws:lambda:eu-central-1:123456789012:network-connector:x not found".into()).to_string();
        assert!(s.contains("network-connector:x not found") && s.contains("make connector-status"), "{s}");
        let other = classify_service("get_microvm_image", Some("SomethingException"), "connector".into()).to_string();
        assert!(!other.contains("connector-status"), "only RunMicrovm: {other}");
        assert!(!BridgeError::Validation("runHookPayload too long".into()).to_string().contains("connector-status"));
    }

    #[test]
    fn egress_mismatch_names_both_lists_and_what_is_left() {
        let conn = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress".to_string();
        let internet = "arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS".to_string();
        let e = BridgeError::egress_mismatch("microvm-x", vec![conn.clone()], vec![internet.clone()], true).to_string();
        assert!(e.contains("echoed egress arn:") && e.contains("INTERNET_EGRESS") && e.contains("exactly arn:") && e.ends_with("; terminated"), "{e}");
        let alive = BridgeError::egress_mismatch("microvm-x", vec![conn.clone()], vec![], false).to_string();
        assert!(alive.contains("echoed egress nothing") && alive.contains("ai-env vm terminate microvm-x"), "{alive}");
        let legacy = BridgeError::egress_mismatch("microvm-x", vec![], vec![conn.clone()], true).to_string();
        assert!(legacy.contains("records no egress connector") && !legacy.contains("requires exactly"), "{legacy}");
        let id_form = BridgeError::egress_mismatch("microvm-x", vec![conn], vec!["arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-0a1b2c:1".into()], true).to_string();
        assert!(id_form.contains("if nc-0a1b2c is the connector's Id") && id_form.contains("make infra-status WRITE=1"), "{id_form}");
        // The configured ARN already in the Id form (measured live): recording the Id cannot help, so no such hint.
        let id_conn = "arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-f0b942fe-0612-44a7-9183-16942c532410".to_string();
        let named = BridgeError::egress_mismatch("microvm-x", vec![id_conn], vec!["arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress".into()], true).to_string();
        assert!(named.contains("echoed egress arn:") && !named.contains("connector's Id") && !named.contains("infra-status"), "{named}");
        let e2 = BridgeError::egress_mismatch("microvm-x", vec![internet.clone()], vec![internet], true).to_string();
        // S9's `S3` (a static op, a status and S3's code: 42 bytes) takes it from 48 to 56; still far under
        // clippy's result_large_err (128).
        assert!(std::mem::size_of::<BridgeError>() <= 56, "boxed: {}", std::mem::size_of::<BridgeError>());
        assert!(!e2.contains("connector's Id"), "{e2}");
    }
}
