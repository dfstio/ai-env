//! Bridge errors, mapped onto the CLI exit taxonomy: 7 AWS/infra, 8 VM lost,
//! 9 policy, 5 credentials unavailable, 1 everything else.
use crate::errors::CliError;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum BridgeError {
    // exit 7
    Sdk { op: &'static str, message: String },
    Quota(String),
    Validation(String),
    Http { status: u16, body: String },
    // exit 5
    CredentialsUnavailable(String),
    // exit 8
    Transport(String),
    Terminated(String),
    Gap { spawn_id: String, from_seq: u64 },
    Protocol(String),
    // exit 9
    Tripwire(String),
    SettingsWidening(String),
    EgressRequired,
    OutsideRoots(PathBuf),
    PayloadTooLarge(usize),
    MaxConcurrent(u32),
    // exit 1
    Config(String),
    Io(std::io::Error),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeError::Sdk { op, message } => write!(f, "aws {op}: {message}"),
            BridgeError::Quota(m) => write!(f, "aws quota: {m}"),
            BridgeError::Validation(m) => write!(f, "aws validation: {m}"),
            BridgeError::Http { status, body } => write!(f, "endpoint HTTP {status}: {body}"),
            BridgeError::CredentialsUnavailable(m) => write!(f, "credentials unavailable: {m}"),
            BridgeError::Transport(m) => write!(f, "transport: {m}"),
            BridgeError::Terminated(m) => write!(f, "microvm terminated: {m}"),
            BridgeError::Gap { spawn_id, from_seq } => write!(f, "replay gap for spawn {spawn_id} from seq {from_seq}"),
            BridgeError::Protocol(m) => write!(f, "shim protocol: {m}"),
            BridgeError::Tripwire(m) => write!(f, "tripwire: {m}"),
            BridgeError::SettingsWidening(m) => write!(f, "repo settings widen permissions: {m}"),
            BridgeError::EgressRequired => f.write_str("egress connector required ([egress].require=true) and none configured"),
            BridgeError::OutsideRoots(p) => write!(f, "{} is outside [workspaces].roots", p.display()),
            BridgeError::PayloadTooLarge(n) => write!(f, "run-hook payload of {n} bytes exceeds 4096"),
            BridgeError::MaxConcurrent(n) => write!(f, "[vm].max_concurrent={n} reached"),
            BridgeError::Config(m) => write!(f, "config: {m}"),
            BridgeError::Io(e) => write!(f, "{e}"),
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
            BridgeError::Sdk { .. } | BridgeError::Quota(_) | BridgeError::Validation(_) | BridgeError::Http { .. } => {
                CliError::Aws(text)
            }
            BridgeError::CredentialsUnavailable(_) => CliError::AuthUnavailable(text),
            BridgeError::Transport(_) | BridgeError::Terminated(_) | BridgeError::Gap { .. } | BridgeError::Protocol(_) => {
                CliError::VmLost(text)
            }
            BridgeError::Tripwire(_)
            | BridgeError::SettingsWidening(_)
            | BridgeError::EgressRequired
            | BridgeError::OutsideRoots(_)
            | BridgeError::PayloadTooLarge(_)
            | BridgeError::MaxConcurrent(_) => CliError::Policy(text),
            BridgeError::Config(_) => CliError::Msg(text),
            BridgeError::Io(io) => CliError::from(io),
        }
    }
}

/// Map an SDK error: construction failures that mention credentials become
/// exit 5; quota/validation service errors are classified; the rest is exit 7.
pub fn map_sdk_error<E, R>(op: &'static str, e: aws_sdk_lambdamicrovms::error::SdkError<E, R>) -> BridgeError
where
    E: fmt::Debug + fmt::Display,
    R: fmt::Debug,
{
    use aws_sdk_lambdamicrovms::error::SdkError;
    match &e {
        SdkError::ConstructionFailure(_) => {
            let text = format!("{e:?}");
            if text.to_ascii_lowercase().contains("credential") {
                return BridgeError::CredentialsUnavailable(text);
            }
            BridgeError::Sdk { op, message: text }
        }
        SdkError::ServiceError(se) => {
            let message = se.err().to_string();
            let lower = message.to_ascii_lowercase();
            if lower.contains("quota") || lower.contains("limit exceeded") {
                BridgeError::Quota(message)
            } else if lower.contains("validation") {
                BridgeError::Validation(message)
            } else {
                BridgeError::Sdk { op, message }
            }
        }
        other => BridgeError::Sdk { op, message: format!("{other:?}") },
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
            (BridgeError::CredentialsUnavailable("c".into()), 5),
            (BridgeError::Transport("t".into()), 8),
            (BridgeError::Gap { spawn_id: "s".into(), from_seq: 1 }, 8),
            (BridgeError::Tripwire("AKIA".into()), 9),
            (BridgeError::EgressRequired, 9),
            (BridgeError::MaxConcurrent(3), 9),
            (BridgeError::Config("bad".into()), 1),
            (BridgeError::Io(std::io::Error::other("io")), 1),
        ];
        for (e, code) in cases {
            let text = e.to_string();
            let c: CliError = e.into();
            assert_eq!(c.exit_code(), code, "{text}");
        }
    }
}
