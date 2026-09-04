//! CLI error with a stable exit code (carried verbatim from menv v1):
//! 0 ok (incl. broken pipe) · 1 generic · 2 usage (clap) · 3 cancelled ·
//! 4 no key / not your key · 5 auth unavailable · 6 corrupt file.
//!
//! INVARIANT: exit codes 4 and 6 are decided by ai-env's OWN pre-flight
//! (container predicate + ai-env-age tag match) and must NEVER be inferred
//! from age's stderr — age exits 1 for everything, `NoIdentityMatchError`
//! has singular and plural wordings, and the plugin's cancel text is a
//! locale-dependent Swift `localizedDescription`. Stderr classification is
//! allowed only for exit 5 (plugin missing) and best-effort exit 3 (cancel).
use ai_env_age::ParseError;

#[derive(Debug)]
pub enum CliError {
    Msg(String),             // 1
    Usage(String),           // 2 (same class as clap usage errors)
    Cancelled,               // 3
    NoKey(String),           // 4
    AuthUnavailable(String), // 5
    Corrupt(String),         // 6
    BrokenPipe,              // treated as success
}

pub type Result<T> = std::result::Result<T, CliError>;

impl CliError {
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::BrokenPipe => 0,
            CliError::Msg(_) => 1,
            CliError::Usage(_) => 2,
            CliError::Cancelled => 3,
            CliError::NoKey(_) => 4,
            CliError::AuthUnavailable(_) => 5,
            CliError::Corrupt(_) => 6,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Msg(m) | CliError::Usage(m) | CliError::NoKey(m)
            | CliError::AuthUnavailable(m) | CliError::Corrupt(m) => f.write_str(m),
            CliError::Cancelled => f.write_str("cancelled"),
            CliError::BrokenPipe => f.write_str("broken pipe"),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            CliError::BrokenPipe
        } else {
            CliError::Msg(e.to_string())
        }
    }
}

impl From<ParseError> for CliError {
    fn from(e: ParseError) -> Self {
        CliError::Corrupt(format!("encrypted payload is not valid age data: {e}"))
    }
}

/// Convenience for `format!`-style one-offs.
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::errors::CliError::Msg(format!($($arg)*)))
    };
}
