//! Errors and codes (plans/s13-contracts.md §P-proto-sdk.6.2, P-R30 and P-R32).

use std::fmt;

use crate::Redactor;

/// The most bytes of an error message on the wire (P-R32).
pub const MESSAGE_MAX: usize = 1024;

/// google.rpc.Code: the numbering of `Error.code` and of gRPC statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Code {
    /// 0 OK.
    Ok = 0,
    /// 1 CANCELLED.
    Cancelled = 1,
    /// 2 UNKNOWN.
    Unknown = 2,
    /// 3 INVALID_ARGUMENT.
    InvalidArgument = 3,
    /// 4 DEADLINE_EXCEEDED.
    DeadlineExceeded = 4,
    /// 5 NOT_FOUND.
    NotFound = 5,
    /// 6 ALREADY_EXISTS.
    AlreadyExists = 6,
    /// 7 PERMISSION_DENIED.
    PermissionDenied = 7,
    /// 8 RESOURCE_EXHAUSTED.
    ResourceExhausted = 8,
    /// 9 FAILED_PRECONDITION.
    FailedPrecondition = 9,
    /// 10 ABORTED.
    Aborted = 10,
    /// 11 OUT_OF_RANGE.
    OutOfRange = 11,
    /// 12 UNIMPLEMENTED.
    Unimplemented = 12,
    /// 13 INTERNAL.
    Internal = 13,
    /// 14 UNAVAILABLE.
    Unavailable = 14,
    /// 15 DATA_LOSS.
    DataLoss = 15,
    /// 16 UNAUTHENTICATED.
    Unauthenticated = 16,
}

impl Code {
    /// Every code, in number order.
    pub const ALL: [Code; 17] = [
        Code::Ok,
        Code::Cancelled,
        Code::Unknown,
        Code::InvalidArgument,
        Code::DeadlineExceeded,
        Code::NotFound,
        Code::AlreadyExists,
        Code::PermissionDenied,
        Code::ResourceExhausted,
        Code::FailedPrecondition,
        Code::Aborted,
        Code::OutOfRange,
        Code::Unimplemented,
        Code::Internal,
        Code::Unavailable,
        Code::DataLoss,
        Code::Unauthenticated,
    ];

    /// The code's number.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The code of a number; `None` outside 0..=16.
    #[must_use]
    pub const fn from_i32(n: i32) -> Option<Code> {
        match n {
            0..=16 => Some(Code::ALL[n as usize]),
            _ => None,
        }
    }

    /// google.rpc's name: `OK`, `CANCELLED`, … `UNAUTHENTICATED`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Code::Ok => "OK",
            Code::Cancelled => "CANCELLED",
            Code::Unknown => "UNKNOWN",
            Code::InvalidArgument => "INVALID_ARGUMENT",
            Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Code::NotFound => "NOT_FOUND",
            Code::AlreadyExists => "ALREADY_EXISTS",
            Code::PermissionDenied => "PERMISSION_DENIED",
            Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Code::FailedPrecondition => "FAILED_PRECONDITION",
            Code::Aborted => "ABORTED",
            Code::OutOfRange => "OUT_OF_RANGE",
            Code::Unimplemented => "UNIMPLEMENTED",
            Code::Internal => "INTERNAL",
            Code::Unavailable => "UNAVAILABLE",
            Code::DataLoss => "DATA_LOSS",
            Code::Unauthenticated => "UNAUTHENTICATED",
        }
    }
}

/// A source's error. Its message reaches the agent (P-R32): never a credential, a connection string or a
/// whole backend reply.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceError {
    /// The params are wrong (INVALID_ARGUMENT).
    InvalidArgument(String),
    /// No such op, row or object (NOT_FOUND).
    NotFound(String),
    /// The backend refused (PERMISSION_DENIED).
    PermissionDenied(String),
    /// A quota or a cap (RESOURCE_EXHAUSTED).
    ResourceExhausted(String),
    /// The backend is not in a state to answer (FAILED_PRECONDITION).
    FailedPrecondition(String),
    /// The backend does not answer (UNAVAILABLE).
    Unavailable(String),
    /// The call's deadline passed (DEADLINE_EXCEEDED).
    DeadlineExceeded,
    /// The call was cancelled (CANCELLED).
    Cancelled,
    /// A fault of the source itself (INTERNAL).
    Internal(String),
}

impl SourceError {
    /// The error's code (P-R30).
    #[must_use]
    pub const fn code(&self) -> Code {
        match self {
            SourceError::InvalidArgument(_) => Code::InvalidArgument,
            SourceError::NotFound(_) => Code::NotFound,
            SourceError::PermissionDenied(_) => Code::PermissionDenied,
            SourceError::ResourceExhausted(_) => Code::ResourceExhausted,
            SourceError::FailedPrecondition(_) => Code::FailedPrecondition,
            SourceError::Unavailable(_) => Code::Unavailable,
            SourceError::DeadlineExceeded => Code::DeadlineExceeded,
            SourceError::Cancelled => Code::Cancelled,
            SourceError::Internal(_) => Code::Internal,
        }
    }

    /// The variant's text; empty for `DeadlineExceeded` and `Cancelled`.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            SourceError::InvalidArgument(m)
            | SourceError::NotFound(m)
            | SourceError::PermissionDenied(m)
            | SourceError::ResourceExhausted(m)
            | SourceError::FailedPrecondition(m)
            | SourceError::Unavailable(m)
            | SourceError::Internal(m) => m,
            SourceError::DeadlineExceeded | SourceError::Cancelled => "",
        }
    }

    /// The message as it goes on the wire (P-R32): redacted first, then cut to at most `MESSAGE_MAX`
    /// bytes at a char boundary.
    #[must_use]
    pub fn wire_message(&self, redactor: &Redactor) -> String {
        let redacted = redactor.redact(self.message());
        let mut end = redacted.len().min(MESSAGE_MAX);
        while !redacted.is_char_boundary(end) {
            end -= 1;
        }
        redacted[..end].to_string()
    }
}

impl fmt::Display for SourceError {
    /// `<NAME>` for `DeadlineExceeded` and `Cancelled`, else `<NAME>: <message>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceError::DeadlineExceeded | SourceError::Cancelled => f.write_str(self.code().name()),
            _ => write!(f, "{}: {}", self.code().name(), self.message()),
        }
    }
}

impl std::error::Error for SourceError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JWT-shaped run, built at run time (P-R82's shape).
    fn jwt() -> String {
        ["eyJ", &"a".repeat(17), ".", &"b".repeat(20), ".", &"c".repeat(20)].concat()
    }

    /// P-T16.
    #[test]
    fn every_error_maps_to_its_grpc_code() {
        let x = || "x".to_string();
        let rows = [
            (SourceError::InvalidArgument(x()), Code::InvalidArgument, 3, "INVALID_ARGUMENT: x"),
            (SourceError::NotFound(x()), Code::NotFound, 5, "NOT_FOUND: x"),
            (SourceError::PermissionDenied(x()), Code::PermissionDenied, 7, "PERMISSION_DENIED: x"),
            (SourceError::ResourceExhausted(x()), Code::ResourceExhausted, 8, "RESOURCE_EXHAUSTED: x"),
            (SourceError::FailedPrecondition(x()), Code::FailedPrecondition, 9, "FAILED_PRECONDITION: x"),
            (SourceError::Unavailable(x()), Code::Unavailable, 14, "UNAVAILABLE: x"),
            (SourceError::DeadlineExceeded, Code::DeadlineExceeded, 4, "DEADLINE_EXCEEDED"),
            (SourceError::Cancelled, Code::Cancelled, 1, "CANCELLED"),
            (SourceError::Internal(x()), Code::Internal, 13, "INTERNAL: x"),
        ];
        for (e, code, n, shown) in rows {
            assert_eq!((e.code(), e.code().as_i32(), e.to_string()), (code, n, shown.to_string()));
            let message = if matches!(e, SourceError::DeadlineExceeded | SourceError::Cancelled) { "" } else { "x" };
            assert_eq!(e.message(), message);
        }
        for (n, code) in (0..=16).zip(Code::ALL) {
            assert_eq!(Code::from_i32(n), Some(code));
            assert_eq!(code.as_i32(), n);
        }
        assert_eq!(Code::from_i32(17), None);
        assert_eq!(Code::from_i32(-1), None);
        let names: Vec<_> = Code::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            [
                "OK",
                "CANCELLED",
                "UNKNOWN",
                "INVALID_ARGUMENT",
                "DEADLINE_EXCEEDED",
                "NOT_FOUND",
                "ALREADY_EXISTS",
                "PERMISSION_DENIED",
                "RESOURCE_EXHAUSTED",
                "FAILED_PRECONDITION",
                "ABORTED",
                "OUT_OF_RANGE",
                "UNIMPLEMENTED",
                "INTERNAL",
                "UNAVAILABLE",
                "DATA_LOSS",
                "UNAUTHENTICATED",
            ]
        );
    }

    /// P-T17.
    #[test]
    fn wire_messages_are_redacted_then_capped() {
        let redactor = Redactor::new();
        let e = SourceError::Unavailable(format!("backend said {} twice", jwt()));
        assert_eq!(e.wire_message(&redactor), "backend said [redacted:jwt] twice");

        let e = SourceError::Internal("\u{e9}".repeat(2000));
        let wire = e.wire_message(&redactor);
        assert_eq!(wire.len(), MESSAGE_MAX);
        assert!(wire.chars().all(|c| c == '\u{e9}'), "cut on a char boundary");
        let e = SourceError::Internal(["x", &"\u{e9}".repeat(1000)].concat());
        let wire = e.wire_message(&redactor);
        assert_eq!(wire.len(), MESSAGE_MAX - 1, "the cut steps back to the char boundary");

        // The token straddles byte MESSAGE_MAX: masked first, so no raw byte of it survives the cut.
        let e = SourceError::FailedPrecondition(format!("{} {}", "x".repeat(1000), jwt()));
        let wire = e.wire_message(&redactor);
        assert!(wire.ends_with(" [redacted:jwt]"), "{wire}");
        assert!(!wire.contains("eyJ"), "{wire}");
        assert_eq!(SourceError::Cancelled.wire_message(&redactor), "");
        assert_eq!(SourceError::NotFound(jwt()).wire_message(&Redactor::none()), jwt());
    }
}
