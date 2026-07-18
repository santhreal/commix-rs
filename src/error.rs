use std::fmt;

/// Core error types for the Commix wrapper.
#[derive(Debug)]
#[non_exhaustive]
pub enum CommixError {
    /// An IO error occurred, likely related to the process spawn.
    Io(std::io::Error),

    /// Reserved for future JSON deserialization paths; not constructed by scan/runner today.
    Json(serde_json::Error),

    /// Commix process exited with a failure status and no findings.
    ///
    /// When the child is terminated by a signal (Unix), `status` is `None` and
    /// `signal` carries the signal number. When the child exits normally,
    /// `status` is the exit code and `signal` is `None`. `stderr` holds captured
    /// subprocess stderr when available (may be empty).
    ProcessFailed {
        /// Exit code when the process exited normally; `None` if killed by signal.
        status: Option<i32>,
        /// Unix signal number when the process was terminated by signal.
        signal: Option<i32>,
        /// Captured stderr from the child process (may be empty).
        stderr: String,
    },

    /// A configured timeout was reached before the scan completed.
    Timeout,

    /// Reserved for parameter validation failures.
    Validation(String),
}

impl fmt::Display for CommixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Json(e) => write!(f, "JSON parsing error: {e}"),
            Self::ProcessFailed {
                status,
                signal,
                stderr,
            } => {
                write!(
                    f,
                    "Commix process failed (exit code: {status:?}, signal: {signal:?})"
                )?;
                if !stderr.is_empty() {
                    write!(f, ": {stderr}")?;
                }
                Ok(())
            }
            Self::Timeout => write!(f, "Execution timed out"),
            Self::Validation(msg) => write!(f, "Validation error: {msg}"),
        }
    }
}

impl std::error::Error for CommixError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CommixError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for CommixError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
