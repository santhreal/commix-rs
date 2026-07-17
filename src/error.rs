use thiserror::Error;

/// Core error types for the Commix wrapper.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CommixError {
    /// An IO error occurred, likely related to the process spawn.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or parsing error.
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    /// Commix process exited with a failure status and no findings.
    ///
    /// When the child is terminated by a signal (Unix), `status` is `None` and
    /// `signal` carries the signal number. When the child exits normally,
    /// `status` is the exit code and `signal` is `None`.
    #[error("Commix process failed (exit code: {status:?}, signal: {signal:?})")]
    ProcessFailed {
        /// Exit code when the process exited normally; `None` if killed by signal.
        status: Option<i32>,
        /// Unix signal number when the process was terminated by signal.
        signal: Option<i32>,
    },

    /// A configured timeout was reached before the scan completed.
    #[error("Execution timed out")]
    Timeout,

    /// Validation error for invalid parameters.
    #[error("Validation error: {0}")]
    Validation(String),
}
