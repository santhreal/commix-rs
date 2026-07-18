//! # Commix-RS
//!
//! An asynchronous, type-safe Rust wrapper for `commix` (Command Injection Exploiter).
//!
//! Provides a programmatic API for orchestrating OS Command Injection scans without manual CLI parsing,
//! designed to integrate with automated threat intelligence pipelines and reconnaissance orchestrators.
//!
//! ## Example
//! ```rust
//! # use commix_rs::Commix;
//! # async fn example() {
//! let runner = Commix::builder()
//!     .url("http://example.com/vulnerable.php?id=1")
//!     .batch(true) // Automatically skip user prompts
//!     .level(3)    // Aggressive testing
//!     .build();
//!
//! let result = runner.scan().await.unwrap();
//! if result.is_vulnerable() {
//!     println!("Vulnerable parameters: {:?}", result.findings);
//! }
//! # }
//! ```
//!
//! ## Safe defaults
//!
//! - **Input size:** No cap on URL, data, cookie, or header strings passed to the builder. Stderr
//!   captured from the commix subprocess is hard-limited to 64 KB (`stderr.take(65536)` in
//!   `runner::CommixRunner::parse_stream`); bytes beyond that are discarded and a truncation note
//!   is appended.
//! - **Recursion depth:** This crate contains no recursive algorithms. The stream parser is a flat
//!   state machine; the builder and runner use only iterative loops.
//! - **Outbound network:** This crate makes no outbound network connections itself. All HTTP traffic
//!   is performed by the `commix` subprocess; network behaviour is entirely controlled by the
//!   operator-supplied `commix` binary and the URL/proxy/timeout arguments passed to it.
//! - **Process spawning:** Each `scan()` / `scan_stream()` call runs a `--version` preflight
//!   (`commix --version`) to verify the binary, then spawns the scan subprocess (two child
//!   processes per call). The scan child is created with `kill_on_drop(true)` so it is terminated
//!   when the `CommixRunner` is dropped. No shell is involved; arguments are passed as discrete
//!   `OsStr` tokens to avoid shell injection.
//! - **Filesystem writes:** This crate writes nothing to disk. Temporary files, session databases,
//!   and scan logs are the sole responsibility of the `commix` subprocess operating in its own
//!   working directory.
//! - **Credential exposure:** Cookies, bearer tokens, and basic-auth credentials supplied via the
//!   builder are forwarded to `commix` as command-line arguments. These values may appear in the
//!   OS process table for the lifetime of the subprocess. They are not emitted at `tracing` info
//!   or debug level by this crate.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::return_self_not_must_use,
    clippy::struct_excessive_bools,
    clippy::struct_field_names
)]

/// Builder pattern for Commix configuration
pub mod builder;
/// Typed errors for Commix wrapper
pub mod error;
/// Stateful stdout stream parsing
pub mod parser;
/// Execution and orchestration engine
pub mod runner;
/// Shared data structures and finding types
pub mod types;

pub use builder::CommixBuilder;
pub use error::CommixError;
pub use runner::CommixRunner;
pub use types::{CommixFinding, CommixResult, Confidence, Technique};

/// Main facade for the initial orchestration logic.
pub struct Commix;

impl Commix {
    /// Returns a new configuration builder for a Commix run.
    pub fn builder() -> CommixBuilder {
        CommixBuilder::new()
    }

    /// A convenience method to instantly scan a URL using batch settings.
    pub async fn scan_url(url: impl Into<String>) -> Result<CommixResult, CommixError> {
        Self::builder().url(url).build().scan().await
    }
}
