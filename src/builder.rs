use crate::runner::CommixRunner;
use base64::Engine;

/// A builder to configure Commix execution orchestration securely.
#[derive(Debug, Clone, Default)]
pub struct CommixBuilder {
    pub(crate) binary_path: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) data: Option<String>,
    pub(crate) cookie: Option<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) headers: Vec<String>,
    pub(crate) proxy: Option<String>,
    pub(crate) level: Option<u8>,
    pub(crate) technique: Option<String>,
    pub(crate) tamper_scripts: Vec<String>,
    pub(crate) timeout_secs: Option<u64>,
    /// Seconds to delay between each HTTP request (`commix --delay`).
    pub(crate) delay_secs: Option<u64>,
    pub(crate) retries: Option<u8>,
    pub(crate) network_timeout: Option<u64>,
    pub(crate) random_agent: bool,
    pub(crate) batch: bool,
    pub(crate) ignore_waf: bool,
    pub(crate) prefix: Option<String>,
    pub(crate) suffix: Option<String>,
    pub(crate) offline: bool,
}

impl CommixBuilder {
    /// Creates a new, default configuration builder for Commix.
    /// Batch mode is enabled by default to ensure programmatic safety.
    pub fn new() -> Self {
        Self {
            batch: true, // Always default to batch mode for programmatic use
            ..Default::default()
        }
    }

    /// Sets a custom binary path (if not in the system PATH).
    pub fn binary_path(mut self, path: impl Into<String>) -> Self {
        self.binary_path = Some(path.into());
        self
    }

    /// Sets the target URL for the scan.
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Sets the HTTP method manually.
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Sets raw POST data string for testing.
    pub fn data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Sets the HTTP cookie header to use.
    pub fn cookie(mut self, cookie: impl Into<String>) -> Self {
        self.cookie = Some(cookie.into());
        self
    }

    /// Sets the User-Agent header.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Adds a custom HTTP header. Can be called multiple times.
    pub fn header(mut self, header: impl Into<String>) -> Self {
        self.headers.push(header.into());
        self
    }

    /// Convenience method to add a Bearer token authorization header.
    pub fn auth_bearer(mut self, token: impl AsRef<str>) -> Self {
        self.headers
            .push(format!("Authorization: Bearer {}", token.as_ref()));
        self
    }

    /// Convenience method to add a Basic authorization header.
    pub fn auth_basic(mut self, username: &str, password: &str) -> Self {
        let creds = format!("{username}:{password}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        self.headers.push(format!("Authorization: Basic {b64}"));
        self
    }

    /// Sets a proxy (e.g. `http://127.0.0.1:8080`).
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Sets the test level (1-3, default 1).
    pub fn level(mut self, level: u8) -> Self {
        self.level = Some(level);
        self
    }

    /// Specifies injection technique codes for `commix --technique`.
    ///
    /// Commix uses single-letter codes: `c` (classic/result-based), `e` (eval-based),
    /// `t` (time-based blind), `f` (file-based).
    /// Combine codes as a string (e.g. `"ctef"`).
    pub fn technique(mut self, technique: impl Into<String>) -> Self {
        self.technique = Some(technique.into());
        self
    }

    /// Specifies an evasion or tamper script file. Can be called multiple times.
    pub fn tamper_script(mut self, script: impl Into<String>) -> Self {
        self.tamper_scripts.push(script.into());
        self
    }

    /// Overrides the execution runtime constraint (Tokio max execution time).
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    /// Overrides the Commix engine connection timeout (seconds).
    pub fn network_timeout(mut self, secs: u64) -> Self {
        self.network_timeout = Some(secs);
        self
    }

    /// Deprecated: commix has no `--threads` flag; retained for API compatibility.
    #[deprecated(since = "0.0.3", note = "commix has no --threads flag; method is a no-op")]
    pub fn threads(self, _count: u8) -> Self {
        self
    }

    /// Sets retry count on connection drops.
    pub fn retries(mut self, count: u8) -> Self {
        self.retries = Some(count);
        self
    }

    /// Randomizes the User-Agent header automatically (evasion capability).
    pub fn random_agent(mut self, enable: bool) -> Self {
        self.random_agent = enable;
        self
    }

    /// Seconds to delay between each HTTP request (`commix --delay`).
    pub fn delay_secs(mut self, secs: u64) -> Self {
        self.delay_secs = Some(secs);
        self
    }

    /// Deprecated alias for [`Self::delay_secs`].
    ///
    /// Commix's `--delay` flag is in seconds, not milliseconds. Prefer
    /// [`Self::delay_secs`].
    #[deprecated(since = "0.0.1", note = "use delay_secs; commix --delay is in seconds")]
    pub fn delay_ms(self, secs: u64) -> Self {
        self.delay_secs(secs)
    }

    /// Enables or disables batch orchestration (default: true).
    pub fn batch(mut self, batch: bool) -> Self {
        self.batch = batch;
        self
    }

    /// Disables heuristics designed to identify WAFs.
    pub fn ignore_waf(mut self, ignore: bool) -> Self {
        self.ignore_waf = ignore;
        self
    }

    /// Injects a fixed prefix into payloads.
    pub fn prefix(mut self, pfx: impl Into<String>) -> Self {
        self.prefix = Some(pfx.into());
        self
    }

    /// Injects a fixed suffix into payloads.
    pub fn suffix(mut self, sfx: impl Into<String>) -> Self {
        self.suffix = Some(sfx.into());
        self
    }

    /// Operates offline, skipping external lookups.
    pub fn offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Freezes the configuration and constructs a [`CommixRunner`] ready for execution.
    pub fn build(self) -> CommixRunner {
        CommixRunner::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = CommixBuilder::new();
        assert!(builder.batch);
        assert!(builder.timeout_secs.is_none());
    }

    #[test]
    fn test_builder_chaining() {
        let builder = CommixBuilder::new()
            .url("http://test.com")
            .level(3)
            .technique("t")
            .ignore_waf(true)
            .batch(false)
            .cookie("session=123")
            .method("POST")
            .data("a=1")
            .delay_secs(2);

        assert_eq!(builder.url.unwrap(), "http://test.com");
        assert_eq!(builder.level.unwrap(), 3);
        assert_eq!(builder.technique.unwrap(), "t");
        assert!(builder.ignore_waf);
        assert!(!builder.batch);
        assert_eq!(builder.cookie.unwrap(), "session=123");
        assert_eq!(builder.method.unwrap(), "POST");
        assert_eq!(builder.data.unwrap(), "a=1");
        assert_eq!(builder.delay_secs.unwrap(), 2);
    }

    #[test]
    fn auth_basic_encodes_standard_base64() {
        let builder = CommixBuilder::new().auth_basic("user", "pass");
        assert_eq!(
            builder.headers,
            vec!["Authorization: Basic dXNlcjpwYXNz".to_string()]
        );
    }
}
