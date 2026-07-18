use crate::builder::CommixBuilder;
use crate::error::CommixError;
use crate::parser::{ParseEvent, StreamParser};
use crate::types::{CommixFinding, CommixResult};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Executes Commix scans securely, managing process pipes and lifecycle.
pub struct CommixRunner {
    config: CommixBuilder,
}

impl CommixRunner {
    pub(crate) fn new(config: CommixBuilder) -> Self {
        Self { config }
    }

    /// Quote-aware splitting of binary path strings.
    fn split_command_string(input: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current_part = String::new();
        let mut in_quotes = false;
        let mut quote_char = '\0';
        let mut escape_next = false;

        for c in input.chars() {
            if escape_next {
                current_part.push(c);
                escape_next = false;
            } else if c == '\\' {
                escape_next = true;
            } else if in_quotes {
                if c == quote_char {
                    in_quotes = false;
                } else {
                    current_part.push(c);
                }
            } else if c == '"' || c == '\'' {
                in_quotes = true;
                quote_char = c;
            } else if c.is_whitespace() {
                if !current_part.is_empty() {
                    // Optimized: take string and replace it with new instead of clone and clear
                    result.push(std::mem::take(&mut current_part));
                }
            } else {
                current_part.push(c);
            }
        }
        // Handle dangling escapes or quotes securely by preserving the trailing data
        if escape_next {
            current_part.push('\\');
        }
        if !current_part.is_empty() {
            result.push(current_part);
        }
        result
    }

    /// Internal function to build the pure, isolated shell command without scan arguments.
    fn build_bare_command(&self) -> Command {
        let binary_full = self.config.binary_path.as_deref().unwrap_or("commix");
        let parts = Self::split_command_string(binary_full);

        let mut iter = parts.into_iter();
        let cmd_name = iter.next().unwrap_or_else(|| "commix".to_string());

        let mut cmd = Command::new(cmd_name);
        for arg in iter {
            cmd.arg(arg);
        }
        cmd.kill_on_drop(true);
        cmd
    }

    /// Internal function to build the shell command accurately.
    fn build_base_command(&self) -> Command {
        let mut cmd = self.build_bare_command();

        if self.config.batch {
            cmd.arg("--batch");
        }
        if self.config.offline {
            cmd.arg("--offline");
        }
        if self.config.ignore_waf {
            cmd.arg("--skip-waf");
        }

        if let Some(url) = &self.config.url {
            cmd.arg("--url").arg(url);
        }
        if let Some(method) = &self.config.method {
            cmd.arg("--method").arg(method);
        }
        if let Some(data) = &self.config.data {
            cmd.arg("--data").arg(data);
        }
        if let Some(cookie) = &self.config.cookie {
            cmd.arg("--cookie").arg(cookie);
        }
        if let Some(ua) = &self.config.user_agent {
            cmd.arg("--user-agent").arg(ua);
        }
        if let Some(proxy) = &self.config.proxy {
            cmd.arg("--proxy").arg(proxy);
        }

        if let Some(level) = self.config.level {
            cmd.arg("--level").arg(level.to_string());
        }
        if let Some(tech) = &self.config.technique {
            cmd.arg("--technique").arg(tech);
        }
        if let Some(r) = self.config.retries {
            cmd.arg("--retries").arg(r.to_string());
        }
        if let Some(nt) = self.config.network_timeout {
            cmd.arg("--timeout").arg(nt.to_string());
        }
        if let Some(delay) = self.config.delay_secs {
            cmd.arg("--delay").arg(delay.to_string());
        }
        if self.config.random_agent {
            cmd.arg("--random-agent");
        }

        for tamper in &self.config.tamper_scripts {
            cmd.arg("--tamper").arg(tamper);
        }
        for header in &self.config.headers {
            cmd.arg("--header").arg(header);
        }

        if let Some(pfx) = &self.config.prefix {
            cmd.arg("--prefix").arg(pfx);
        }
        if let Some(sfx) = &self.config.suffix {
            cmd.arg("--suffix").arg(sfx);
        }

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd
    }

    /// Core STDOUT orchestration running purely on tokio streams.
    /// Can optionally send findings into a tokio mpsc sender continuously in real-time.
    async fn parse_stream(
        &self,
        mut child: tokio::process::Child,
        tx: Option<mpsc::Sender<CommixFinding>>,
    ) -> Result<CommixResult, CommixError> {
        let stdout = child.stdout.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Failed to capture stdout")
        })?;

        let stderr_handle = child.stderr.take().map(|stderr| {
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = String::new();
                // Prevent memory exhaustion on noisy processes by limiting to 64KB
                let mut limited = stderr.take(65536);
                if limited.read_to_string(&mut buf).await.is_ok() && buf.len() == 65536 {
                    buf.push_str("\n... (stderr truncated to 64KB)\n");
                }
                buf
            })
        });

        let mut reader = BufReader::new(stdout).lines();
        let mut findings = Vec::new();
        let mut warnings = Vec::new();
        let mut execution_errors = Vec::new();

        let mut parser = StreamParser::new();

        loop {
            match reader.next_line().await {
                Ok(Some(line)) => match parser.parse_line(&line) {
                    ParseEvent::Finding(finding) => {
                        // Instantly relay payload if streaming is enabled
                        if let Some(ref sender) = tx {
                            let _ = sender.send(finding.clone()).await;
                        }
                        findings.push(finding);
                    }
                    ParseEvent::Warning(warn) => warnings.push(warn),
                    ParseEvent::Error(err) => execution_errors.push(err),
                    ParseEvent::Wait => {}
                },
                Ok(None) => break,
                Err(e) => {
                    execution_errors.push(format!("stdout read error: {e}"));
                    break;
                }
            }
        }

        let status = child.wait().await?;
        let stderr_msg = if let Some(handle) = stderr_handle {
            handle.await.unwrap_or_default()
        } else {
            String::new()
        };
        if !stderr_msg.is_empty() {
            debug!("Commix stderr: {}", stderr_msg);
        }
        if !status.success() && findings.is_empty() {
            error!("Commix exited with status {} and no findings", status);
            #[cfg(unix)]
            let signal = std::os::unix::process::ExitStatusExt::signal(&status);
            #[cfg(not(unix))]
            let signal = None;
            return Err(CommixError::ProcessFailed {
                status: status.code(),
                signal,
                stderr: stderr_msg,
            });
        }

        Ok(CommixResult {
            findings,
            warnings,
            execution_errors,
        })
    }

    /// Check if the commix binary is available on this system.
    ///
    /// Runs `commix --version` and checks if it returns successfully.
    ///
    /// # Example
    /// ```rust
    /// # use commix_rs::Commix;
    /// # async fn example() {
    /// let runner = Commix::builder().build();
    /// if runner.is_available().await {
    ///     println!("Commix is ready!");
    /// }
    /// # }
    /// ```
    pub async fn is_available(&self) -> bool {
        let mut cmd = self.build_bare_command();
        cmd.arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_ok_and(|s| s.success())
    }

    /// Get the commix version string, if available.
    ///
    /// Runs `commix --version` and captures the output.
    ///
    /// # Example
    /// ```rust
    /// # use commix_rs::Commix;
    /// # async fn example() {
    /// let runner = Commix::builder().build();
    /// if let Ok(version) = runner.version().await {
    ///     println!("Version: {}", version);
    /// }
    /// # }
    /// ```
    pub async fn version(&self) -> Result<String, CommixError> {
        let mut cmd = self.build_bare_command();
        let output = cmd
            .arg("--version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;
        if !output.status.success() {
            #[cfg(unix)]
            let signal = std::os::unix::process::ExitStatusExt::signal(&output.status);
            #[cfg(not(unix))]
            let signal = None;
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(CommixError::ProcessFailed {
                status: output.status.code(),
                signal,
                stderr,
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Execute a scan with optional timeout.
    async fn execute_with_timeout(
        &self,
        child: tokio::process::Child,
        tx: Option<mpsc::Sender<CommixFinding>>,
    ) -> Result<CommixResult, CommixError> {
        if let Some(timeout_secs) = self.config.timeout_secs {
            let timeout = std::time::Duration::from_secs(timeout_secs);
            match tokio::time::timeout(timeout, self.parse_stream(child, tx)).await {
                Ok(result) => result,
                Err(_) => Err(CommixError::Timeout),
            }
        } else {
            self.parse_stream(child, tx).await
        }
    }

    /// Returns argv flag tokens passed to the commix subprocess (program name omitted).
    ///
    /// Hidden; used by integration contract tests to assert documented CLI wiring.
    #[doc(hidden)]
    pub fn command_argv(&self) -> Vec<String> {
        self.build_base_command()
            .as_std()
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    /// Fires exactly one Commix scan asynchronously. Returns a monolithic result object at the end.
    #[tracing::instrument(skip(self), name = "commix_scan", fields(url = self.config.url.as_deref().unwrap_or("unknown")))]
    pub async fn scan(&self) -> Result<CommixResult, CommixError> {
        self.spawn_execution(None).await
    }

    /// Spawns the execution and streams vulnerabilities back immediately over a tokio channel
    /// as they are discovered, without blocking until the process finishes.
    ///
    /// # Arguments
    /// * `stream` - A `mpsc::Sender` to push `CommixFinding`s into.
    ///
    /// # Example
    /// ```rust
    /// # use commix_rs::Commix;
    /// # use tokio::sync::mpsc;
    /// # async fn example() {
    /// let runner = Commix::builder().url("http://test.com").build();
    /// let (tx, mut rx) = mpsc::channel(100);
    ///
    /// // Start stream in background
    /// tokio::spawn(async move {
    ///     let _ = runner.scan_stream(tx).await;
    /// });
    ///
    /// while let Some(finding) = rx.recv().await {
    ///     println!("Found: {}", finding.parameter);
    /// }
    /// # }
    /// ```
    pub async fn scan_stream(
        &self,
        stream: mpsc::Sender<CommixFinding>,
    ) -> Result<CommixResult, CommixError> {
        self.spawn_execution(Some(stream)).await
    }

    async fn ensure_binary_available(&self) -> Result<(), CommixError> {
        let mut cmd = self.build_bare_command();
        match cmd
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
        {
            Ok(status) if status.success() => Ok(()),
            Ok(_) => Err(CommixError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "commix --version failed (binary present but not runnable)",
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(CommixError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "commix binary not found in PATH or configured path",
                )))
            }
            Err(e) => Err(CommixError::Io(e)),
        }
    }

    async fn spawn_execution(
        &self,
        tx: Option<mpsc::Sender<CommixFinding>>,
    ) -> Result<CommixResult, CommixError> {
        self.ensure_binary_available().await?;

        let mut cmd = self.build_base_command();
        // Fire child process safely
        debug!("Spawning commix process: {:?}", cmd);
        let child = cmd.spawn().map_err(|e| {
            error!("Failed to spawn commix process: {}", e);
            CommixError::Io(e)
        })?;

        info!("Commix process spawned successfully. Awaiting results...");
        self.execute_with_timeout(child, tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Commix;

    #[test]
    fn builder_creates_runner() {
        let runner = Commix::builder()
            .url("http://localhost/test.php?v=1")
            .timeout_secs(30)
            .level(3)
            .cookie("session=abc")
            .build();
        let _ = runner;
    }

    #[test]
    fn result_empty_findings() {
        let result = CommixResult {
            findings: vec![],
            warnings: vec![],
            execution_errors: vec![],
        };
        assert!(!result.is_vulnerable());
    }

    #[test]
    fn test_build_base_command() {
        let runner = Commix::builder()
            .url("http://test.com?q=1")
            .data("hello=world")
            .level(2)
            .ignore_waf(true)
            .tamper_script("space2hash")
            .header("X-Custom: 1")
            .delay_secs(3)
            .build();

        let cmd = runner.build_base_command();
        let cmd_str = format!("{cmd:?}");

        assert!(cmd_str.contains("--url\" \"http://test.com?q=1\""));
        assert!(cmd_str.contains("--data\" \"hello=world\""));
        assert!(cmd_str.contains("--level\" \"2\""));
        assert!(cmd_str.contains("--skip-waf"));
        assert!(!cmd_str.contains("--threads"));
        assert!(cmd_str.contains("--tamper\" \"space2hash\""));
        assert!(cmd_str.contains("--header\" \"X-Custom: 1\""));
        assert!(cmd_str.contains("--delay\" \"3\""));
        assert!(cmd_str.contains("--batch"));
    }

    #[test]
    fn process_failed_preserves_exit_code_without_fabricating_minus_one() {
        let err = CommixError::ProcessFailed {
            status: Some(2),
            signal: None,
            stderr: String::new(),
        };
        assert!(err.to_string().contains("Some(2)"));
        let err = CommixError::ProcessFailed {
            status: None,
            signal: Some(9),
            stderr: String::new(),
        };
        assert!(err.to_string().contains("Some(9)"));
    }

    #[tokio::test]
    async fn parse_stream_process_failed_includes_stderr() {
        let runner = Commix::builder().build();
        let child = tokio::process::Command::new("bash")
            .arg("-c")
            .arg("echo commix-rs-stderr-marker 1>&2; exit 1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("bash required for stderr capture test");

        let err = runner.parse_stream(child, None).await.unwrap_err();
        match err {
            CommixError::ProcessFailed { stderr, .. } => {
                assert!(
                    stderr.contains("commix-rs-stderr-marker"),
                    "expected stderr in ProcessFailed, got {stderr:?}"
                );
            }
            other => panic!("expected ProcessFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn ensure_binary_available_distinguishes_version_failure_from_not_found() {
        let dir = std::env::temp_dir().join(format!("commix_rs_preflight_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let script = dir.join("fake_commix.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 1\n").expect("write fake commix script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake commix script");
        }

        let runner = Commix::builder()
            .url("http://example.com")
            .binary_path(script.to_string_lossy().into_owned())
            .build();
        let err = runner.scan().await.unwrap_err();
        match err {
            CommixError::Io(e) => {
                assert_ne!(
                    e.kind(),
                    std::io::ErrorKind::NotFound,
                    "version failure must not be reported as NotFound"
                );
                assert!(
                    e.to_string().contains("--version failed"),
                    "expected version failure message, got {e}"
                );
            }
            other => panic!("expected Io version failure, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn parse_stream_invalid_utf8_records_execution_error() {
        let runner = Commix::builder().build();
        let child = tokio::process::Command::new("bash")
            .arg("-c")
            .arg("printf '\\xff\\xfe\\n'; exit 0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("bash required for invalid-utf8 test");

        let result = runner.parse_stream(child, None).await.unwrap();
        assert!(
            result
                .execution_errors
                .iter()
                .any(|e| e.contains("stdout read error")),
            "expected stdout read error, got {:?}",
            result.execution_errors
        );
    }

    #[test]
    fn test_binary_path_splitting() {
        let runner = Commix::builder()
            .binary_path("python3 \"/opt/Security Tools/commix/commix.py\"")
            .build();
        let cmd = runner.build_bare_command();
        let cmd_str = format!("{cmd:?}");

        // Ensure "python3" is the binary and "/opt/Security Tools/commix/commix.py" is the first argument
        assert!(
            cmd_str.contains("python3") && cmd_str.contains("/opt/Security Tools/commix/commix.py")
        );
    }
}
