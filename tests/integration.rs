/// Integration tests: end-to-end exercise of the public API surface.
///
/// These tests drive the full public API - builder -> runner - using only
/// behaviours observable without a live commix binary (binary-availability
/// checks, argument-wiring verification, stream-parsing pipelines, etc.).
use commix_rs::{
    parser::{ParseEvent, StreamParser},
    Commix, CommixBuilder, CommixError, CommixFinding, CommixResult, Confidence, Technique,
};

// ---- Commix facade ----

#[test]
fn commix_builder_returns_builder() {
    let _builder = Commix::builder();
    // If we reach here the facade compiled and returned a value.
}

#[tokio::test]
async fn commix_is_available_false_for_nonexistent_binary() {
    let runner = Commix::builder()
        .binary_path("/nonexistent-commix-xyz")
        .build();
    assert!(
        !runner.is_available().await,
        "missing binary must report unavailable"
    );
}

#[tokio::test]
async fn commix_scan_url_returns_error_when_binary_absent() {
    // If commix is not installed, scan_url must fail gracefully (Io error, not panic).
    let result = Commix::scan_url("http://localhost/page?id=1").await;
    if let Err(e) = result {
        match e {
            CommixError::Io(_) | CommixError::ProcessFailed { .. } | CommixError::Timeout => {}
            _ => panic!("unexpected error variant for missing binary: {e}"),
        }
    }
    // If commix IS installed (unlikely in CI), the result may be Ok or Err - either is fine.
}

// ---- Builder → Runner wiring ----

#[test]
fn builder_build_produces_runner() {
    // Just verify the builder chain compiles and build() completes without panic.
    let _runner = Commix::builder()
        .url("http://example.com/page?id=1")
        .method("GET")
        .level(2)
        .timeout_secs(60)
        .batch(true)
        .build();
}

#[test]
#[allow(deprecated)]
fn builder_all_fields_accepted_without_panic() {
    // Verify that all builder methods accept their values without panicking.
    let _runner = CommixBuilder::new()
        .url("http://target.com?q=1")
        .method("POST")
        .data("param=value")
        .cookie("session=abc")
        .user_agent("TestAgent/1.0")
        .header("X-Custom: yes")
        .proxy("http://127.0.0.1:8080")
        .level(3)
        .technique("ctef")
        .tamper_script("space2hash")
        .timeout_secs(30)
        .network_timeout(10)
        .threads(4)
        .retries(2)
        .delay_secs(1)
        .random_agent(true)
        .ignore_waf(true)
        .prefix(";")
        .suffix("#")
        .offline(true)
        .batch(true)
        .build();
}

#[test]
fn builder_batch_false_builds_without_panic() {
    // batch=false must be accepted by build()
    let _runner = CommixBuilder::new()
        .url("http://t.com")
        .batch(false)
        .build();
}

#[test]
fn builder_ignore_waf_false_builds_without_panic() {
    let _runner = CommixBuilder::new().ignore_waf(false).build();
}

#[test]
fn builder_offline_false_builds_without_panic() {
    let _runner = CommixBuilder::new().offline(false).build();
}

#[test]
fn builder_random_agent_false_builds_without_panic() {
    let _runner = CommixBuilder::new().random_agent(false).build();
}

// ---- Binary path splitting integration (via is_available, which uses bare_command) ----

// ---- Full parser pipeline (no real process) ----

/// Simulates the output of a full commix session and verifies that the
/// parser pipeline produces the correct CommixResult-equivalent state.
#[test]
fn parser_pipeline_produces_correct_aggregated_state() {
    let mut parser = StreamParser::new();
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    let lines = [
        "Starting commix v0.9...",
        "Request: http://target.com?id=1",
        "[14:22:01] [info] GET parameter 'id' appears to be injectable via (results-based) classic command injection technique.",
        "           |_ id=1;cat /etc/passwd;#",
        "[14:22:01] [warning] WAF detected, retrying with evasion",
        "Request: http://target.com?name=1",
        "CVE-2021-3156",
        "[+] The GET parameter 'name' is vulnerable to classic command injection",
        "[+] Payload: name=a;id;#",
        "[x] Network timeout on attempt 3",
        "Scan complete.",
    ];

    for line in &lines {
        match parser.parse_line(line) {
            ParseEvent::Finding(f) => findings.push(f),
            ParseEvent::Warning(w) => warnings.push(w),
            ParseEvent::Error(e) => errors.push(e),
            ParseEvent::Wait => {}
        }
    }

    assert_eq!(findings.len(), 2, "expected 2 findings");
    assert_eq!(warnings.len(), 1, "expected 1 warning");
    assert_eq!(errors.len(), 1, "expected 1 error");

    assert_eq!(findings[0].parameter, "id");
    assert_eq!(findings[0].payload, "id=1;cat /etc/passwd;#");
    assert_eq!(findings[0].poc, "http://target.com?id=1");
    assert_eq!(findings[0].injection_type, "GET");
    assert_eq!(findings[0].cve, None);

    assert_eq!(findings[1].parameter, "name");
    assert_eq!(findings[1].payload, "name=a;id;#");
    assert_eq!(findings[1].poc, "http://target.com?name=1");
    assert_eq!(findings[1].cve.as_deref(), Some("CVE-2021-3156"));

    assert_eq!(warnings[0], "WAF detected, retrying with evasion");
    assert_eq!(errors[0], "Network timeout on attempt 3");
}

/// Simulate a clean run with no findings.
#[test]
fn parser_pipeline_clean_run_no_events() {
    let mut parser = StreamParser::new();
    let lines = [
        "Starting commix...",
        "Testing GET parameter 'id'...",
        "No vulnerabilities found.",
        "Exiting.",
    ];
    let mut findings = 0;
    let mut warnings = 0;
    for line in &lines {
        match parser.parse_line(line) {
            ParseEvent::Finding(_) => findings += 1,
            ParseEvent::Warning(_) => warnings += 1,
            _ => {}
        }
    }
    assert_eq!(findings, 0);
    assert_eq!(warnings, 0);
}

// ---- CommixResult integration ----

#[test]
fn result_constructed_from_parser_output_is_consistent() {
    let finding = CommixFinding {
        parameter: "id".into(),
        technique: Technique::Classic,
        payload: "id=1;id".into(),
        injection_type: "Unknown".into(),
        poc: "http://t.com?id=1".into(),
        cve: Some("CVE-2023-0001".into()),
        confidence: Confidence::Certain,
    };
    let r = CommixResult {
        findings: vec![finding],
        warnings: vec!["Rate limit hit".into()],
        execution_errors: vec![],
    };

    assert!(r.is_vulnerable());
    assert!(r.has_interference());

    let display = format!("{}", r);
    assert!(display.contains("Found 1 vulnerabilities"));
    assert!(display.contains("Rate limit hit"));
    assert!(display.contains("id"));
}

// ---- Streaming channel integration ----

#[tokio::test]
async fn scan_stream_channel_with_missing_binary_returns_io_error() {
    use tokio::sync::mpsc;

    let (tx, mut rx) = mpsc::channel(32);
    let runner = CommixBuilder::new()
        .binary_path("/nonexistent/commix_binary")
        .url("http://example.com")
        .build();

    let result = runner.scan_stream(tx).await;
    // Channel must be closed (no sends happened because binary wasn't found)
    assert!(
        rx.try_recv().is_err(),
        "no findings expected for missing binary"
    );
    match result {
        Err(CommixError::Io(_)) => {}
        other => panic!("expected Io error for missing binary, got {:?}", other),
    }
}

// ---- Error type integration ----

#[test]
fn error_from_io_error_wraps_correctly() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "binary not found");
    let e: CommixError = io_err.into();
    match e {
        CommixError::Io(_) => {}
        _ => panic!("expected CommixError::Io"),
    }
}

#[test]
fn error_from_json_error_wraps_correctly() {
    let json_err: serde_json::Error =
        serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
    let e: CommixError = json_err.into();
    match e {
        CommixError::Json(_) => {}
        _ => panic!("expected CommixError::Json"),
    }
}

// ---- Version call with missing binary ----

#[tokio::test]
async fn version_returns_string_or_io_error() {
    let runner = Commix::builder().build();
    match runner.version().await {
        Ok(s) => {
            // If commix is installed, version string is a string (may be empty)
            let _ = s;
        }
        Err(CommixError::Io(_)) | Err(CommixError::ProcessFailed { .. }) => {
            // Expected when commix is not installed or --version fails
        }
        Err(e) => panic!("unexpected error from version(): {}", e),
    }
}

// ---- Auth header accumulation integration ----

#[test]
fn multiple_auth_methods_all_accepted() {
    let builder = CommixBuilder::new()
        .auth_bearer("token123")
        .auth_basic("admin", "secret")
        .header("X-Extra: val");

    // Verify all three method calls complete without panic and build() works.
    let _runner = builder.build();
}
