/// Unit tests for individual public types and functions in commix-rs.
///
/// Only the public API surface is used.  CommixBuilder fields are pub(crate)
/// and are therefore not accessible here; we test observable behaviour via the
/// methods the builder exposes and the types it produces.
use commix_rs::{
    parser::{ParseEvent, StreamParser},
    CommixBuilder, CommixError, CommixFinding, CommixResult, Confidence, Technique,
};

// ---- CommixBuilder: build() does not panic ----

#[test]
fn builder_default_builds_without_panic() {
    let _runner = CommixBuilder::new().build();
}

#[test]
#[allow(deprecated)]
fn builder_full_chain_builds_without_panic() {
    let _runner = CommixBuilder::new()
        .url("http://example.com/page?id=1")
        .method("POST")
        .data("param=value")
        .cookie("session=abc123")
        .user_agent("Mozilla/5.0")
        .header("X-A: 1")
        .header("X-B: 2")
        .proxy("http://127.0.0.1:8080")
        .level(2)
        .technique("ctef")
        .tamper_script("space2hash")
        .tamper_script("charencode")
        .timeout_secs(120)
        .network_timeout(30)
        .threads(4)
        .retries(3)
        .random_agent(true)
        .delay_secs(1)
        .batch(false)
        .ignore_waf(true)
        .prefix(";")
        .suffix("#")
        .offline(true)
        .binary_path("/usr/bin/commix")
        .build();
}

// ---- CommixBuilder: auth_basic produces valid base64 ----

#[test]
fn builder_auth_basic_valid_credentials_succeeds() {
    let _runner = CommixBuilder::new().auth_basic("user", "pass").build();
}

#[test]
fn builder_auth_basic_empty_credentials_succeeds() {
    let _runner = CommixBuilder::new().auth_basic("", "").build();
}

#[test]
fn builder_auth_basic_known_value_builds() {
    // "user:pass" → base64 "dXNlcjpwYXNz" (asserted in builder unit tests).
    let _runner = CommixBuilder::new().auth_basic("user", "pass").build();
}

#[test]
fn builder_auth_bearer_builds_without_panic() {
    let _runner = CommixBuilder::new().auth_bearer("mytoken123").build();
}

// ---- CommixResult helper methods ----

#[test]
fn result_is_vulnerable_false_when_empty() {
    let r = CommixResult {
        findings: vec![],
        warnings: vec![],
        execution_errors: vec![],
    };
    assert!(!r.is_vulnerable());
}

#[test]
fn result_is_vulnerable_true_when_findings_present() {
    let finding = CommixFinding {
        parameter: "id".into(),
        technique: Technique::Classic,
        payload: "1;id".into(),
        injection_type: "GET".into(),
        poc: "http://t.com?id=1;id".into(),
        cve: None,
        confidence: Confidence::Certain,
    };
    let r = CommixResult {
        findings: vec![finding],
        warnings: vec![],
        execution_errors: vec![],
    };
    assert!(r.is_vulnerable());
}

#[test]
fn result_has_interference_false_when_clean() {
    let r = CommixResult {
        findings: vec![],
        warnings: vec![],
        execution_errors: vec![],
    };
    assert!(!r.has_interference());
}

#[test]
fn result_has_interference_true_when_warnings() {
    let r = CommixResult {
        findings: vec![],
        warnings: vec!["WAF detected".into()],
        execution_errors: vec![],
    };
    assert!(r.has_interference());
}

#[test]
fn result_has_interference_true_when_errors() {
    let r = CommixResult {
        findings: vec![],
        warnings: vec![],
        execution_errors: vec!["Connection reset".into()],
    };
    assert!(r.has_interference());
}

// ---- CommixResult Display ----

#[test]
fn result_display_no_findings_text() {
    let r = CommixResult {
        findings: vec![],
        warnings: vec![],
        execution_errors: vec![],
    };
    assert_eq!(format!("{}", r), "No vulnerabilities found.");
}

#[test]
fn result_display_with_finding_contains_count() {
    let finding = CommixFinding {
        parameter: "x".into(),
        technique: Technique::TimeBasedBlind,
        payload: "x=1".into(),
        injection_type: "POST".into(),
        poc: "poc-url".into(),
        cve: Some("CVE-2023-1111".into()),
        confidence: Confidence::Tentative,
    };
    let r = CommixResult {
        findings: vec![finding],
        warnings: vec![],
        execution_errors: vec![],
    };
    let s = format!("{}", r);
    assert!(s.contains("Found 1 vulnerabilities"));
}

#[test]
fn result_display_execution_errors_shown() {
    let r = CommixResult {
        findings: vec![],
        warnings: vec![],
        execution_errors: vec!["boom".into()],
    };
    let s = format!("{}", r);
    assert!(s.contains("1 critical execution errors"));
    assert!(s.contains("boom"));
}

#[test]
fn result_display_warnings_shown() {
    let r = CommixResult {
        findings: vec![],
        warnings: vec!["WAF detected".into(), "slow response".into()],
        execution_errors: vec![],
    };
    let s = format!("{}", r);
    assert!(s.contains("2 warnings"));
}

// ---- CommixFinding Display ----

#[test]
fn finding_display_with_cve() {
    let f = CommixFinding {
        parameter: "param".into(),
        technique: Technique::EvalBased,
        payload: "evil".into(),
        injection_type: "GET".into(),
        poc: "http://x.com?param=evil".into(),
        cve: Some("CVE-2024-9999".into()),
        confidence: Confidence::Certain,
    };
    let s = format!("{}", f);
    assert!(s.contains("CVE-2024-9999"));
    assert!(s.contains("param"));
    assert!(s.contains("evil"));
}

#[test]
fn finding_display_without_cve() {
    let f = CommixFinding {
        parameter: "q".into(),
        technique: Technique::FileBased,
        payload: "payload".into(),
        injection_type: "POST".into(),
        poc: "poc".into(),
        cve: None,
        confidence: Confidence::Low,
    };
    let s = format!("{}", f);
    assert!(!s.contains("CVE"));
    assert!(s.contains("q"));
}

// ---- Confidence and Technique serialisation ----

#[test]
fn confidence_serializes_lowercase() {
    assert_eq!(
        serde_json::to_string(&Confidence::Certain).unwrap(),
        r#""certain""#
    );
    assert_eq!(
        serde_json::to_string(&Confidence::Tentative).unwrap(),
        r#""tentative""#
    );
    assert_eq!(serde_json::to_string(&Confidence::Low).unwrap(), r#""low""#);
}

#[test]
fn technique_serializes_lowercase() {
    assert_eq!(
        serde_json::to_string(&Technique::Classic).unwrap(),
        r#""classic""#
    );
    assert_eq!(
        serde_json::to_string(&Technique::TimeBasedBlind).unwrap(),
        r#""timebasedblind""#
    );
    assert_eq!(
        serde_json::to_string(&Technique::EvalBased).unwrap(),
        r#""evalbased""#
    );
    assert_eq!(
        serde_json::to_string(&Technique::FileBased).unwrap(),
        r#""filebased""#
    );
}

#[test]
fn confidence_deserializes_roundtrip() {
    for v in [Confidence::Certain, Confidence::Tentative, Confidence::Low] {
        let json = serde_json::to_string(&v).unwrap();
        let back: Confidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

#[test]
fn technique_deserializes_roundtrip() {
    for v in [
        Technique::Classic,
        Technique::TimeBasedBlind,
        Technique::EvalBased,
        Technique::FileBased,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: Technique = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

#[test]
fn finding_serde_roundtrip() {
    let f = CommixFinding {
        parameter: "id".into(),
        technique: Technique::Classic,
        payload: "id=1;id".into(),
        injection_type: "GET".into(),
        poc: "http://t.com?id=1".into(),
        cve: Some("CVE-2023-1111".into()),
        confidence: Confidence::Certain,
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: CommixFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.parameter, f.parameter);
    assert_eq!(back.payload, f.payload);
    assert_eq!(back.cve, f.cve);
    assert_eq!(back.technique, f.technique);
    assert_eq!(back.confidence, f.confidence);
}

#[test]
fn result_serde_roundtrip() {
    let r = CommixResult {
        findings: vec![CommixFinding {
            parameter: "x".into(),
            technique: Technique::EvalBased,
            payload: "evil".into(),
            injection_type: "POST".into(),
            poc: "poc".into(),
            cve: None,
            confidence: Confidence::Low,
        }],
        warnings: vec!["w1".into()],
        execution_errors: vec!["e1".into()],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CommixResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.findings.len(), 1);
    assert_eq!(back.warnings.len(), 1);
    assert_eq!(back.execution_errors.len(), 1);
}

// ---- CommixError variants ----

#[test]
fn error_display_process_failed() {
    let e = CommixError::ProcessFailed {
        status: Some(127),
        signal: None,
        stderr: "engine stderr".into(),
    };
    assert!(format!("{}", e).contains("127"));
    assert!(format!("{}", e).contains("engine stderr"));
}

#[test]
fn error_display_timeout() {
    let e = CommixError::Timeout;
    assert!(format!("{}", e).contains("timed out"));
}

#[test]
fn error_display_validation() {
    let e = CommixError::Validation("too large".into());
    assert!(format!("{}", e).contains("too large"));
}

// ---- StreamParser individual line parsing ----

#[test]
fn parser_new_returns_default_state() {
    // Brand new parser should emit Wait for an empty line
    let mut p = StreamParser::new();
    assert!(matches!(p.parse_line(""), ParseEvent::Wait));
}

#[test]
fn parser_warning_line_returns_warning_event() {
    let mut p = StreamParser::new();
    match p.parse_line("[!] Something went wrong") {
        ParseEvent::Warning(w) => assert_eq!(w, "Something went wrong"),
        _ => panic!("expected Warning"),
    }
}

#[test]
fn parser_error_line_returns_error_event() {
    let mut p = StreamParser::new();
    match p.parse_line("[x] Fatal error") {
        ParseEvent::Error(e) => assert_eq!(e, "Fatal error"),
        _ => panic!("expected Error"),
    }
}

#[test]
fn parser_modern_post_and_cookie_injection_types() {
    let mut post = StreamParser::new();
    post.parse_line(
        "[21:53:04] [info] POST parameter 'ip' appears to be injectable via (results-based) classic command injection technique.",
    );
    match post.parse_line("           |_ localhost;echo LKHGJO") {
        ParseEvent::Finding(f) => {
            assert_eq!(f.parameter, "ip");
            assert_eq!(f.injection_type, "POST");
            assert_eq!(f.technique, Technique::Classic);
        }
        _ => panic!("expected POST finding"),
    }

    let mut cookie = StreamParser::new();
    cookie.parse_line(
        "Cookie parameter 'sessionid' appears to be injectable via (results-based) classic command injection technique.",
    );
    match cookie.parse_line("|_ sessionid=1;id") {
        ParseEvent::Finding(f) => {
            assert_eq!(f.parameter, "sessionid");
            assert_eq!(f.injection_type, "COOKIE");
        }
        _ => panic!("expected COOKIE finding"),
    }
}

#[test]
fn parser_modern_warning_and_error_formats() {
    let mut p = StreamParser::new();
    match p.parse_line("[14:22:01] [warning] WAF/IPS detected") {
        ParseEvent::Warning(w) => assert_eq!(w, "WAF/IPS detected"),
        _ => panic!("expected Warning"),
    }
    match p.parse_line("[14:22:01] [error] Connection timed out") {
        ParseEvent::Error(e) => assert_eq!(e, "Connection timed out"),
        _ => panic!("expected Error"),
    }
    match p.parse_line("[14:22:01] [critical] Target host is unreachable") {
        ParseEvent::Error(e) => assert_eq!(e, "Target host is unreachable"),
        _ => panic!("expected Error for [critical]"),
    }
}

#[test]
fn parser_technique_parsed_from_injectable_line() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The GET parameter 'q' is vulnerable to time-based blind injection");
    match p.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => {
            assert_eq!(f.technique, Technique::TimeBasedBlind);
            assert_eq!(f.injection_type, "GET");
        }
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_full_finding_sequence_emits_finding() {
    let mut p = StreamParser::new();
    p.parse_line("Request: http://site.com?q=1");
    p.parse_line("[+] The GET parameter 'q' is vulnerable to classic command injection");
    match p.parse_line("[+] Payload: q=1;id") {
        ParseEvent::Finding(f) => {
            assert_eq!(f.parameter, "q");
            assert_eq!(f.payload, "q=1;id");
            assert_eq!(f.poc, "http://site.com?q=1");
            assert_eq!(f.injection_type, "GET");
            assert_eq!(f.technique, Technique::Classic);
            assert!(f.cve.is_none());
            assert_eq!(f.confidence, Confidence::Certain);
        }
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_state_clears_after_finding() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The GET parameter 'a' is vulnerable");
    p.parse_line("[+] Payload: a=1");
    // parameter and poc should be cleared; next payload without param produces Wait
    match p.parse_line("[+] Payload: b=1") {
        ParseEvent::Wait => {}
        _ => panic!("expected Wait after state reset"),
    }
}

#[test]
fn parser_cve_extracted_from_context_line() {
    let mut p = StreamParser::new();
    p.parse_line("Exploiting CVE-2023-4567 via injection");
    p.parse_line("[+] The GET parameter 'x' is vulnerable");
    match p.parse_line("[+] Payload: x=1") {
        ParseEvent::Finding(f) => assert_eq!(f.cve.as_deref(), Some("CVE-2023-4567")),
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_unrecognised_line_returns_wait() {
    let mut p = StreamParser::new();
    match p.parse_line("Just some random commix output line") {
        ParseEvent::Wait => {}
        _ => panic!("expected Wait"),
    }
}

#[test]
fn parser_request_line_sets_poc() {
    let mut p = StreamParser::new();
    assert!(matches!(
        p.parse_line("Request: http://example.com/api"),
        ParseEvent::Wait
    ));
    // Feed a complete finding to confirm poc was stored
    p.parse_line("[+] The GET parameter 'id' is vulnerable");
    match p.parse_line("[+] Payload: id=1") {
        ParseEvent::Finding(f) => assert_eq!(f.poc, "http://example.com/api"),
        _ => panic!("expected Finding"),
    }
}
