/// Adversarial tests: hostile, malformed, boundary, and oversized inputs.
use commix_rs::{
    parser::{ParseEvent, StreamParser},
    CommixBuilder, CommixFinding, CommixResult, Confidence, Technique,
};

// ---- Empty and zero-length inputs ----

#[test]
fn parser_empty_line_returns_wait() {
    let mut p = StreamParser::new();
    assert!(matches!(p.parse_line(""), ParseEvent::Wait));
}

#[test]
fn parser_whitespace_only_returns_wait() {
    let mut p = StreamParser::new();
    assert!(matches!(p.parse_line("   \t\n  "), ParseEvent::Wait));
}

#[test]
fn parser_payload_with_empty_body_emits_finding_with_empty_payload() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The GET parameter 'q' is vulnerable");
    match p.parse_line("[+] Payload:") {
        ParseEvent::Finding(f) => assert_eq!(f.payload, ""),
        _ => panic!("expected Finding with empty payload"),
    }
}

#[test]
fn parser_request_line_with_no_url() {
    let mut p = StreamParser::new();
    assert!(matches!(p.parse_line("Request:"), ParseEvent::Wait));
}

// ---- Null bytes ----

#[test]
fn parser_null_byte_in_warning_preserved() {
    let mut p = StreamParser::new();
    match p.parse_line("[!] null\x00byte") {
        ParseEvent::Warning(w) => assert_eq!(w, "null\x00byte"),
        _ => panic!("expected Warning"),
    }
}

#[test]
fn parser_null_byte_in_parameter_name() {
    let mut p = StreamParser::new();
    // A null byte in the 'is vulnerable' pattern should NOT match because the
    // pattern requires "' is vulnerable" after the param name, so this won't parse.
    assert!(matches!(
        p.parse_line("[+] The GET parameter '\x00' is vulnerable to injection"),
        ParseEvent::Wait
    ));
}

#[test]
fn parser_null_byte_in_payload_stored_verbatim() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The GET parameter 'x' is vulnerable");
    match p.parse_line("[+] Payload: x\x00=1") {
        ParseEvent::Finding(f) => assert!(f.payload.contains('\x00')),
        _ => panic!("expected Finding"),
    }
}

// ---- Boundary sizes ----

#[test]
fn parser_1mb_payload_accepted() {
    let mut p = StreamParser::new();
    let huge = "X".repeat(1024 * 1024);
    p.parse_line("[+] The GET parameter 'p' is vulnerable");
    match p.parse_line(&format!("[+] Payload: {}", huge)) {
        ParseEvent::Finding(f) => assert_eq!(f.payload.len(), huge.len()),
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_1mb_warning_text_accepted() {
    let mut p = StreamParser::new();
    let huge = "W".repeat(1024 * 1024);
    match p.parse_line(&format!("[!] {}", huge)) {
        ParseEvent::Warning(w) => assert_eq!(w.len(), huge.len()),
        _ => panic!("expected Warning"),
    }
}

#[test]
fn parser_1mb_parameter_name_accepted() {
    let mut p = StreamParser::new();
    let huge = "P".repeat(1024 * 1024);
    p.parse_line(&format!("[+] The GET parameter '{}' is vulnerable", huge));
    match p.parse_line("[+] Payload: x=1") {
        ParseEvent::Finding(f) => assert_eq!(f.parameter.len(), huge.len()),
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_1mb_random_line_returns_wait() {
    let mut p = StreamParser::new();
    let huge = "R".repeat(1024 * 1024);
    assert!(matches!(p.parse_line(&huge), ParseEvent::Wait));
}

// ---- Malformed CVE strings ----

#[test]
fn parser_cve_with_non_digit_year_ignored() {
    let mut p = StreamParser::new();
    p.parse_line("CVE-ABCD-1234"); // year is non-digit
    p.parse_line("[+] The GET parameter 'q' is vulnerable");
    match p.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.cve, None),
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_cve_with_non_digit_id_ignored() {
    let mut p = StreamParser::new();
    p.parse_line("CVE-2023-WXYZ"); // id is non-digit
    p.parse_line("[+] The GET parameter 'q' is vulnerable");
    match p.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.cve, None),
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_cve_too_short_ignored() {
    let mut p = StreamParser::new();
    p.parse_line("CVE-2023"); // only 2 parts, not 3
    p.parse_line("[+] The GET parameter 'q' is vulnerable");
    match p.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.cve, None),
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_cve_max_digit_values_accepted() {
    let mut p = StreamParser::new();
    p.parse_line("CVE-9999-999999999");
    p.parse_line("[+] The GET parameter 'q' is vulnerable");
    match p.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.cve.as_deref(), Some("CVE-9999-999999999")),
        _ => panic!("expected Finding"),
    }
}

// ---- Truncated/partial lines ----

#[test]
fn parser_truncated_vulnerability_line_no_close_quote_returns_wait() {
    let mut p = StreamParser::new();
    assert!(matches!(
        p.parse_line("[+] The GET parameter 'q' is"),
        ParseEvent::Wait
    ));
}

#[test]
fn parser_vulnerability_line_without_is_vulnerable_text_returns_wait() {
    let mut p = StreamParser::new();
    assert!(matches!(
        p.parse_line("[+] The GET parameter 'q' is safe"),
        ParseEvent::Wait
    ));
}

#[test]
fn parser_payload_keyword_with_no_prior_param_returns_wait() {
    let mut p = StreamParser::new();
    // Payload arrives without parameter having been set first
    assert!(matches!(
        p.parse_line("[+] Payload: evil;id"),
        ParseEvent::Wait
    ));
}

// ---- Unicode edge cases ----

#[test]
fn parser_unicode_emoji_in_parameter() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The GET parameter '🔥' is vulnerable to injection");
    match p.parse_line("[+] Payload: 🔥=1;id") {
        ParseEvent::Finding(f) => assert_eq!(f.parameter, "🔥"),
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_bom_in_warning_preserved() {
    let mut p = StreamParser::new();
    match p.parse_line("[!] \u{feff}payload marker") {
        ParseEvent::Warning(w) => assert!(w.contains('\u{feff}')),
        _ => panic!("expected Warning"),
    }
}

#[test]
fn parser_rtl_override_in_line_returns_wait() {
    let mut p = StreamParser::new();
    // RTL override character should not cause panic or incorrect parse
    assert!(matches!(
        p.parse_line("some \u{202e}line"),
        ParseEvent::Wait
    ));
}

// ---- Duplicate and reordered lines ----

#[test]
fn parser_duplicate_vulnerability_lines_last_wins() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The GET parameter 'first' is vulnerable");
    p.parse_line("[+] The GET parameter 'second' is vulnerable");
    match p.parse_line("[+] Payload: x=1") {
        ParseEvent::Finding(f) => assert_eq!(f.parameter, "second"),
        _ => panic!("expected Finding"),
    }
}

#[test]
fn parser_multiple_request_lines_last_wins() {
    let mut p = StreamParser::new();
    p.parse_line("Request: http://first.com");
    p.parse_line("Request: http://second.com");
    p.parse_line("[+] The GET parameter 'q' is vulnerable");
    match p.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.poc, "http://second.com"),
        _ => panic!("expected Finding"),
    }
}

// ---- Builder adversarial inputs ----

#[test]
fn builder_auth_basic_empty_credentials_succeeds() {
    let _runner = CommixBuilder::new().auth_basic("", "").build();
}

#[test]
fn builder_many_headers_accepted() {
    let mut b = CommixBuilder::new();
    for i in 0..1000 {
        b = b.header(format!("X-Test-{}: value", i));
    }
    // Just verify build() completes without panic
    let _runner = b.build();
}

#[test]
fn builder_many_tamper_scripts_accepted() {
    let mut b = CommixBuilder::new();
    for i in 0..1000 {
        b = b.tamper_script(format!("script_{}", i));
    }
    // Just verify build() completes without panic
    let _runner = b.build();
}

#[test]
fn builder_max_u64_timeout_accepted() {
    let b = CommixBuilder::new().timeout_secs(u64::MAX);
    let _runner = b.build();
}

#[test]
fn builder_max_u8_level_accepted() {
    let b = CommixBuilder::new().level(u8::MAX);
    let _runner = b.build();
}

#[test]
fn builder_max_u8_threads_accepted() {
    let b = CommixBuilder::new().threads(u8::MAX);
    let _runner = b.build();
}

// ---- CommixResult adversarial construction ----

#[test]
fn result_many_findings_is_vulnerable() {
    let findings: Vec<CommixFinding> = (0..10_000)
        .map(|i| CommixFinding {
            parameter: format!("p{}", i),
            technique: Technique::Classic,
            payload: format!("p{}=1;id", i),
            injection_type: "GET".into(),
            poc: format!("http://t.com?p{}=1", i),
            cve: None,
            confidence: Confidence::Certain,
        })
        .collect();
    let r = CommixResult {
        findings,
        warnings: vec![],
        execution_errors: vec![],
    };
    assert!(r.is_vulnerable());
    assert!(!r.has_interference());
}

#[test]
fn result_many_warnings_has_interference() {
    let warnings: Vec<String> = (0..10_000).map(|i| format!("warning {}", i)).collect();
    let r = CommixResult {
        findings: vec![],
        warnings,
        execution_errors: vec![],
    };
    assert!(r.has_interference());
}

// ---- Concurrent parser instances ----

#[test]
fn concurrent_independent_parsers_do_not_interfere() {
    use std::thread;
    let handles: Vec<_> = (0..16)
        .map(|i| {
            thread::spawn(move || {
                let mut p = StreamParser::new();
                p.parse_line(&format!("Request: http://site{}.com", i));
                p.parse_line("[+] The GET parameter 'q' is vulnerable");
                match p.parse_line("[+] Payload: q=1") {
                    ParseEvent::Finding(f) => {
                        assert_eq!(f.poc, format!("http://site{}.com", i));
                    }
                    _ => panic!("expected Finding"),
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread panicked");
    }
}
