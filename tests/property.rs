/// Property-based tests using proptest to establish invariants over commix-rs public API.
///
/// CommixBuilder fields are pub(crate) and not accessible here; all tests
/// use only the public method surface.
use commix_rs::{
    parser::{ParseEvent, StreamParser},
    CommixBuilder, CommixFinding, CommixResult, Confidence, Technique,
};
use proptest::prelude::*;

// ---- StreamParser invariants ----

proptest! {
    /// Any arbitrary line that does not start with a Commix-recognised prefix
    /// and has no recognisable structure must return ParseEvent::Wait.
    /// We restrict to lines starting with non-special chars to keep the
    /// invariant simple and avoid accidentally hitting real patterns.
    #[test]
    fn parser_non_special_line_always_returns_wait(
        line in "[^\\[CVERrequst].*"
    ) {
        let mut p = StreamParser::new();
        // The generated line cannot start with '[', 'C', 'V', 'E', 'R', 'r', etc.
        // so it should always be Wait.
        match p.parse_line(&line) {
            ParseEvent::Wait => {}
            other => prop_assert!(
                false,
                "unexpected event for line {:?}: {:?}",
                line,
                std::mem::discriminant(&other)
            ),
        }
    }

    /// Any line beginning with "[!]" must produce ParseEvent::Warning, and the
    /// warning text must be the part after "[!] " (trimmed).
    #[test]
    fn parser_warning_prefix_always_produces_warning(suffix in ".*") {
        let mut p = StreamParser::new();
        let line = format!("[!] {}", suffix);
        match p.parse_line(&line) {
            ParseEvent::Warning(w) => {
                prop_assert_eq!(w, suffix.trim());
            }
            _ => prop_assert!(false, "expected Warning event"),
        }
    }

    /// Any line beginning with "[x]" must produce ParseEvent::Error.
    #[test]
    fn parser_error_prefix_always_produces_error(suffix in ".*") {
        let mut p = StreamParser::new();
        let line = format!("[x] {}", suffix);
        match p.parse_line(&line) {
            ParseEvent::Error(e) => {
                prop_assert_eq!(e, suffix.trim());
            }
            _ => prop_assert!(false, "expected Error event"),
        }
    }

    /// After emitting a Finding, the parser's parameter and poc accumulators are
    /// always cleared, so a subsequent Payload line without a prior parameter
    /// produces Wait (not a spurious finding with leftover state).
    #[test]
    fn parser_state_cleared_after_finding(
        param in "[a-z][a-z0-9_]{0,15}",
        poc   in "http://[a-z]{3,8}\\.com/[a-z]{0,8}",
        payload in "[a-z0-9;=#]{1,30}",
    ) {
        let mut p = StreamParser::new();
        p.parse_line(&format!("Request: {}", poc));
        p.parse_line(&format!("[+] The GET parameter '{}' is vulnerable to injection", param));
        // First payload produces a Finding
        match p.parse_line(&format!("[+] Payload: {}", payload)) {
            ParseEvent::Finding(f) => {
                prop_assert_eq!(&f.parameter, &param);
                prop_assert_eq!(&f.poc, &poc);
            }
            _ => prop_assert!(false, "expected Finding on first payload"),
        }
        // Second payload without new parameter line must produce Wait
        match p.parse_line("[+] Payload: orphan=1") {
            ParseEvent::Wait => {}
            _ => prop_assert!(false, "expected Wait after state cleared"),
        }
    }

    /// The payload extracted from a Finding always equals the text after "[+] Payload: "
    /// (trimmed), regardless of content.
    #[test]
    fn parser_payload_text_preserved_verbatim(payload in ".{0,500}") {
        let mut p = StreamParser::new();
        p.parse_line("[+] The GET parameter 'q' is vulnerable to injection");
        let line = format!("[+] Payload: {}", payload);
        match p.parse_line(&line) {
            ParseEvent::Finding(f) => {
                prop_assert_eq!(f.payload, payload.trim());
            }
            _ => prop_assert!(false, "expected Finding"),
        }
    }

    /// A well-formed CVE string of the form CVE-YYYY-NNNNN anywhere in the line
    /// is always captured when a finding is later emitted.
    #[test]
    fn parser_valid_cve_always_captured(
        year in 1000u32..=9999,
        id   in 1u32..=999999,
    ) {
        let cve_str = format!("CVE-{}-{}", year, id);
        let mut p = StreamParser::new();
        p.parse_line(&format!("Exploiting {}", cve_str));
        p.parse_line("[+] The GET parameter 'q' is vulnerable");
        match p.parse_line("[+] Payload: q=1") {
            ParseEvent::Finding(f) => {
                prop_assert_eq!(f.cve.as_deref(), Some(cve_str.as_str()));
            }
            _ => prop_assert!(false, "expected Finding"),
        }
    }
}

// ---- CommixBuilder invariants ----

proptest! {
    /// auth_bearer always results in a runner being buildable without panic.
    #[test]
    fn builder_bearer_token_builds_without_panic(token in "[A-Za-z0-9._\\-]{1,100}") {
        let _runner = CommixBuilder::new().auth_bearer(token).build();
    }

    /// auth_basic never panics for short inputs and always builds.
    #[test]
    fn builder_auth_basic_never_panics(
        user in "[a-zA-Z0-9]{0,50}",
        pass in "[a-zA-Z0-9!@#$%]{0,50}",
    ) {
        let _runner = CommixBuilder::new().auth_basic(&user, &pass).build();
    }

    /// Setting url always produces a builder that builds without panic.
    #[test]
    fn builder_url_builds_without_panic(url in ".{0,200}") {
        let _runner = CommixBuilder::new().url(url).build();
    }

    /// Setting cookie always produces a builder that builds without panic.
    #[test]
    fn builder_cookie_builds_without_panic(cookie in ".{0,200}") {
        let _runner = CommixBuilder::new().cookie(cookie).build();
    }

    /// Adding N headers always produces a builder that builds without panic.
    #[test]
    fn builder_n_headers_builds_without_panic(
        headers in prop::collection::vec(".{1,80}", 1..=50)
    ) {
        let mut b = CommixBuilder::new();
        for h in headers {
            b = b.header(h);
        }
        let _runner = b.build();
    }

    /// Adding N tamper scripts always produces a builder that builds without panic.
    #[test]
    fn builder_n_tamper_scripts_builds_without_panic(
        scripts in prop::collection::vec("[a-z0-9_]{1,20}", 1..=50)
    ) {
        let mut b = CommixBuilder::new();
        for s in scripts {
            b = b.tamper_script(s);
        }
        let _runner = b.build();
    }
}

// ---- CommixResult invariants ----

proptest! {
    /// is_vulnerable() is true iff findings is non-empty.
    #[test]
    fn result_is_vulnerable_iff_findings_nonempty(
        n_findings in 0usize..=20,
    ) {
        let findings: Vec<CommixFinding> = (0..n_findings)
            .map(|i| CommixFinding {
                parameter: format!("p{}", i),
                technique: Technique::Classic,
                payload: "x=1".into(),
                injection_type: "GET".into(),
                poc: "http://t.com".into(),
                cve: None,
                confidence: Confidence::Certain,
            })
            .collect();
        let r = CommixResult {
            findings,
            warnings: vec![],
            execution_errors: vec![],
        };
        if n_findings == 0 {
            prop_assert!(!r.is_vulnerable());
        } else {
            prop_assert!(r.is_vulnerable());
        }
    }

    /// has_interference() is true iff warnings or execution_errors is non-empty.
    #[test]
    fn result_has_interference_iff_nonempty_warnings_or_errors(
        n_warnings in 0usize..=10,
        n_errors   in 0usize..=10,
    ) {
        let r = CommixResult {
            findings: vec![],
            warnings: (0..n_warnings).map(|i| format!("w{}", i)).collect(),
            execution_errors: (0..n_errors).map(|i| format!("e{}", i)).collect(),
        };
        let expected = n_warnings > 0 || n_errors > 0;
        prop_assert_eq!(r.has_interference(), expected);
    }

    /// Display on CommixResult never panics for arbitrary warnings/errors.
    #[test]
    fn result_display_never_panics(
        warnings in prop::collection::vec(".*", 0..=5),
        errors in prop::collection::vec(".*", 0..=5),
    ) {
        let r = CommixResult {
            findings: vec![],
            warnings,
            execution_errors: errors,
        };
        let _ = format!("{}", r);
    }
}
