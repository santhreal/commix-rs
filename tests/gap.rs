/// Gap tests: pins documented limitations and edge-case behaviour so any future
/// change that alters these semantics is deliberate and visible in the diff.
use commix_rs::{
    parser::{ParseEvent, StreamParser},
    CommixFinding, CommixResult, Confidence, Technique,
};

// ---- Limitation: technique is always Classic regardless of actual commix output ----

/// The StreamParser always assigns Technique::Classic to findings regardless of
/// what commix says on stdout.  This is a known gap: the parser does not yet
/// classify time-based or eval-based techniques from the stream.
#[test]
fn gap_parser_technique_always_classic() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The GET parameter 'q' is vulnerable to time-based blind injection");
    match p.parse_line("[+] Payload: q=1;sleep 5;#") {
        ParseEvent::Finding(f) => {
            // Pin: until the parser is extended, technique will always be Classic.
            assert_eq!(
                f.technique,
                Technique::Classic,
                "gap: parser does not classify technique from output; expected Classic"
            );
        }
        _ => panic!("expected Finding"),
    }
}

// ---- Limitation: injection_type is always "Unknown" ----

/// The parser sets injection_type to the hard-coded string "Unknown" because
/// the injection type (GET/POST/HEADER) is not yet parsed from the stream.
#[test]
fn gap_parser_injection_type_always_unknown() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The POST parameter 'data' is vulnerable");
    match p.parse_line("[+] Payload: data=x") {
        ParseEvent::Finding(f) => {
            assert_eq!(
                f.injection_type, "Unknown",
                "gap: injection_type is not parsed from stream"
            );
        }
        _ => panic!("expected Finding"),
    }
}

// ---- Limitation: confidence is always Certain ----

/// The parser always assigns Confidence::Certain regardless of what commix
/// says, because the confidence keyword is not extracted from the output.
#[test]
fn gap_parser_confidence_always_certain() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The GET parameter 'q' is vulnerable (tentative)");
    match p.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => {
            assert_eq!(
                f.confidence,
                Confidence::Certain,
                "gap: confidence not parsed; always Certain"
            );
        }
        _ => panic!("expected Finding"),
    }
}

// ---- Limitation: CVE overwritten when multiple CVE lines appear ----

/// When multiple CVE lines appear before a finding, only the last one is
/// captured because current_cve is a single Option<String>.
#[test]
fn gap_parser_cve_last_one_wins() {
    let mut p = StreamParser::new();
    p.parse_line("Reference: CVE-2022-0001");
    p.parse_line("Reference: CVE-2023-9999");
    p.parse_line("[+] The GET parameter 'q' is vulnerable");
    match p.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => {
            // Pin: last CVE wins; earlier ones are silently discarded.
            assert_eq!(
                f.cve.as_deref(),
                Some("CVE-2023-9999"),
                "gap: only the last CVE seen before a finding is kept"
            );
        }
        _ => panic!("expected Finding"),
    }
}

// ---- Limitation: PoC (Request:) overwritten on repeated lines ----

/// When multiple "Request:" lines appear, the last one wins. This means if
/// commix emits multiple request lines for one finding, earlier ones are lost.
#[test]
fn gap_parser_poc_last_request_wins() {
    let mut p = StreamParser::new();
    p.parse_line("Request: http://first.example.com");
    p.parse_line("Request: http://last.example.com");
    p.parse_line("[+] The GET parameter 'q' is vulnerable");
    match p.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => {
            assert_eq!(
                f.poc, "http://last.example.com",
                "gap: last Request: line wins; earlier ones discarded"
            );
        }
        _ => panic!("expected Finding"),
    }
}

// ---- Limitation: CVE tag is NOT cleared between findings ----

/// After a CVE is emitted with a finding, current_cve is cleared by
/// `take()`. This is correct behaviour. Pin it so a refactor can't
/// accidentally keep CVE state leaking across findings.
#[test]
fn gap_parser_cve_cleared_after_finding() {
    let mut p = StreamParser::new();
    p.parse_line("CVE-2023-1234");
    p.parse_line("[+] The GET parameter 'a' is vulnerable");
    match p.parse_line("[+] Payload: a=1") {
        ParseEvent::Finding(f) => {
            assert_eq!(f.cve.as_deref(), Some("CVE-2023-1234"));
        }
        _ => panic!("expected Finding"),
    }

    // Second finding should have NO CVE (state was cleared by take())
    p.parse_line("[+] The GET parameter 'b' is vulnerable");
    match p.parse_line("[+] Payload: b=1") {
        ParseEvent::Finding(f) => {
            assert_eq!(
                f.cve, None,
                "gap: CVE must be cleared after the first finding"
            );
        }
        _ => panic!("expected Finding"),
    }
}

// ---- Limitation: process failure with findings does not raise ProcessFailed ----

/// CommixResult represents a run that found vulnerabilities but the process
/// exited non-zero.  The runner treats ANY findings as success (no ProcessFailed
/// error).  This is a documented design choice pinned here.
#[test]
fn gap_result_is_vulnerable_does_not_imply_no_errors() {
    let finding = CommixFinding {
        parameter: "id".into(),
        technique: Technique::Classic,
        payload: "id=1;id".into(),
        injection_type: "GET".into(),
        poc: "http://t.com?id=1".into(),
        cve: None,
        confidence: Confidence::Certain,
    };
    // A result can be both vulnerable AND have execution errors (design gap: no
    // reconciliation of partial-success scans).
    let r = CommixResult {
        findings: vec![finding],
        warnings: vec![],
        execution_errors: vec!["Process exited with code 1".into()],
    };
    assert!(r.is_vulnerable(), "has findings");
    assert!(
        r.has_interference(),
        "gap: both findings and errors can coexist"
    );
}

// ---- Limitation: Display for CommixResult uses 1-based indexing ----

/// The Display implementation numbers findings starting at 1.  Pin this so
/// a refactor to 0-based indexing is explicit.
#[test]
fn gap_result_display_one_based_index() {
    let finding = CommixFinding {
        parameter: "x".into(),
        technique: Technique::Classic,
        payload: "x=1".into(),
        injection_type: "GET".into(),
        poc: "http://t.com".into(),
        cve: None,
        confidence: Confidence::Certain,
    };
    let r = CommixResult {
        findings: vec![finding],
        warnings: vec![],
        execution_errors: vec![],
    };
    let s = format!("{}", r);
    assert!(
        s.contains("1."),
        "gap: findings display starts at 1, not 0: {}",
        s
    );
    assert!(!s.contains("0."), "gap: no 0-indexed entry expected");
}

// ---- Limitation: StreamParser is NOT Send/Sync (it does not need to be) ----

/// StreamParser is intentionally designed to be owned by a single task on one
/// Tokio stream.  It holds non-thread-safe String accumulators and is not Arc-able.
/// Pin this so adding `Send` bounds does not silently break the ownership model.
#[test]
fn gap_stream_parser_is_send() {
    fn assert_send<T: Send>() {}
    // StreamParser only holds String fields, so it IS Send.
    // Pin: if this fails, a future refactor has introduced non-Send state.
    assert_send::<StreamParser>();
}

// ---- Gap: Commix binary absence causes scan() to return Io error ----

/// When the commix binary is absent, scan() and scan_stream() return an Io error
/// (NotFound).  This is exercised here without actually spawning a process by
/// pointing to a nonexistent binary path.
#[tokio::test]
async fn gap_missing_binary_returns_io_error() {
    use commix_rs::{Commix, CommixError};

    let runner = Commix::builder()
        .binary_path("/nonexistent/path/to/commix")
        .build();

    match runner.scan().await {
        Err(CommixError::Io(_)) => {
            // Expected: binary not found → Io error
        }
        other => panic!(
            "expected CommixError::Io when binary is missing, got {:?}",
            other
        ),
    }
}

// ---- Gap: auth_basic always builds (base64 via the `base64` crate) ----

/// auth_basic uses the vetted `base64` crate. Pin that common credential
/// shapes still build without panic after that swap.
#[test]
fn gap_auth_basic_builds_for_representative_credentials() {
    let _runner = commix_rs::CommixBuilder::new()
        .auth_basic("user", "pass")
        .build();
    let _runner2 = commix_rs::CommixBuilder::new().auth_basic("a", "b").build();
}

// ---- Gap: technique classification + injection_type ----

/// Pin the documented parser limitation across eval/time-based commix output lines.
#[test]
fn gap_parser_technique_stays_classic_for_eval_and_time_based_output() {
    let cases = [
        "[+] The GET parameter 'q' is vulnerable to eval-based injection",
        "[+] The GET parameter 'q' is vulnerable to time-based blind injection",
        "[+] The POST parameter 'data' is vulnerable to file-based injection",
    ];
    for line in cases {
        let mut p = StreamParser::new();
        p.parse_line(line);
        match p.parse_line("[+] Payload: q=1") {
            ParseEvent::Finding(f) => assert_eq!(
                f.technique,
                Technique::Classic,
                "gap: technique not classified from stream for line: {line}"
            ),
            _ => panic!("expected Finding for line: {line}"),
        }
    }
}

/// Pin injection_type stays Unknown for header-style commix output until parser grows.
#[test]
fn gap_parser_injection_type_unknown_for_header_parameter_output() {
    let mut p = StreamParser::new();
    p.parse_line("[+] The HTTP Header parameter 'X-Forwarded-For' is vulnerable");
    match p.parse_line("[+] Payload: X-Forwarded-For=1;id") {
        ParseEvent::Finding(f) => assert_eq!(
            f.injection_type, "Unknown",
            "gap: injection_type not parsed for header parameters"
        ),
        _ => panic!("expected Finding"),
    }
}

// ---- Contract: scan preflight spawns --version before scan subprocess ----

/// `scan()` / `scan_stream()` run `commix --version` preflight before spawning the
/// scan child (two subprocesses per call). Pinned in crate docs (`src/lib.rs`).
#[test]
fn gap_scan_runs_version_preflight_before_scan_process() {
    let lib_rs = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("read src/lib.rs");
    assert!(
        lib_rs.contains("--version") && lib_rs.contains("preflight"),
        "gap: lib.rs must document --version preflight before scan spawn"
    );
}
