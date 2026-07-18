use commix_rs::parser::{ParseEvent, StreamParser};
use commix_rs::Commix;
use std::sync::Arc;
use std::thread;

// 1. Empty input / zero-length slices

// 1. Empty input / zero-length slices
// Testing the parser since builder fields are private.

#[test]
fn test_01_parser_empty_line() {
    let mut parser = StreamParser::new();
    match parser.parse_line("") {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
}

#[test]
fn test_02_parser_empty_request() {
    let mut parser = StreamParser::new();
    match parser.parse_line("Request:") {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
}

#[test]
fn test_03_parser_empty_payload() {
    let mut parser = StreamParser::new();
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload:") {
        ParseEvent::Finding(f) => assert_eq!(f.payload, ""),
        _ => panic!("Expected Finding, as Payload regex matches empty string"),
    }
}

#[test]
fn test_04_parser_whitespace_only() {
    let mut parser = StreamParser::new();
    match parser.parse_line("   \t   ") {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
}

// 2. Null bytes in input

#[test]
fn test_05_parser_null_byte_param() {
    let mut parser = StreamParser::new();
    match parser.parse_line("[+] The GET parameter '\x00' is vulnerable") {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
}

#[test]
fn test_06_parser_null_byte_payload() {
    let mut parser = StreamParser::new();
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload: echo \x00") {
        ParseEvent::Finding(f) => assert_eq!(f.payload, "echo \x00"),
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_07_parser_null_byte_input() {
    let mut parser = StreamParser::new();
    match parser.parse_line("Request: http://test.com/api?q=1\x002") {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
}

// 3. Maximum u32/u64 values for any numeric parameter

#[test]
fn test_08_parser_max_cve_numbers() {
    let mut parser = StreamParser::new();
    match parser.parse_line("CVE-9999-999999999") {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.cve.unwrap(), "CVE-9999-999999999"),
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_09_parser_huge_warning() {
    let mut parser = StreamParser::new();
    let huge_warning = "A".repeat(10000);
    let line = format!("[!] {}", huge_warning);
    match parser.parse_line(&line) {
        ParseEvent::Warning(w) => assert_eq!(w, huge_warning),
        _ => panic!("Expected Warning"),
    }
}

#[test]
fn test_10_parser_huge_error() {
    let mut parser = StreamParser::new();
    let huge_error = "B".repeat(10000);
    let line = format!("[x] {}", huge_error);
    match parser.parse_line(&line) {
        ParseEvent::Error(e) => assert_eq!(e, huge_error),
        _ => panic!("Expected Error"),
    }
}

#[test]
fn test_11_parser_huge_param() {
    let mut parser = StreamParser::new();
    let huge_param = "C".repeat(10000);
    let line = format!("[+] The GET parameter '{}' is vulnerable", huge_param);
    parser.parse_line(&line);
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.parameter, huge_param),
        _ => panic!("Expected Finding"),
    }
}

// 4. 1MB+ input (if the crate processes byte buffers)

#[test]
fn test_12_parser_huge_payload() {
    let mut parser = StreamParser::new();
    let huge_payload = "D".repeat(1024 * 1024); // 1MB
    let line = format!("[+] Payload: {}", huge_payload);
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line(&line) {
        ParseEvent::Finding(f) => assert_eq!(f.payload, huge_payload),
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_13_parser_huge_poc() {
    let mut parser = StreamParser::new();
    let huge_poc = "E".repeat(1024 * 1024); // 1MB
    let line = format!("Request: {}", huge_poc);
    parser.parse_line(&line);
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.poc, huge_poc),
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_14_parser_huge_line() {
    let mut parser = StreamParser::new();
    let huge_line = "A".repeat(1024 * 1024);
    match parser.parse_line(&huge_line) {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
}

// 5. Concurrent access from 8 threads (if the crate has shared state)

#[test]
fn test_15_concurrent_parser() {
    let mut handles = vec![];
    for _ in 0..8 {
        handles.push(thread::spawn(|| {
            let mut parser = StreamParser::new();
            parser.parse_line("Request: http://test.com");
            parser.parse_line("[+] The GET parameter 'q' is vulnerable");
            match parser.parse_line("[+] Payload: q=1") {
                ParseEvent::Finding(f) => assert_eq!(f.poc, "http://test.com"),
                _ => panic!("Expected Finding"),
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn test_16_concurrent_runner_is_available() {
    let runner = Arc::new(Commix::builder().build());
    let mut handles = vec![];
    for _ in 0..8 {
        let r = runner.clone();
        handles.push(tokio::spawn(async move {
            r.is_available().await;
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
}

// 6. Malformed/truncated input (partial data, missing headers)

#[test]
fn test_17_parser_malformed_cve() {
    let mut parser = StreamParser::new();
    parser.parse_line("CVE-ABCD-1234");
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.cve, None),
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_18_parser_truncated_vulnerability_line() {
    let mut parser = StreamParser::new();
    match parser.parse_line("[+] The GET parameter 'q' is") {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
}

#[test]
fn test_19_parser_truncated_payload_line() {
    let mut parser = StreamParser::new();
    match parser.parse_line("[+] Payload:") {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
}

// 7. Unicode edge cases (BOM, overlong sequences, surrogates)

#[test]
fn test_20_parser_unicode_poc() {
    let mut parser = StreamParser::new();
    parser.parse_line("Request: http://test.com/🐛");
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.poc, "http://test.com/🐛"),
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_21_parser_unicode_vulnerability() {
    let mut parser = StreamParser::new();
    parser.parse_line("Request: http://test.com/api?🐛=1");
    parser.parse_line("[+] The GET parameter '🐛' is vulnerable to classic command injection");
    match parser.parse_line("[+] Payload: 🐛=1;echo VULN;#") {
        ParseEvent::Finding(f) => {
            assert_eq!(f.parameter, "🐛");
        }
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_22_parser_bom_data() {
    let mut parser = StreamParser::new();
    match parser.parse_line("[!] \u{feff}payload") {
        ParseEvent::Warning(w) => assert_eq!(w, "\u{feff}payload"),
        _ => panic!("Expected Warning"),
    }
}

// 8. Duplicate entries (same key twice, same pattern twice)

#[test]
fn test_23_parser_duplicate_params() {
    let mut parser = StreamParser::new();
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.parameter, "q"),
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_24_parser_duplicate_payloads() {
    let mut parser = StreamParser::new();
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.payload, "q=1"),
        _ => panic!("Expected Finding"),
    }
    match parser.parse_line("[+] Payload: q=2") {
        ParseEvent::Wait => {} // Because parameter is cleared after first finding
        _ => panic!("Expected Wait"),
    }
}

// 9. Off-by-one: first byte, last byte, boundary between chunks

#[test]
fn test_25_parser_boundary_regex_cve() {
    let mut parser = StreamParser::new();
    parser.parse_line("CVE-2023-12345"); // Just the CVE
    match parser.parse_line("[+] The GET parameter 'q' is vulnerable to classic command injection")
    {
        ParseEvent::Wait => {}
        _ => panic!("Expected Wait"),
    }
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => {
            // The regex might accidentally truncate or parse the whole thing. We expect it to grab the whole thing if it's well-formed, but wait...
            // Let's assert what the CRATE ACTUALLY DOES or SHOULD DO. The crate currently grabs CVE-2023-12345. But actually it's a bug if it grabs an invalid CVE format. Wait, CVEs can have 5 digits.
            // Let's assert it grabs CVE-2023-12345 correctly. Wait, it failed because the assertion was "CVE-2023-1234".
            assert_eq!(f.cve.unwrap(), "CVE-2023-12345");
        }
        _ => panic!("Expected Finding"),
    }
}

// 10. Resource exhaustion: 100K items, deeply nested structures

#[test]
fn test_26_parser_100k_cves() {
    let mut parser = StreamParser::new();
    for i in 0..100_000 {
        parser.parse_line(&format!("CVE-2024-{}", i));
    }
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.cve.unwrap(), "CVE-2024-99999"),
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_27_parser_100k_pocs() {
    let mut parser = StreamParser::new();
    for i in 0..100_000 {
        parser.parse_line(&format!("Request: {}", i));
    }
    parser.parse_line("[+] The GET parameter 'q' is vulnerable");
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => assert_eq!(f.poc, "99999"),
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_28_parser_100k_lines() {
    let mut parser = StreamParser::new();
    for _ in 0..100_000 {
        match parser.parse_line("Some random log line that doesn't match anything") {
            ParseEvent::Wait => {}
            _ => panic!("Expected Wait"),
        }
    }
}

// Specific edge cases designed to break the parsing logic

#[test]
fn test_29_parser_payload_without_param() {
    let mut parser = StreamParser::new();
    // Payload appears before param or without param
    match parser.parse_line("[+] Payload: q=1;echo VULN;#") {
        ParseEvent::Wait => {} // Should wait because current_parameter is empty
        _ => panic!("Expected Wait"),
    }
}

#[test]
fn test_30_parser_cve_regex_greedy() {
    let mut parser = StreamParser::new();
    parser.parse_line("This is a CVE-2023-1234 and another CVE-2024-5678");
    parser.parse_line("[+] The GET parameter 'q' is vulnerable to classic command injection");
    match parser.parse_line("[+] Payload: q=1") {
        ParseEvent::Finding(f) => {
            // Which one did it capture? The first one.
            assert_eq!(f.cve.unwrap(), "CVE-2023-1234");
        }
        _ => panic!("Expected Finding"),
    }
}

#[test]
fn test_31_parser_warning() {
    let mut parser = StreamParser::new();
    match parser.parse_line("[!] Warning: WAF detected") {
        ParseEvent::Warning(w) => assert_eq!(w, "Warning: WAF detected"),
        _ => panic!("Expected Warning"),
    }
}

#[test]
fn test_32_parser_error() {
    let mut parser = StreamParser::new();
    match parser.parse_line("[x] Critical: Connection timed out") {
        ParseEvent::Error(e) => assert_eq!(e, "Critical: Connection timed out"),
        _ => panic!("Expected Error"),
    }
}

#[test]
fn test_33_parser_multiple_vulns() {
    let mut parser = StreamParser::new();
    parser.parse_line("[+] The GET parameter 'a' is vulnerable to classic command injection");
    match parser.parse_line("[+] Payload: a=1") {
        ParseEvent::Finding(f) => assert_eq!(f.parameter, "a"),
        _ => panic!("Expected Finding"),
    }

    parser.parse_line("[+] The GET parameter 'b' is vulnerable to classic command injection");
    match parser.parse_line("[+] Payload: b=1") {
        ParseEvent::Finding(f) => assert_eq!(f.parameter, "b"),
        _ => panic!("Expected Finding"),
    }
}

// NEW ADVERSARIAL TESTS added for audit:

#[tokio::test]
async fn test_34_builder_base64_overflow() {
    // Tests functional behavior, actual overflow test may OOM if allowed.
    let runner = commix_rs::CommixBuilder::new()
        .auth_basic("admin", "password")
        .build();
    let _ = runner.is_available().await;
}

#[tokio::test]
async fn test_35_runner_resource_exhaustion() {
    // Spawn 1000 builders and test runner instantiation
    let mut runners = vec![];
    for _ in 0..1000 {
        runners.push(commix_rs::Commix::builder().url("http://test.com").build());
    }
    assert_eq!(runners.len(), 1000);
}

#[test]
fn test_36_parser_fuzz_garbage() {
    let mut parser = StreamParser::new();
    for _ in 0..10000 {
        match parser.parse_line(&"A".repeat(100)) {
            ParseEvent::Wait => {}
            _ => panic!("Expected Wait"),
        }
    }
}

#[tokio::test]
async fn test_37_concurrent_100_threads() {
    let mut handles = vec![];
    let runner = std::sync::Arc::new(commix_rs::Commix::builder().url("http://test.com").build());
    for _ in 0..100 {
        let r = runner.clone();
        handles.push(tokio::spawn(async move {
            r.is_available().await;
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_38_builder_huge_headers() {
    let mut builder = commix_rs::CommixBuilder::new();
    for i in 0..10000 {
        builder = builder.header(format!("X-Test-{}: {}", i, "A".repeat(100)));
    }
    let runner = builder.build();
    assert!(runner
        .scan_stream(tokio::sync::mpsc::channel(1).0)
        .await
        .is_err()); // will fail gracefully because no binary
}

#[tokio::test]
async fn test_39_malformed_url() {
    let builder = commix_rs::CommixBuilder::new()
        .url("http://\x00\x00\x00")
        .build();
    let _ = builder.is_available().await; // malformed URL is not consulted; only checks no panic
}

#[tokio::test]
#[allow(deprecated)]
async fn test_40_integer_bounds() {
    let runner = commix_rs::CommixBuilder::new()
        .timeout_secs(u64::MAX)
        .delay_secs(u64::MAX)
        .threads(u8::MAX)
        .retries(u8::MAX)
        .level(u8::MAX)
        .build();
    let _ = runner.is_available().await;
}

#[tokio::test]
async fn test_41_runner_split_command_escape_end() {
    // Tests that split_command_string handles an escape at the very end without panicking
    let runner = commix_rs::Commix::builder()
        .binary_path("commix \\")
        .build();
    let _ = runner.is_available().await;
}

#[tokio::test]
async fn test_42_runner_split_command_quotes_unterminated() {
    let runner = commix_rs::Commix::builder()
        .binary_path("commix \"unterminated")
        .build();
    let _ = runner.is_available().await;
}

#[test]
fn test_43_parser_extreme_nesting() {
    let mut parser = StreamParser::new();
    let nested = "[+] The GET parameter 'q' is vulnerable\n".repeat(1000);
    for line in nested.lines() {
        parser.parse_line(line);
    }
    match parser.parse_line("[+] Payload: echo VULN") {
        ParseEvent::Finding(_) => {}
        _ => panic!("Expected finding"),
    }
}
