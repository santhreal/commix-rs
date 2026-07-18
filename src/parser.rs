//! Parsing engine to convert raw continuous stdout text streams from Commix into structured Rust events.

use crate::types::{CommixFinding, Confidence, Technique};
use tracing::{info, trace};

/// A stateful parser that processes lines one-by-one from the Commix STDOUT stream.
#[derive(Debug)]
pub struct StreamParser {
    current_poc: String,
    current_parameter: String,
    current_cve: Option<String>,
    current_technique: Technique,
    current_injection_type: String,
}

impl Default for StreamParser {
    fn default() -> Self {
        Self {
            current_poc: String::new(),
            current_parameter: String::new(),
            current_cve: None,
            current_technique: Technique::Classic,
            current_injection_type: "Unknown".to_string(),
        }
    }
}

/// An event emitted by the `StreamParser` when a line is processed.
#[derive(Debug)]
pub enum ParseEvent {
    /// A new vulnerability was definitively found and fully constructed.
    Finding(CommixFinding),
    /// A runtime warning was logged by Commix.
    Warning(String),
    /// A critical execution error was logged by Commix.
    Error(String),
    /// The line was parsed, but state is just accumulating (no emit yet).
    Wait,
}

impl StreamParser {
    /// Creates a new `StreamParser` instance to parse chunked commix output.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a single line of stdout into the state machine and returns a `ParseEvent` if the logic
    /// crosses a completion boundary.
    pub fn parse_line(&mut self, line: &str) -> ParseEvent {
        let trimmed_raw = line.trim();

        if let Some(payload) = trimmed_raw.strip_prefix("|_ ") {
            return self.finalize_finding(payload.trim().to_string());
        }
        if let Some(payload_str) = trimmed_raw.strip_prefix("[+] Payload:") {
            return self.finalize_finding(payload_str.trim().to_string());
        }

        let normalized = normalize_line(line);
        trace!("commix parser ingested: {}", normalized);

        extract_cve(&mut self.current_cve, &normalized);

        if let Some(event) = parse_warning_or_error(&normalized) {
            return event;
        }

        let content = strip_log_level(&normalized);

        if content.starts_with("Request:") {
            self.current_poc = content.replace("Request:", "").trim().to_string();
            return ParseEvent::Wait;
        }

        if let Some((parameter, injection_type, technique)) = parse_injectable_line(content) {
            self.current_parameter = parameter;
            self.current_injection_type = injection_type;
            self.current_technique = technique;
            return ParseEvent::Wait;
        }

        ParseEvent::Wait
    }

    fn finalize_finding(&mut self, payload: String) -> ParseEvent {
        if self.current_parameter.is_empty() {
            return ParseEvent::Wait;
        }

        info!(
            "Found vulnerability in parameter '{}'",
            self.current_parameter
        );
        let finding = CommixFinding {
            parameter: std::mem::take(&mut self.current_parameter),
            technique: self.current_technique.clone(),
            payload,
            cve: self.current_cve.take(),
            injection_type: std::mem::take(&mut self.current_injection_type),
            poc: std::mem::take(&mut self.current_poc),
            confidence: Confidence::Certain,
        };
        self.current_technique = Technique::Classic;
        self.current_injection_type = "Unknown".to_string();

        ParseEvent::Finding(finding)
    }
}

fn normalize_line(line: &str) -> String {
    strip_timestamp(&strip_ansi(line)).trim().to_string()
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            let mut sequence = String::from("\x1b[");
            chars.next();
            let mut closed = false;
            while let Some(&next) = chars.peek() {
                sequence.push(next);
                chars.next();
                if next == 'm' {
                    closed = true;
                    break;
                }
            }
            if !closed {
                out.push_str(&sequence);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn strip_timestamp(input: &str) -> &str {
    let trimmed = input.trim_start();
    if !trimmed.starts_with('[') {
        return input;
    }
    let Some(close) = trimmed.find(']') else {
        return input;
    };
    let inner = &trimmed[1..close];
    if inner.len() == 8
        && inner.as_bytes().get(2) == Some(&b':')
        && inner.as_bytes().get(5) == Some(&b':')
        && inner[..2].chars().all(|c| c.is_ascii_digit())
        && inner[3..5].chars().all(|c| c.is_ascii_digit())
        && inner[6..8].chars().all(|c| c.is_ascii_digit())
    {
        trimmed[close + 1..].trim_start()
    } else {
        input
    }
}

fn strip_log_level(input: &str) -> &str {
    let trimmed = input.trim_start();
    for prefix in ["[info] ", "[warning] ", "[error] "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest;
        }
    }
    trimmed
}

fn parse_warning_or_error(normalized: &str) -> Option<ParseEvent> {
    let trimmed = normalized.trim_start();
    if let Some(warn) = trimmed.strip_prefix("[warning]") {
        return Some(ParseEvent::Warning(warn.trim().to_string()));
    }
    if let Some(err) = trimmed.strip_prefix("[error]") {
        return Some(ParseEvent::Error(err.trim().to_string()));
    }
    if let Some(warn) = trimmed.strip_prefix("[!]") {
        return Some(ParseEvent::Warning(warn.trim().to_string()));
    }
    if let Some(err) = trimmed.strip_prefix("[x]") {
        return Some(ParseEvent::Error(err.trim().to_string()));
    }
    None
}

fn parse_injectable_line(content: &str) -> Option<(String, String, Technique)> {
    if content.contains("appears to be injectable") {
        return parse_modern_injectable(content);
    }
    if content.starts_with("[+] The")
        && content.contains(" parameter '")
        && content.contains("' is vulnerable")
    {
        return parse_legacy_injectable(content);
    }
    None
}

fn parse_modern_injectable(content: &str) -> Option<(String, String, Technique)> {
    let parameter = extract_quoted_parameter(content)?;
    let injection_type = parse_injection_type(content);
    let technique = parse_technique_from_text(content);
    Some((parameter, injection_type, technique))
}

fn parse_legacy_injectable(content: &str) -> Option<(String, String, Technique)> {
    let start = content.find(" parameter '")? + " parameter '".len();
    let rest = &content[start..];
    let end = rest.find("' is vulnerable")?;
    let parameter = rest[..end].to_string();
    let injection_type = parse_injection_type(content);
    let technique = parse_technique_from_text(content);
    Some((parameter, injection_type, technique))
}

fn extract_quoted_parameter(content: &str) -> Option<String> {
    let marker = " parameter '";
    let start = content.find(marker)? + marker.len();
    let rest = &content[start..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

fn parse_injection_type(content: &str) -> String {
    let lower = content.to_ascii_lowercase();
    if lower.contains("get parameter") {
        "GET".to_string()
    } else if lower.contains("post parameter") {
        "POST".to_string()
    } else if lower.contains("http header parameter") || lower.contains("header parameter") {
        "HEADER".to_string()
    } else if lower.contains("cookie parameter") {
        "COOKIE".to_string()
    } else {
        "Unknown".to_string()
    }
}

fn parse_technique_from_text(content: &str) -> Technique {
    let lower = content.to_ascii_lowercase();
    if lower.contains("time-based") {
        Technique::TimeBasedBlind
    } else if lower.contains("file-based") {
        Technique::FileBased
    } else if lower.contains("eval-based") {
        Technique::EvalBased
    } else {
        Technique::Classic
    }
}

fn extract_cve(current_cve: &mut Option<String>, line: &str) {
    if !line.contains("CVE-") {
        return;
    }
    if let Some(idx) = line.find("CVE-") {
        let rest = &line[idx..];
        let end = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .count();
        let cve_str = &rest[..end];

        let parts: Vec<&str> = cve_str.split('-').collect();
        if parts.len() >= 3
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && parts[2].chars().all(|c| c.is_ascii_digit())
        {
            *current_cve = Some(cve_str.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_state_machine_legacy() {
        let mut parser = StreamParser::new();

        assert!(matches!(
            parser.parse_line("Request: http://test.com/api?q=1"),
            ParseEvent::Wait
        ));
        assert_eq!(parser.current_poc, "http://test.com/api?q=1");

        assert!(matches!(
            parser
                .parse_line("[+] The GET parameter 'q' is vulnerable to classic command injection"),
            ParseEvent::Wait
        ));
        assert_eq!(parser.current_parameter, "q");

        match parser.parse_line("[+] Payload: q=1;echo VULN;#") {
            ParseEvent::Finding(f) => {
                assert_eq!(f.parameter, "q");
                assert_eq!(f.payload, "q=1;echo VULN;#");
                assert_eq!(f.poc, "http://test.com/api?q=1");
            }
            _ => panic!("Expected Finding"),
        }

        assert!(parser.current_parameter.is_empty());
        assert!(parser.current_poc.is_empty());
    }

    #[test]
    fn test_parser_modern_commix_transcript() {
        let mut parser = StreamParser::new();
        let lines = [
            "\x1b[94m[14:22:01]\x1b[0m [info] GET parameter 'ip' appears to be injectable via (results-based) classic command injection technique.",
            "           |_ ;echo AWMZVA; id",
            "[14:22:01] [warning] WAF/IPS detected",
            "[14:22:01] [error] Connection timed out",
        ];

        match parser.parse_line(lines[0]) {
            ParseEvent::Wait => {}
            _ => panic!("expected Wait after injectable line"),
        }
        match parser.parse_line(lines[1]) {
            ParseEvent::Finding(f) => {
                assert_eq!(f.parameter, "ip");
                assert_eq!(f.payload, ";echo AWMZVA; id");
                assert_eq!(f.injection_type, "GET");
                assert_eq!(f.technique, Technique::Classic);
            }
            _ => panic!("expected Finding from payload continuation"),
        }
        match parser.parse_line(lines[2]) {
            ParseEvent::Warning(w) => assert_eq!(w, "WAF/IPS detected"),
            _ => panic!("expected Warning"),
        }
        match parser.parse_line(lines[3]) {
            ParseEvent::Error(e) => assert_eq!(e, "Connection timed out"),
            _ => panic!("expected Error"),
        }
    }
}
