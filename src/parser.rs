//! Parsing engine to convert raw continuous stdout text streams from Commix into structured Rust events.

use crate::types::{CommixFinding, Confidence, Technique};
use tracing::{info, trace};

/// A stateful parser that processes lines one-by-one from the Commix STDOUT stream.
#[derive(Debug, Default)]
pub struct StreamParser {
    current_poc: String,
    current_parameter: String,
    current_cve: Option<String>,
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
    ///
    /// # Returns
    /// A new default initialized `StreamParser`.
    ///
    /// # Example
    /// ```rust
    /// use commix_rs::parser::StreamParser;
    /// let parser = StreamParser::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a single line of stdout into the state machine and returns a `ParseEvent` if the logic
    /// crosses a completion boundary.
    ///
    /// # Arguments
    /// * `line` - The stdout string line.
    ///
    /// # Example
    /// ```rust
    /// use commix_rs::parser::{StreamParser, ParseEvent};
    /// let mut parser = StreamParser::new();
    /// match parser.parse_line("[!] Warning: Something happened") {
    ///     ParseEvent::Warning(w) => println!("Warning: {}", w),
    ///     _ => {}
    /// }
    /// ```
    pub fn parse_line(&mut self, line: &str) -> ParseEvent {
        let trimmed = line.trim();
        trace!("commix parser ingested: {}", trimmed);

        // Look for CVE tags in the stream context (CVE-YYYY-NNNN)
        if trimmed.contains("CVE-") {
            if let Some(idx) = trimmed.find("CVE-") {
                let rest = &trimmed[idx..];
                // Extract sequence of characters matching format CVE-\d{4}-\d+
                let end = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .count();
                let cve_str = &rest[..end];

                let parts: Vec<&str> = cve_str.split('-').collect();
                // Ensure it's exactly the CVE format (e.g. CVE-2024-1234) where the parts are digits
                if parts.len() >= 3
                    && parts[1].chars().all(|c| c.is_ascii_digit())
                    && parts[2].chars().all(|c| c.is_ascii_digit())
                {
                    self.current_cve = Some(cve_str.to_string());
                }
            }
        }

        // Extract the vulnerable parameter (initial flag)
        if trimmed.starts_with("[+] The")
            && trimmed.contains(" parameter '")
            && trimmed.contains("' is vulnerable")
        {
            if let Some(start) = trimmed.find(" parameter '") {
                let rest = &trimmed[start + " parameter '".len()..];
                if let Some(end) = rest.find("' is vulnerable") {
                    self.current_parameter = rest[..end].to_string();
                }
            }
        }

        // Extract payload and finalize finding. Commix outputs the payload slightly AFTER stating vulnerability.
        if let Some(payload_str) = trimmed.strip_prefix("[+] Payload:") {
            let payload_str = payload_str.trim().to_string();

            if !self.current_parameter.is_empty() {
                info!(
                    "Found vulnerability in parameter '{}'",
                    self.current_parameter
                );
                let finding = CommixFinding {
                    parameter: self.current_parameter.clone(),
                    technique: Technique::Classic,
                    payload: payload_str,
                    cve: self.current_cve.take(),
                    injection_type: "Unknown".to_string(),
                    poc: self.current_poc.clone(),
                    confidence: Confidence::Certain,
                };

                // Reset internal accumulators
                self.current_parameter.clear();
                self.current_poc.clear();

                return ParseEvent::Finding(finding);
            }
        } else if trimmed.starts_with("Request:") {
            // Save the HTTP request / Proof of Concept
            self.current_poc = trimmed.replace("Request:", "").trim().to_string();
        } else if let Some(warn_str) = trimmed.strip_prefix("[!]") {
            return ParseEvent::Warning(warn_str.trim().to_string());
        } else if let Some(err_str) = trimmed.strip_prefix("[x]") {
            return ParseEvent::Error(err_str.trim().to_string());
        }

        ParseEvent::Wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_state_machine() {
        let mut parser = StreamParser::new();

        // Mocking a Commix output flow sequentially
        match parser.parse_line("Request: http://test.com/api?q=1") {
            ParseEvent::Wait => {}
            _ => panic!("Expected Wait"),
        }
        assert_eq!(parser.current_poc, "http://test.com/api?q=1");

        match parser
            .parse_line("[+] The GET parameter 'q' is vulnerable to classic command injection")
        {
            ParseEvent::Wait => {}
            _ => panic!("Expected Wait"),
        }
        assert_eq!(parser.current_parameter, "q");

        match parser.parse_line("[+] Payload: q=1;echo VULN;#") {
            ParseEvent::Finding(f) => {
                assert_eq!(f.parameter, "q");
                assert_eq!(f.payload, "q=1;echo VULN;#");
                assert_eq!(f.poc, "http://test.com/api?q=1");
            }
            _ => panic!("Expected Finding"),
        }

        // Ensure state wiped
        assert!(parser.current_parameter.is_empty());
        assert!(parser.current_poc.is_empty());
    }
}
