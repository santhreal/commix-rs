use serde::{Deserialize, Serialize};

/// Confidence level of the vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Highly certain the injection succeeded.
    Certain,
    /// Likely vulnerable but missing definitive proof.
    Tentative,
    /// Edge cases or false positives possible.
    Low,
}

/// The injection technique used by Commix.
///
/// Serialized JSON uses lowercase wire names (via `rename_all = "lowercase"`):
/// `classic`, `timebasedblind`, `evalbased`, `filebased`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Technique {
    /// Classic generic results-based injection
    Classic,
    /// Time-based blind injection
    TimeBasedBlind,
    /// Evaluation-based
    EvalBased,
    /// File-based injection
    FileBased,
}

/// Represents a single vulnerability finding emitted by Commix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommixFinding {
    /// The vulnerable parameter.
    pub parameter: String,
    /// The technique used to exploit it.
    pub technique: Technique,
    /// The injected payload that succeeded.
    pub payload: String,
    /// The type of injection (e.g., "GET", "POST", "HEADER").
    pub injection_type: String,
    /// Proof of Concept URL / Request.
    pub poc: String,
    /// Associated CVE identifier, if explicitly identified by the engine.
    pub cve: Option<String>,
    /// The confidence of the finding.
    pub confidence: Confidence,
}

/// The aggregated result of a complete Commix scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommixResult {
    /// A list of valid command injection findings.
    pub findings: Vec<CommixFinding>,
    /// Warnings emitted by Commix (e.g., WAF detected).
    pub warnings: Vec<String>,
    /// Critical execution errors emitted by Commix (e.g., Connection dropped).
    pub execution_errors: Vec<String>,
}

impl CommixResult {
    /// Helper to check if any findings were discovered.
    pub fn is_vulnerable(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Helper to check if execution faced heavy resistance (WAFs or bans).
    pub fn has_interference(&self) -> bool {
        !self.warnings.is_empty() || !self.execution_errors.is_empty()
    }
}

impl std::fmt::Display for CommixFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let title = match &self.cve {
            Some(cve) => format!(
                "[{:?}] ({}) Vulnerable parameter '{}'",
                self.confidence, cve, self.parameter
            ),
            None => format!(
                "[{:?}] Vulnerable parameter '{}'",
                self.confidence, self.parameter
            ),
        };
        write!(
            f,
            "{} via {:?}\n  Payload: {}\n  Proof:   {}",
            title, self.technique, self.payload, self.poc
        )
    }
}

impl std::fmt::Display for CommixResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.execution_errors.is_empty() {
            writeln!(
                f,
                "[!] Encountered {} critical execution errors.",
                self.execution_errors.len()
            )?;
            for err in &self.execution_errors {
                writeln!(f, "  - {err}")?;
            }
        }
        if !self.warnings.is_empty() {
            writeln!(
                f,
                "[*] Issued {} warnings during execution.",
                self.warnings.len()
            )?;
            for wrn in &self.warnings {
                writeln!(f, "  - {wrn}")?;
            }
        }

        if self.findings.is_empty() {
            return write!(f, "No vulnerabilities found.");
        }

        writeln!(f, "Found {} vulnerabilities:", self.findings.len())?;
        for (i, finding) in self.findings.iter().enumerate() {
            writeln!(f, "{}. {}", i + 1, finding)?;
        }
        Ok(())
    }
}
