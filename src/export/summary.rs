//! Console summary module for `firewall_audit`
//!
//! Provides a function to append a summary message to the audit output for console display.

use crate::export::block::{count_by_severity, parse_audit_blocks};

/// Returns a summary phrase for the audit output (for console display).
///
/// # Arguments
/// * `audit_output` - The audit result as a string (from the audit engine)
///
/// # Returns
/// * `String` - The summary phrase (e.g., "X problem(s) detected..." or "No problem detected...")
pub fn audit_summary_phrase(audit_output: &str) -> String {
    let blocks = parse_audit_blocks(audit_output);
    let filtered: Vec<_> = blocks
        .iter()
        .filter(|b| !b.no_match && !b.matches.is_empty())
        .collect();
    let (high, medium, low, info) = count_by_severity(filtered.iter().copied());
    let total = high + medium + low + info;
    if total > 0 {
        format!(
            "{total} problem(s) detected : {high} critical(s), {medium} important(s), {low} minor(s), {info} informational(s)."
        )
    } else {
        "No problem detected according to the audit criteria.".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const AUDIT_SAMPLE: &str = r"
Audit Rule: test-high
Description: Critical
Severity: high
  ✅ 2 match(es) found:
    - Rule1
    - Rule2
Audit Rule: test-info
Description: Info
Severity: info
  ✅ 1 match(es) found:
    - Rule3
Audit Rule: test-nomatch
Description: No match
Severity: low
  ❌ no firewall rule matches this audit rule
--- Audit End ---
";

    #[test]
    fn test_audit_summary_phrase() {
        let summary = audit_summary_phrase(AUDIT_SAMPLE);
        assert!(summary.contains("problem(s) detected"));
        assert!(summary.contains("1 critical(s)"));
        assert!(summary.contains("1 informational(s)"));
    }
    #[test]
    fn test_audit_summary_phrase_no_problem() {
        let no_match = "--- Audit End ---\n";
        let summary = audit_summary_phrase(no_match);
        assert_eq!(
            summary,
            "No problem detected according to the audit criteria."
        );
    }
}
