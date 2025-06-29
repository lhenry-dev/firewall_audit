//! Console summary module for `firewall_audit`
//!
//! Provides a function to append a summary message to the audit output for console display.

use crate::export::block::{count_by_severity, parse_audit_blocks};

/// Appends an explanatory summary message to the audit output for console display.
///
/// # Arguments
/// * `audit_output` - The audit result as a string (from the audit engine)
///
/// # Returns
/// * `String` - The audit output with a summary message appended
pub fn append_console_explanation(audit_output: &str) -> String {
    let blocks = parse_audit_blocks(audit_output);
    let filtered: Vec<_> = blocks
        .iter()
        .filter(|b| !b.no_match && !b.matches.is_empty())
        .collect();
    let (high, medium, low, info) = count_by_severity(filtered.iter().copied());
    let total = high + medium + low + info;
    let mut out = audit_output.to_string();
    out.push('\n');
    if total > 0 {
        out.push_str(&format!(
            "{total} problem(s) detected : {high} critical(s), {medium} important(s), {low} minor(s), {info} informational(s).\n"
        ));
    } else {
        out.push_str("No problem detected according to the audit criteria.\n");
    }
    out
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
    fn test_console_explanation() {
        let txt = append_console_explanation(AUDIT_SAMPLE);
        assert!(txt.contains("problem(s) detected"));
        assert!(txt.contains("1 critical(s)"));
        assert!(txt.contains("1 informational(s)"));
        // We no longer check for the absence of 'test-nomatch' as the original text is preserved
    }
}
