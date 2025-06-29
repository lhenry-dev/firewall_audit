use crate::export::block::{count_by_severity, parse_audit_blocks};

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
            "{} problem(s) detected : {} critical(s), {} important(s), {} minor(s), {} informational(s).\n",
            total, high, medium, low, info
        ));
    } else {
        out.push_str("No problems detected according to audit criteria.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    const AUDIT_SAMPLE: &str = r#"
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
"#;

    #[test]
    fn test_console_explanation() {
        let txt = append_console_explanation(AUDIT_SAMPLE);
        assert!(txt.contains("problem(s) detected"));
        assert!(txt.contains("1 critical(s)"));
        assert!(txt.contains("1 informational(s)"));
        // We no longer check for the absence of 'test-nomatch' as the original text is preserved
    }
}
