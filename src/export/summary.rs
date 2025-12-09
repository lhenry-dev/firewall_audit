use crate::audit::AuditMatch;

/// Returns a summary phrase for the audit output for console display.
pub fn audit_summary_phrase(audit_results: &[AuditMatch]) -> String {
    let (high, medium, low, info) = audit_results.iter().fold((0, 0, 0, 0), |mut acc, a| {
        match a.severity.to_lowercase().as_str() {
            "high" => acc.0 += 1,
            "medium" => acc.1 += 1,
            "low" => acc.2 += 1,
            "info" => acc.3 += 1,
            _ => {}
        }
        acc
    });
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
    use crate::{audit::AuditMatch, export::audit_summary_phrase};

    #[test]
    fn test_audit_summary_phrase() {
        let audit_results = vec![
            AuditMatch {
                rule_id: "test-high".to_string(),
                description: "Critical".to_string(),
                severity: "high".to_string(),
                matched_firewall_rules: vec!["Rule1".to_string(), "Rule2".to_string()],
            },
            AuditMatch {
                rule_id: "test-info".to_string(),
                description: "Info".to_string(),
                severity: "info".to_string(),
                matched_firewall_rules: vec!["Rule3".to_string()],
            },
        ];
        let summary = audit_summary_phrase(&audit_results);
        assert!(summary.contains("problem(s) detected"));
        assert!(summary.contains("1 critical(s)"));
        assert!(summary.contains("1 informational(s)"));
    }

    #[test]
    fn test_audit_summary_phrase_no_problem() {
        let audit_results: Vec<AuditMatch> = vec![];
        let summary = audit_summary_phrase(&audit_results);
        assert_eq!(
            summary,
            "No problem detected according to the audit criteria."
        );
    }
}
