use crate::audit::run::AuditMatch;

/// Formats audit results as a human-readable text string for CLI output.
pub fn export_text(audit_results: &[AuditMatch]) -> String {
    let mut output = String::new();
    for audit in audit_results {
        output.push_str(&format!("\nAudit Rule: {}\n", audit.rule_id));
        output.push_str(&format!("Description: {}\n", audit.description));
        output.push_str(&format!("Severity: {}\n", audit.severity));
        output.push_str(&format!(
            "  ✅ {} match(es) found:\n",
            audit.matched_firewall_rules.len()
        ));
        for name in &audit.matched_firewall_rules {
            output.push_str(&format!("    - {name}\n"));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::run::AuditMatch;

    #[test]
    fn test_export_text_empty() {
        let result = export_text(&[]);
        assert!(result.trim().is_empty(), "Should be empty for no results");
    }

    #[test]
    fn test_export_text_one_match() {
        let audit = AuditMatch {
            rule_id: "R1".into(),
            description: "desc1".into(),
            severity: "high".into(),
            matched_firewall_rules: vec!["RuleA".into()],
        };
        let result = export_text(&[audit]);
        assert!(result.contains("Audit Rule: R1"));
        assert!(result.contains("desc1"));
        assert!(result.contains("high"));
        assert!(result.contains("1 match(es)"));
        assert!(result.contains("- RuleA"));
    }

    #[test]
    fn test_export_text_multiple_matches() {
        let audit = AuditMatch {
            rule_id: "R2".into(),
            description: "desc2".into(),
            severity: "low".into(),
            matched_firewall_rules: vec!["RuleB".into(), "RuleC".into()],
        };
        let result = export_text(&[audit]);
        assert!(result.contains("2 match(es)"));
        assert!(result.contains("- RuleB"));
        assert!(result.contains("- RuleC"));
    }

    #[test]
    fn test_export_text_special_characters() {
        let audit = AuditMatch {
            rule_id: "R3".into(),
            description: "desc3".into(),
            severity: "medium".into(),
            matched_firewall_rules: vec!["Règle spéciale !@#".into()],
        };
        let result = export_text(&[audit]);
        assert!(result.contains("Règle spéciale !@#"));
    }
}
