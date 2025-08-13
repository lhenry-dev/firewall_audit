use crate::{audit::run::AuditMatch, FirewallAuditError};
use std::fmt::Write as _;

/// Formats audit results as a human-readable text string for CLI output.
pub fn export_text(audit_results: &[AuditMatch]) -> Result<String, FirewallAuditError> {
    let mut output = String::new();
    for audit in audit_results {
        writeln!(&mut output, "\nAudit Rule: {}", audit.rule_id)?;
        writeln!(&mut output, "Description: {}", audit.description)?;
        writeln!(&mut output, "Severity: {}", audit.severity)?;
        writeln!(
            &mut output,
            "\t{} match(es) found:",
            audit.matched_firewall_rules.len()
        )?;
        for name in &audit.matched_firewall_rules {
            writeln!(&mut output, "\t- {name}")?;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use crate::{audit::run::AuditMatch, export_text};

    #[test]
    fn test_export_text_empty() {
        let result = export_text(&[]).unwrap();
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
        let result = export_text(&[audit]).unwrap();
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
        let result = export_text(&[audit]).unwrap();
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
        let result = export_text(&[audit]).unwrap();
        assert!(result.contains("Règle spéciale !@#"));
    }
}
