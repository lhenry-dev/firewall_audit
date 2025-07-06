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
