use crate::criteria::eval::eval_criteria;
use crate::criteria::types::AuditRule;
use crate::firewall_rule::FirewallRule;

/// Represents the result of a single audit rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditMatch {
    pub rule_id: String,
    pub description: String,
    pub severity: String,
    pub matched_firewall_rules: Vec<String>,
}

/// Executes the audit on a list of firewall rules and audit rules, returning structured results.
pub fn run_audit_multi_with_criteria(
    audit_criteria: &[AuditRule],
    firewall_rules: &[FirewallRule],
) -> Vec<AuditMatch> {
    let mut results = Vec::new();
    for criteria in audit_criteria {
        let mut matched_firewall_rules = Vec::new();
        for fw_rule in firewall_rules {
            if eval_criteria(fw_rule, &criteria.criteria) {
                matched_firewall_rules.push(fw_rule.name.clone());
            }
        }
        if !matched_firewall_rules.is_empty() {
            results.push(AuditMatch {
                rule_id: criteria.id.clone(),
                description: criteria.description.clone(),
                severity: criteria.severity.clone(),
                matched_firewall_rules,
            });
        }
    }
    results
}
