// Audit execution
// Functions extracted from the old audit.rs

use crate::criteria::eval::eval_criterias;
use crate::criteria::types::AuditRule;
use crate::firewall_rule::FirewallRule;
use rayon::prelude::*;

/// Represents the result of a single audit rule evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditMatch {
    pub rule_id: String,
    pub description: String,
    pub severity: String,
    pub matched_firewall_rules: Vec<String>,
}

/// Executes the audit on a list of firewall rules and audit rules, returning structured results.
pub fn run_audit_multi_with_rules(
    audit_rules: &[AuditRule],
    firewall_rules: &[FirewallRule],
) -> Vec<AuditMatch> {
    let mut results = Vec::new();
    for audit_rule in audit_rules {
        let matches: Vec<String> = firewall_rules
            .par_iter()
            .filter(|fw_rule| match &audit_rule.os {
                Some(os_list) if !os_list.is_empty() => fw_rule
                    .os
                    .as_ref()
                    .map(|os| os_list.iter().any(|o| o.eq_ignore_ascii_case(os)))
                    .unwrap_or(false),
                _ => true,
            })
            .filter_map(|fw_rule| {
                if eval_criterias(fw_rule, &audit_rule.criterias) {
                    Some(fw_rule.name.clone())
                } else {
                    None
                }
            })
            .collect();
        if !matches.is_empty() {
            results.push(AuditMatch {
                rule_id: audit_rule.id.clone(),
                description: audit_rule.description.clone(),
                severity: audit_rule.severity.clone(),
                matched_firewall_rules: matches,
            });
        }
    }
    results
}
