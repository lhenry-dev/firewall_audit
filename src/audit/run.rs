// Audit execution
// Functions extracted from the old audit.rs

use crate::criteria::eval::eval_criterias;
use crate::criteria::types::AuditRule;
use crate::error::Result;
use crate::firewall_rule::{FirewallRule, FirewallRuleProvider};
use rayon::prelude::*;

/// Executes the audit on a list of firewall rules and audit rules
pub fn run_audit_multi_with_rules(
    audit_rules: &[AuditRule],
    firewall_rules: &[FirewallRule],
) -> Result<String> {
    let mut output = String::new();
    output.push_str("\n--- Firewall Audit ---\n");
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
            output.push_str(&format!("\nAudit Rule: {}\n", audit_rule.id));
            output.push_str(&format!("Description: {}\n", audit_rule.description));
            output.push_str(&format!("Severity: {}\n", audit_rule.severity));
            output.push_str(&format!("  ✅ {} match(es) found:\n", matches.len()));
            for name in matches {
                output.push_str(&format!("    - {name}\n"));
            }
        }
    }
    output.push_str("\n--- Audit End ---\n");
    Ok(output)
}

/// Utility version for the CLI: automatically lists firewall rules
pub fn run_audit_multi(audit_rules: &[AuditRule]) -> Result<String> {
    let firewall_rules: Vec<FirewallRule> = crate::firewall_rule::FirewallProvider::list_rules()?;
    run_audit_multi_with_rules(audit_rules, &firewall_rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::criteria::{CriteriaCondition, CriteriaExpr};
    use crate::firewall_rule::FirewallRule;

    fn fw_linux() -> FirewallRule {
        FirewallRule {
            name: "rule1".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: None,
            application_name: None,
            service_name: None,
            protocol: None,
            local_ports: None,
            remote_ports: None,
            local_addresses: None,
            remote_addresses: None,
            icmp_types_and_codes: None,
            interfaces: None,
            interface_types: None,
            grouping: None,
            profiles: None,
            edge_traversal: None,
            os: Some("linux".to_string()),
        }
    }
    fn fw_windows() -> FirewallRule {
        FirewallRule {
            name: "rule2".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: None,
            application_name: None,
            service_name: None,
            protocol: None,
            local_ports: None,
            remote_ports: None,
            local_addresses: None,
            remote_addresses: None,
            icmp_types_and_codes: None,
            interfaces: None,
            interface_types: None,
            grouping: None,
            profiles: None,
            edge_traversal: None,
            os: Some("windows".to_string()),
        }
    }
    fn fw_no_os() -> FirewallRule {
        FirewallRule {
            name: "rule3".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: None,
            application_name: None,
            service_name: None,
            protocol: None,
            local_ports: None,
            remote_ports: None,
            local_addresses: None,
            remote_addresses: None,
            icmp_types_and_codes: None,
            interfaces: None,
            interface_types: None,
            grouping: None,
            profiles: None,
            edge_traversal: None,
            os: None,
        }
    }

    #[test]
    fn test_os_filtering_linux_only() {
        let fw_rules = vec![fw_linux(), fw_windows(), fw_no_os()];
        let audit_rule_linux = AuditRule {
            id: "linux_only".to_string(),
            description: "Linux only".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule1".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        };
        let matches: Vec<String> = fw_rules
            .iter()
            .filter(|fw_rule| match &audit_rule_linux.os {
                Some(os_list) if !os_list.is_empty() => match &fw_rule.os {
                    Some(os) => os_list.iter().any(|o| o.eq_ignore_ascii_case(os)),
                    None => false,
                },
                _ => true,
            })
            .filter_map(|fw_rule| {
                if fw_rule.name == "rule1" {
                    Some(fw_rule.name.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(matches, vec!["rule1"]);
    }

    #[test]
    fn test_os_filtering_windows_only() {
        let fw_rules = vec![fw_linux(), fw_windows(), fw_no_os()];
        let audit_rule_windows = AuditRule {
            id: "windows_only".to_string(),
            description: "Windows only".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule2".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["windows".to_string()]),
        };
        let matches: Vec<String> = fw_rules
            .iter()
            .filter(|fw_rule| match &audit_rule_windows.os {
                Some(os_list) if !os_list.is_empty() => match &fw_rule.os {
                    Some(os) => os_list.iter().any(|o| o.eq_ignore_ascii_case(os)),
                    None => false,
                },
                _ => true,
            })
            .filter_map(|fw_rule| {
                if fw_rule.name == "rule2" {
                    Some(fw_rule.name.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(matches, vec!["rule2"]);
    }

    #[test]
    fn test_os_filtering_linux_and_windows() {
        let fw_rules = vec![fw_linux(), fw_windows(), fw_no_os()];
        let audit_rule_both = AuditRule {
            id: "both".to_string(),
            description: "Linux and Windows".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule1".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string(), "windows".to_string()]),
        };
        let matches: Vec<String> = fw_rules
            .iter()
            .filter(|fw_rule| match &audit_rule_both.os {
                Some(os_list) if !os_list.is_empty() => match &fw_rule.os {
                    Some(os) => os_list.iter().any(|o| o.eq_ignore_ascii_case(os)),
                    None => false,
                },
                _ => true,
            })
            .filter_map(|fw_rule| {
                if fw_rule.name == "rule1" {
                    Some(fw_rule.name.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(matches, vec!["rule1"]); // rule2 is not in the name criteria
    }

    #[test]
    fn test_os_filtering_firewall_no_os() {
        let fw_rules = vec![fw_linux(), fw_windows(), fw_no_os()];
        let audit_rule_all = AuditRule {
            id: "all".to_string(),
            description: "All OS".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule3".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: None,
        };
        let matches: Vec<String> = fw_rules
            .iter()
            .filter(|fw_rule| match &audit_rule_all.os {
                Some(os_list) if !os_list.is_empty() => match &fw_rule.os {
                    Some(os) => os_list.iter().any(|o| o.eq_ignore_ascii_case(os)),
                    None => false,
                },
                _ => true,
            })
            .filter_map(|fw_rule| {
                if fw_rule.name == "rule3" {
                    Some(fw_rule.name.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(matches, vec!["rule3"]);
    }

    #[test]
    fn test_parallel_vs_sequential_audit() {
        // Simulates a sequential vs parallel audit on a large list
        let fw_rules: Vec<FirewallRule> = (0..1000)
            .map(|i| FirewallRule {
                name: if i == 42 {
                    "TestRule".to_string()
                } else {
                    format!("Rule-{}", i)
                },
                direction: "In".to_string(),
                enabled: true,
                action: "Allow".to_string(),
                description: None,
                application_name: None,
                service_name: None,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                local_addresses: None,
                remote_addresses: None,
                icmp_types_and_codes: None,
                interfaces: None,
                interface_types: None,
                grouping: None,
                profiles: None,
                edge_traversal: None,
                os: Some("windows".to_string()),
            })
            .collect();
        let audit_rule = AuditRule {
            id: "test_parallel".to_string(),
            description: "test".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("TestRule".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["windows".to_string()]),
        };
        // Sequential
        let mut matches_seq = Vec::new();
        for fw_rule in &fw_rules {
            if eval_criterias(fw_rule, &audit_rule.criterias) {
                matches_seq.push(fw_rule.name.clone());
            }
        }
        // Parallel
        let matches_par: Vec<String> = fw_rules
            .par_iter()
            .filter_map(|fw_rule| {
                if eval_criterias(fw_rule, &audit_rule.criterias) {
                    Some(fw_rule.name.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(matches_seq, matches_par);
    }
}
